package main

// This file implements an on-disk analysis cache for the `urls` and
// `secrets` modes. The cache is opt-in via the --cache flag. When the
// cache is not enabled, the single-shot analysis path is completely
// untouched and no cache files are created.
//
// Design overview
// ---------------
// Identity: scripts are identified by the SHA-256 hash of their exact
// byte content, never by path alone. The same path holding different
// content therefore produces a different cache key, while identical
// content at different paths shares one entry.
//
// Versioning: every entry carries the analysis RuleVersion (bumped
// whenever the built-in matchers/rules change), the analysis mode, and
// a hash of all analysis-affecting options (expression placeholder,
// user-supplied secret patterns). An entry whose version or config
// hash differs is treated as a miss and recomputed.
//
// Atomicity: each entry and the manifest are written to a temporary
// file in the same directory and atomically renamed into place, so a
// kill at any point leaves either the previous complete file or the
// new complete file - never a truncated one. All cache files are
// fsynced before the rename.
//
// Concurrency: goroutines inside one process are serialised by mu.
// Separate jsluice processes sharing a cache directory are serialised
// by an exclusive flock(2) on the lock file; the kernel releases the
// lock automatically if the process dies, so a killed run can never
// wedge the cache.
//
// Degradation: any unrecoverable cache problem (corrupt JSON, unwritable
// directory) is reported on stderr as a warning and the run falls back
// to a full uncached analysis. Cache problems never change stdout or
// the exit code.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/BishopFox/jsluice"
)

// RuleVersion identifies the version of the built-in analysis rules
// (the URL/Secret matchers in the jsluice package). It MUST be bumped
// whenever any built-in matcher or analysis behaviour changes in a way
// that could alter results. Old cache entries carry the old version and
// are automatically treated as misses, i.e. they are never reused.
const RuleVersion = 1

const (
	entriesDirName = "entries"
	lockName       = "lock"
	touchName      = "lru.json"
	tmpSuffix      = ".tmp"
)

// Stats summarises cache behaviour for a single run.
type Stats struct {
	Inputs    int  `json:"inputs"`
	Hits      int  `json:"reused"`
	Misses    int  `json:"recomputed"`
	Invalid   int  `json:"forced_invalidations"`
	Corrupt   int  `json:"corrupt_entries_ignored"`
	Evicted   int  `json:"entries_evicted"`
	Added     int  `json:"scripts_added"`
	Removed   int  `json:"scripts_removed"`
	Changed   int  `json:"scripts_changed"`
	Degraded  bool `json:"degraded"`
	CacheSize int  `json:"cache_entries_total"`
}

// Change describes how one input name's results differ between the
// previous run and the current one. It is only populated when the
// script's content changed (same name, new content hash).
type Change struct {
	Name    string   `json:"name"`
	OldHash string   `json:"old_hash"`
	NewHash string   `json:"new_hash"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	// Note is set when a diff cannot be produced, e.g. because the old
	// entry was written by a different rule version and has been
	// invalidated rather than compared.
	Note string `json:"note,omitempty"`
}

// cachedResult is the payload stored for one (content, mode, config)
// combination. It contains the raw jsluice match objects, before any
// presentation-layer processing (filename assignment, -R resolution,
// -u de-duplication, -S source stripping). That processing is a pure
// function of the stored matches plus the current CLI options, so it
// stays outside the cache and the emitted output is identical to an
// uncached run.
type cachedResult struct {
	URLs    []*jsluice.URL    `json:"urls,omitempty"`
	Secrets []*jsluice.Secret `json:"secrets,omitempty"`
}

// entry is the on-disk representation of one cache entry.
type entry struct {
	// Version of the built-in analysis rules that produced Results.
	Version int `json:"version"`

	// Mode is "urls" or "secrets".
	Mode string `json:"mode"`

	// ContentHash is the SHA-256 hex digest of the exact script bytes
	// the entry was produced from.
	ContentHash string `json:"content_hash"`

	// ConfigHash covers every option that can influence analysis
	// results (as opposed to presentation): the expression placeholder
	// and, for secrets mode, the user-patterns file content.
	ConfigHash string `json:"config_hash"`

	// Results holds the raw match objects.
	Results cachedResult `json:"results"`

	// CreatedAt / LastUsedAt record when the entry was first written
	// and last (re)computed. LRU eviction ordering itself is driven by
	// the separate lru.json index so that cache hits never rewrite an
	// entry; these timestamps remain useful for auditing and as a
	// fallback if the index is missing.
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// manifestFile tracks which logical input names (file paths or URLs)
// currently map to which content hashes, per mode+config. It makes
// "script deleted" detectable: a name present in a previous manifest
// but absent from the current run was deleted. Deleted scripts keep
// their cache entries (and therefore their historical results) but are
// excluded from the current run's conclusions.
type manifestFile struct {
	Version int `json:"version"`

	// Scope is mode + "|" + configHash, so different analyses keep
	// independent name->hash maps in the shared cache directory.
	Scope string `json:"scope"`

	// Names maps input name -> content hash.
	Names map[string]string `json:"names"`

	UpdatedAt time.Time `json:"updated_at"`
}

// Cache is the on-disk analysis cache. A nil *Cache is safe to use and
// behaves as "caching disabled".
type Cache struct {
	dir string

	// disabled is set when the cache directory is unusable; all
	// operations then become no-ops and analysis proceeds uncached.
	disabled bool

	warn func(string, ...any)

	// mu serialises in-process access to everything below.
	mu sync.Mutex

	// lockFile holds the exclusive cross-process flock for the run.
	lockFile *os.File

	// scope identifies this run's mode+config partition.
	scope string

	// priorNames is the name->hash mapping loaded from the previous
	// manifest at run start; currentNames is accumulated during the run.
	priorNames   map[string]string
	currentNames map[string]string

	// invalidate holds content hashes that must be recomputed even if
	// a valid entry exists (per-entry forced invalidation).
	invalidate map[string]bool

	// touched records entries used by this run. Their LastUsedAt is
	// persisted once into a single LRU index at Commit, so a cache hit
	// performs no per-entry write and no fsync - which is what keeps a
	// hit cheaper than re-parsing.
	touched map[string]bool

	// lru is the in-memory view of the shared LRU index
	// (content hash -> last used time), loaded once at BeginScope.
	lru map[string]time.Time

	maxEntries int

	stats   Stats
	changes []Change
}

// OpenCache prepares a cache rooted at dir. If dir cannot be created or
// is not writable, a warning is emitted and a disabled cache is
// returned so the caller degrades gracefully to uncached analysis.
func OpenCache(dir string, maxEntries int, warn func(string, ...any), invalidate []string) *Cache {
	c := &Cache{
		dir:        dir,
		warn:       warn,
		invalidate: make(map[string]bool),
		touched:    make(map[string]bool),
		lru:        make(map[string]time.Time),
		maxEntries: maxEntries,
	}
	for _, h := range invalidate {
		c.invalidate[h] = true
	}

	if err := os.MkdirAll(filepath.Join(dir, entriesDirName), 0o755); err != nil {
		warn("cache: cannot create cache directory %s (%v); falling back to uncached analysis", dir, err)
		c.disabled = true
		return c
	}

	// Probe writability: a read-only cache directory would fail later
	// on the first write. Detect it once, warn once, and degrade.
	probe := filepath.Join(dir, ".write-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		warn("cache: cache directory %s is not writable (%v); falling back to uncached analysis", dir, err)
		c.disabled = true
		return c
	}
	_ = os.Remove(probe)

	// Take the cross-process lock. A blocking lock keeps behaviour
	// deterministic: two runs sharing a directory cannot interleave
	// manifest updates. The kernel releases it if this process dies.
	lf, err := os.OpenFile(filepath.Join(dir, lockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		warn("cache: cannot open lock file in %s (%v); falling back to uncached analysis", dir, err)
		c.disabled = true
		return c
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		warn("cache: cannot lock %s (%v); falling back to uncached analysis", dir, err)
		lf.Close()
		c.disabled = true
		return c
	}
	c.lockFile = lf

	return c
}

// BeginScope loads the previous manifest for the mode+config partition
// this run belongs to. Called once after OpenCache.
func (c *Cache) BeginScope(scope string) {
	if !c.Enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.scope = scope
	c.currentNames = make(map[string]string)
	c.touched = make(map[string]bool)

	// Load the shared LRU index. It is global to the cache directory
	// (not per-scope), since eviction is a disk-space concern. A missing
	// or corrupt index simply means "no usage history"; eviction then
	// falls back to entry file mtimes.
	if data, err := os.ReadFile(c.lruPath()); err == nil {
		if err := json.Unmarshal(data, &c.lru); err != nil {
			c.warn("cache: LRU index is corrupt; rebuilding usage history from entry file times")
			c.lru = make(map[string]time.Time)
		}
	}

	data, err := os.ReadFile(c.manifestPath())
	if err != nil {
		// No previous manifest: first run for this scope.
		c.priorNames = make(map[string]string)
		return
	}

	var m manifestFile
	if err := json.Unmarshal(data, &m); err != nil {
		c.warn("cache: manifest for scope %s is corrupt; rebuilding it from this run", scope)
		c.priorNames = make(map[string]string)
		return
	}
	c.priorNames = m.Names
}

// Close releases the cross-process lock. Entries themselves are
// persistent and untouched by closing.
func (c *Cache) Close() {
	if c == nil || c.lockFile == nil {
		return
	}
	_ = syscall.Flock(int(c.lockFile.Fd()), syscall.LOCK_UN)
	_ = c.lockFile.Close()
	c.lockFile = nil
}

// Enabled reports whether the cache is operational.
func (c *Cache) Enabled() bool {
	return c != nil && !c.disabled
}

// ContentHash returns the SHA-256 hex digest of source. It is the
// script identity required by the hard constraints: content-based, so
// same-name/different-content scripts are never confused.
func ContentHash(source []byte) string {
	sum := sha256.Sum256(source)
	return hex.EncodeToString(sum[:])
}

// ConfigHash builds the hash of every option that affects what the
// analyser produces (not how the results are presented afterwards).
func ConfigHash(mode, placeholder string, patternsPayload []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "mode=%s\x00placeholder=%s\x00ruleVersion=%d\x00", mode, placeholder, RuleVersion)
	h.Write(patternsPayload)
	return hex.EncodeToString(h.Sum(nil))
}

func entryPath(dir, hash string) string {
	return filepath.Join(dir, entriesDirName, hash+".json")
}

func (c *Cache) manifestPath() string {
	sum := sha256.Sum256([]byte(c.scope))
	return filepath.Join(c.dir, "manifest-"+hex.EncodeToString(sum[:8])+".json")
}

func (c *Cache) lruPath() string {
	return filepath.Join(c.dir, touchName)
}

// Lookup returns the cached raw results for (mode, contentHash,
// configHash). The boolean is false (and no error) on a legitimate
// miss. A corrupt entry is counted, warned about, and reported as a
// miss so the caller recomputes - a corrupt cache must never change
// the analysis result.
//
// Cached JSON is decoded with UseNumber so integers keep their exact
// digit spelling: the re-marshalled output of a cache hit is byte
// identical to a fresh analysis.
func (c *Cache) Lookup(mode, contentHash, configHash string) (cachedResult, bool) {
	var zero cachedResult
	if !c.Enabled() {
		return zero, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.invalidate[contentHash] {
		c.stats.Invalid++
		return zero, false
	}

	path := entryPath(c.dir, contentHash)
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, false
	}

	var e entry
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&e); err != nil {
		c.warn("cache: corrupt entry %s ignored (%v); recomputing", path, err)
		c.stats.Corrupt++
		_ = os.Remove(path)
		return zero, false
	}

	if e.Version != RuleVersion || e.Mode != mode || e.ContentHash != contentHash || e.ConfigHash != configHash {
		// Stale entry: rule upgrade, option change, or hash mismatch.
		// It will be overwritten by Store.
		return zero, false
	}

	// Record usage in memory only. The shared LRU index is rewritten
	// once at Commit, so a cache hit performs no write and no fsync -
	// which is what keeps it cheaper than re-parsing.
	c.touched[contentHash] = true

	return e.Results, true
}

// Store writes (or overwrites) one entry atomically.
func (c *Cache) Store(mode, contentHash, configHash string, results cachedResult) error {
	if !c.Enabled() {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	e := entry{
		Version:     RuleVersion,
		Mode:        mode,
		ContentHash: contentHash,
		ConfigHash:  configHash,
		Results:     results,
		CreatedAt:   now,
		LastUsedAt:  now,
	}

	path := entryPath(c.dir, contentHash)
	if err := atomicWriteJSON(path, &e); err != nil {
		c.warn("cache: failed to write entry %s (%v); continuing without persisting this result", path, err)
		return err
	}
	return nil
}

// MarkInvalidated forces the entry for contentHash to be recomputed on
// the next Lookup (per-entry invalidation, usable when a single cached
// result is suspected to be wrong).
func (c *Cache) MarkInvalidated(contentHash string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidate[contentHash] = true
}

// RecordInput accounts for one processed input and tracks the name->hash
// mapping for end-of-run manifest reconciliation.
func (c *Cache) RecordInput(name, contentHash string, hit bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Inputs++
	if hit {
		c.stats.Hits++
	} else {
		c.stats.Misses++
	}
	if c.currentNames != nil {
		c.currentNames[name] = contentHash
	}
}

// PriorHash returns the content hash the manifest recorded for name in
// the previous run, and whether the name was known.
func (c *Cache) PriorHash(name string) (string, bool) {
	if !c.Enabled() {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	h, ok := c.priorNames[name]
	return h, ok
}

// loadEntry reads and decodes one entry file. Used for diffing a
// changed script against its previous incarnation.
func (c *Cache) loadEntry(hash string) (entry, bool) {
	data, err := os.ReadFile(entryPath(c.dir, hash))
	if err != nil {
		return entry{}, false
	}
	var e entry
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&e); err != nil {
		return entry{}, false
	}
	return e, true
}

// Commit reconciles the current run against the previous manifest:
//   - added names (new or previously unknown)
//   - removed names (known before, absent now; their entries and hence
//     their history are retained, only the manifest mapping is dropped)
//   - changed names (same name, different content), with an added/
//     removed diff of the raw match results
//
// The new manifest is written atomically.
func (c *Cache) Commit() (added, removed []string, changes []Change) {
	if !c.Enabled() {
		return nil, nil, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for name, hash := range c.currentNames {
		oldHash, existed := c.priorNames[name]
		if !existed {
			added = append(added, name)
			continue
		}
		if oldHash != hash {
			ch := Change{Name: name, OldHash: oldHash, NewHash: hash}
			oldEntry, oldOK := c.loadEntry(oldHash)
			newEntry, newOK := c.loadEntry(hash)
			switch {
			case !oldOK || !newOK:
				ch.Note = "previous or current entry unavailable; diff skipped"
			case oldEntry.Version != RuleVersion || oldEntry.ConfigHash != newEntry.ConfigHash:
				ch.Note = "rules or analysis options changed; old results invalidated, diff skipped"
			default:
				ch.Added, ch.Removed = diffResults(oldEntry.Results, newEntry.Results)
			}
			changes = append(changes, ch)
		}
	}
	for name := range c.priorNames {
		if _, ok := c.currentNames[name]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Slice(changes, func(i, j int) bool { return changes[i].Name < changes[j].Name })

	m := manifestFile{
		Version:   RuleVersion,
		Scope:     c.scope,
		Names:     c.currentNames,
		UpdatedAt: time.Now().UTC(),
	}
	if err := atomicWriteJSON(c.manifestPath(), &m); err != nil {
		c.warn("cache: failed to persist manifest %s (%v)", c.manifestPath(), err)
	}

	c.stats.Added = len(added)
	c.stats.Removed = len(removed)
	c.stats.Changed = len(changes)
	c.changes = changes

	c.persistLRU()
	return added, removed, changes
}

// persistLRU folds this run's usage into the shared LRU index and
// writes it as a single atomically-replaced file. This is the only
// usage-tracking write a run performs, regardless of how many entries
// were hit, so the read hot path stays write-free.
func (c *Cache) persistLRU() {
	if len(c.touched) == 0 {
		return
	}
	now := time.Now().UTC()
	for hash := range c.touched {
		c.lru[hash] = now
	}
	if err := atomicWriteJSON(c.lruPath(), c.lru); err != nil {
		c.warn("cache: could not persist LRU index (%v); eviction will use file times", err)
	}
}

// SnapshotChanges returns the per-script diffs computed by Commit.
func (c *Cache) SnapshotChanges() []Change {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Change, len(c.changes))
	copy(out, c.changes)
	return out
}

// canonicalMatch renders one match object deterministically so that two
// results can be compared as sets. Filename is presentation state and
// excluded from the comparison.
func canonicalMatch(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(b)
}

func resultSets(r cachedResult) map[string]struct{} {
	out := make(map[string]struct{})
	for _, u := range r.URLs {
		if u == nil {
			continue
		}
		cp := *u
		cp.Filename = ""
		out[canonicalMatch(cp)] = struct{}{}
	}
	for _, s := range r.Secrets {
		if s == nil {
			continue
		}
		cp := *s
		cp.Filename = ""
		out[canonicalMatch(cp)] = struct{}{}
	}
	return out
}

// diffResults returns the matches present in new but not old (added),
// and present in old but not new (removed).
func diffResults(old, new cachedResult) (added, removed []string) {
	oldSet := resultSets(old)
	newSet := resultSets(new)
	for k := range newSet {
		if _, ok := oldSet[k]; !ok {
			added = append(added, k)
		}
	}
	for k := range oldSet {
		if _, ok := newSet[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// Evict enforces the cache growth bound by removing the least recently
// used entries beyond maxEntries. Recency comes from the shared LRU
// index, falling back to entry file modification time. Entries
// referenced by the current run are protected unless the run alone
// exceeds the bound (which is then treated as a hard cap). A
// maxEntries <= 0 disables eviction.
func (c *Cache) Evict() {
	if !c.Enabled() || c.maxEntries <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	referenced := make(map[string]bool, len(c.currentNames))
	for _, h := range c.currentNames {
		referenced[h] = true
	}

	type meta struct {
		path string
		hash string
		used time.Time
	}
	var all []meta
	entriesRoot := filepath.Join(c.dir, entriesDirName)
	_ = filepath.WalkDir(entriesRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		base := filepath.Base(path)
		hash := base[:len(base)-len(".json")]
		used, known := c.lru[hash]
		if !known {
			used = fileMtime(path)
		}
		all = append(all, meta{path: path, hash: hash, used: used})
		return nil
	})

	if len(all) <= c.maxEntries {
		return
	}

	sort.Slice(all, func(i, j int) bool { return all[i].used.Before(all[j].used) })

	// Two-phase eviction. First drop entries not referenced by the
	// current run, oldest first; those are the natural LRU victims. If
	// the current run alone still exceeds the size bound, the bound is
	// a hard cap, so continue evicting the oldest referenced entries.
	removed := 0
	evict := func(allowReferenced bool) {
		for _, m := range all {
			if len(all)-removed <= c.maxEntries {
				return
			}
			if referenced[m.hash] && !allowReferenced {
				continue
			}
			if err := os.Remove(m.path); err == nil {
				delete(c.lru, m.hash)
				removed++
			}
		}
	}
	evict(false)
	evict(true)
	c.stats.Evicted += removed
}

// fileMtime returns a file's modification time, or the zero time.
func fileMtime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

// SnapshotStats returns a copy of the current statistics and the total
// number of entry files currently in the cache.
func (c *Cache) SnapshotStats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Degraded = c.disabled
	root := filepath.Join(c.dir, entriesDirName)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(path) == ".json" {
			s.CacheSize++
		}
		return nil
	})
	return s
}

// atomicWriteJSON marshals v and writes it to dst atomically: write to
// a temp file in the same directory, fsync, then rename. A crash at any
// point leaves the previous file intact; readers never see a partial
// file because the rename is the only visible step.
func atomicWriteJSON(dst string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, filepath.Base(dst)+".*"+tmpSuffix)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
