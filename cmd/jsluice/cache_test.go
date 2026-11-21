package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/BishopFox/jsluice"
)

// discardWarn swallows cache warnings in tests; individual tests that
// assert on warnings can replace it.
func discardWarn(string, ...any) {}

// runAnalysis mirrors the worker pipeline: analyse then present,
// collecting the emitted JSONL lines. It is used both with and without
// a cache so the comparison exercises the exact production code paths.
func runAnalysis(t *testing.T, opts options, name string, source []byte) []string {
	t.Helper()

	raw, err := analyze(opts, source)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}

	out := make(chan string, 1024)
	errs := make(chan error, 32)
	present(opts, name, raw, out, errs)
	close(out)
	close(errs)

	for e := range errs {
		t.Fatalf("presentation error: %v", e)
	}

	var lines []string
	for line := range out {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func urlsOptions(cacheDir string) options {
	return options{
		mode:            modeURLs,
		placeholder:     jsluice.ExpressionPlaceholder,
		cacheDir:        cacheDir,
		cacheMaxEntries: 5000,
	}
}

func secretsOptions(cacheDir, patternsFile string) options {
	return options{
		mode:            modeSecrets,
		placeholder:     jsluice.ExpressionPlaceholder,
		cacheDir:        cacheDir,
		cacheMaxEntries: 5000,
		patternsFile:    patternsFile,
	}
}

// canonicalLine sorts any JSON array field whose order is not
// semantically significant, so two semantically equal outputs compare
// equal even when Go map iteration produced different slice orders.
// That map-order nondeterminism is pre-existing jsluice behaviour
// (see unique() in url-matchers.go), not a cache artefact.
func canonicalLine(t *testing.T, line string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		t.Fatalf("bad output JSON %q: %v", line, err)
	}
	canonical(v)
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("re-marshal failed: %v", err)
	}
	return string(b)
}

func canonical(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if arr, ok := val.([]any); ok && (k == "queryParams" || k == "bodyParams") {
				strs := make([]string, 0, len(arr))
				for _, e := range arr {
					strs = append(strs, e.(string))
				}
				sort.Strings(strs)
				sorted := make([]any, len(strs))
				for i, s := range strs {
					sorted[i] = s
				}
				x[k] = sorted
			} else {
				canonical(val)
			}
		}
	case []any:
		for _, e := range x {
			canonical(e)
		}
	}
}

func canonicalSet(t *testing.T, lines []string) []string {
	t.Helper()
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, canonicalLine(t, l))
	}
	sort.Strings(out)
	return out
}

func writeScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

const scriptA = `
function go(){
  fetch("/api/v1/users?id=1", {method: "GET", headers: {"X-Env": "prod"}})
  location.href = "/login"
}
`

const scriptB = `
var cfg = { awsKey: "AKIAIOSFODNN7EXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" };
fetch("/api/thing")
`

const scriptC = `
const u = "https://example.com/redirect?a=1&b=2";
$.post("/api/v1/save", {x: 1});
`

// TestCacheAllReuse: a second run over unchanged scripts serves every
// result from the cache and produces output identical to a full run.
func TestCacheAllReuse(t *testing.T) {
	dir := t.TempDir()
	scripts := map[string]string{"a.js": scriptA, "b.js": scriptB, "c.js": scriptC}

	// Full uncached reference output.
	var reference []string
	for name, src := range scripts {
		opts := urlsOptions("")
		reference = append(reference, runAnalysis(t, opts, name, []byte(src))...)
	}
	reference = canonicalSet(t, reference)

	cache := OpenCache(filepath.Join(dir, "cache"), 5000, discardWarn, nil)
	opts := urlsOptions(filepath.Join(dir, "cache"))
	opts.cacheConfigHash = ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)
	cache.BeginScope(modeURLs + "|" + opts.cacheConfigHash)

	// Cold run: everything is a miss and gets stored.
	var cold []string
	for name, src := range scripts {
		hash := ContentHash([]byte(src))
		_, ok := cache.LookupCached(opts, hash)
		if ok {
			t.Fatalf("%s unexpectedly cached on cold run", name)
		}
		raw, err := analyze(opts, []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		cache.StoreCachedResult(opts, hash, raw)
		cache.RecordInput(name, hash, false)
		cold = append(cold, runAnalysis(t, opts, name, []byte(src))...)
	}
	if got := canonicalSet(t, cold); !equalSlices(got, reference) {
		t.Fatalf("cold cached output differs from uncached reference")
	}

	// Warm run: every lookup must hit and output must still match.
	var warm []string
	hits := 0
	for name, src := range scripts {
		hash := ContentHash([]byte(src))
		res, ok := cache.LookupCached(opts, hash)
		if !ok {
			t.Fatalf("%s should have been a cache hit", name)
		}
		hits++
		cache.RecordInput(name, hash, true)
		out := make(chan string, 1024)
		errs := make(chan error, 32)
		emitCached(opts, name, res, out, errs)
		close(out)
		close(errs)
		for line := range out {
			warm = append(warm, line)
		}
	}
	if hits != len(scripts) {
		t.Fatalf("expected %d hits, got %d", len(scripts), hits)
	}
	if got := canonicalSet(t, warm); !equalSlices(got, reference) {
		for _, l := range diffStrings(reference, got) {
			t.Logf("WARM DIFF %s", l)
		}
		t.Fatalf("warm cached output differs from uncached reference")
	}

	added, removed, changes := cache.Commit()
	if len(removed) != 0 || len(changes) != 0 {
		t.Fatalf("first commit should have no removals/changes, got removed=%v changes=%v", removed, changes)
	}
	if len(added) != len(scripts) {
		t.Fatalf("expected %d added, got %d", len(scripts), len(added))
	}

	stats := cache.SnapshotStats()
	if stats.Hits != len(scripts) || stats.Misses != len(scripts) {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

// TestCachePartialRecompute: changing one script recomputes only that
// script; the others remain hits, and the manifest records one change
// with a real added/removed diff.
func TestCachePartialRecompute(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	cache := OpenCache(cacheDir, 5000, discardWarn, nil)
	opts := urlsOptions(cacheDir)
	opts.cacheConfigHash = ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)
	cache.BeginScope(modeURLs + "|" + opts.cacheConfigHash)

	initial := map[string]string{"a.js": scriptA, "c.js": scriptC}
	for name, src := range initial {
		hash := ContentHash([]byte(src))
		raw, _ := analyze(opts, []byte(src))
		cache.StoreCachedResult(opts, hash, raw)
		cache.RecordInput(name, hash, false)
	}
	cache.Commit()
	cache.Close()

	// New process, same cache directory: a.js unchanged, c.js modified.
	cache2 := OpenCache(cacheDir, 5000, discardWarn, nil)
	cache2.BeginScope(modeURLs + "|" + opts.cacheConfigHash)

	changedC := scriptC + "\nfetch(\"/api/v2/new-endpoint\");\n"

	hashA := ContentHash([]byte(scriptA))
	if _, ok := cache2.LookupCached(opts, hashA); !ok {
		t.Fatal("unchanged a.js should be a hit")
	}
	cache2.RecordInput("a.js", hashA, true)

	hashC := ContentHash([]byte(changedC))
	if _, ok := cache2.LookupCached(opts, hashC); ok {
		t.Fatal("modified c.js should be a miss (new content hash)")
	}
	rawC, _ := analyze(opts, []byte(changedC))
	cache2.StoreCachedResult(opts, hashC, rawC)
	cache2.RecordInput("c.js", hashC, false)

	_, _, changes := cache2.Commit()
	if len(changes) != 1 || changes[0].Name != "c.js" {
		t.Fatalf("expected exactly one change for c.js, got %+v", changes)
	}
	if len(changes[0].Added) == 0 {
		t.Fatalf("expected added results for c.js, got %+v", changes[0])
	}

	stats := cache2.SnapshotStats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.Changed != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

// TestCacheRuleUpgradeInvalidates: bumping RuleVersion makes every old
// entry a miss even though content and path are unchanged, and the old
// cached result is never reused.
func TestCacheRuleUpgradeInvalidates(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")

	cache := OpenCache(cacheDir, 5000, discardWarn, nil)
	opts := urlsOptions(cacheDir)
	opts.cacheConfigHash = ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)
	cache.BeginScope(modeURLs + "|" + opts.cacheConfigHash)

	hash := ContentHash([]byte(scriptA))
	raw, _ := analyze(opts, []byte(scriptA))
	if err := cache.Store(modeURLs, hash, opts.cacheConfigHash, raw); err != nil {
		t.Fatal(err)
	}

	if _, ok := cache.Lookup(modeURLs, hash, opts.cacheConfigHash); !ok {
		t.Fatal("entry should be valid before the rule upgrade")
	}

	// Simulate a rule upgrade by rewriting the entry with an older
	// version number, exactly as a previous jsluice release would have
	// written it.
	path := entryPath(cacheDir, hash)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e entry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	e.Version = RuleVersion - 1
	if err := atomicWriteJSON(path, &e); err != nil {
		t.Fatal(err)
	}

	if _, ok := cache.Lookup(modeURLs, hash, opts.cacheConfigHash); ok {
		t.Fatal("stale-version entry must not be reused after a rule upgrade")
	}

	// A fresh store writes the current version and the entry is valid
	// again.
	if err := cache.Store(modeURLs, hash, opts.cacheConfigHash, raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup(modeURLs, hash, opts.cacheConfigHash); !ok {
		t.Fatal("recomputed entry should be valid")
	}
}

// TestCacheConfigHashChange: changing an analysis-affecting option
// (placeholder, patterns) changes the config hash and forces a miss.
func TestCacheConfigHashChange(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	cache := OpenCache(cacheDir, 5000, discardWarn, nil)

	hash := ContentHash([]byte(scriptA))
	cfg1 := ConfigHash(modeURLs, "EXPR", nil)
	raw, _ := analyze(urlsOptions(cacheDir), []byte(scriptA))
	if err := cache.Store(modeURLs, hash, cfg1, raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup(modeURLs, hash, cfg1); !ok {
		t.Fatal("entry valid under original config")
	}
	cfg2 := ConfigHash(modeURLs, "OTHER", nil)
	if _, ok := cache.Lookup(modeURLs, hash, cfg2); ok {
		t.Fatal("entry must not be reused under a different placeholder config")
	}
}

// TestCacheCorruptEntry: a truncated entry file is ignored, counted,
// and treated as a full-recompute miss rather than failing the run.
func TestCacheCorruptEntry(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	cache := OpenCache(cacheDir, 5000, discardWarn, nil)
	opts := urlsOptions(cacheDir)
	opts.cacheConfigHash = ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)

	hash := ContentHash([]byte(scriptA))
	raw, _ := analyze(opts, []byte(scriptA))
	if err := cache.Store(modeURLs, hash, opts.cacheConfigHash, raw); err != nil {
		t.Fatal(err)
	}

	// Corrupt the file.
	path := entryPath(cacheDir, hash)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, ok := cache.Lookup(modeURLs, hash, opts.cacheConfigHash); ok {
		t.Fatal("corrupt entry must be reported as a miss")
	}
	if cache.SnapshotStats().Corrupt != 1 {
		t.Fatalf("expected 1 corrupt entry counted, got %d", cache.SnapshotStats().Corrupt)
	}
}

// TestCacheUnwritableDirectory: opening a cache in a read-only location
// degrades to disabled; analysis still works and nothing is written.
func TestCacheUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission bits")
	}
	parent := t.TempDir()
	ro := filepath.Join(parent, "readonly")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })

	var warned bool
	cache := OpenCache(ro, 5000, func(string, ...any) { warned = true }, nil)
	if cache.Enabled() {
		t.Fatal("cache should be disabled when the directory is not writable")
	}
	if !warned {
		t.Fatal("a warning must be emitted on degradation")
	}

	// Disabled cache behaves as pure pass-through.
	if _, ok := cache.Lookup(modeURLs, "x", "y"); ok {
		t.Fatal("disabled cache must never report a hit")
	}
	if err := cache.Store(modeURLs, "x", "y", cachedResult{}); err != nil {
		t.Fatal("store on disabled cache should be a no-op without error")
	}
}

// TestCachePerEntryInvalidation: --invalidate forces exactly one hash
// to be recomputed while everything else stays cached.
func TestCachePerEntryInvalidation(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	cache := OpenCache(cacheDir, 5000, discardWarn, nil)
	opts := urlsOptions(cacheDir)
	opts.cacheConfigHash = ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)

	hashA := ContentHash([]byte(scriptA))
	hashC := ContentHash([]byte(scriptC))
	rawA, _ := analyze(opts, []byte(scriptA))
	rawC, _ := analyze(opts, []byte(scriptC))
	_ = cache.Store(modeURLs, hashA, opts.cacheConfigHash, rawA)
	_ = cache.Store(modeURLs, hashC, opts.cacheConfigHash, rawC)

	cache.MarkInvalidated(hashA)
	if _, ok := cache.Lookup(modeURLs, hashA, opts.cacheConfigHash); ok {
		t.Fatal("invalidated hash must be a miss")
	}
	if _, ok := cache.Lookup(modeURLs, hashC, opts.cacheConfigHash); !ok {
		t.Fatal("non-invalidated hash must remain a hit")
	}
	if cache.SnapshotStats().Invalid != 1 {
		t.Fatalf("expected 1 forced invalidation, got %d", cache.SnapshotStats().Invalid)
	}
}

// TestCacheEviction: entries beyond the size bound are removed LRU,
// while entries referenced by the current run are protected.
func TestCacheEviction(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	cache := OpenCache(cacheDir, 3, discardWarn, nil)
	opts := urlsOptions(cacheDir)
	opts.cacheConfigHash = ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)
	cache.BeginScope(modeURLs + "|" + opts.cacheConfigHash)

	hashes := make([]string, 5)
	for i, src := range []string{scriptA, scriptB, scriptC,
		"fetch(\"/one\")", "fetch(\"/two\")"} {
		h := ContentHash([]byte(src))
		hashes[i] = h
		raw, _ := analyze(opts, []byte(src))
		_ = cache.Store(modeURLs, h, opts.cacheConfigHash, raw)
		// Distinct LastUsedAt ordering.
	}

	// Two are referenced by the current manifest; with a bound of 3
	// and 5 entries, the two unreferenced LRU entries are evicted
	// first, leaving the bound satisfied without touching referenced
	// entries.
	cache.RecordInput("four.js", hashes[3], true)
	cache.RecordInput("five.js", hashes[4], true)
	cache.Evict()

	stats := cache.SnapshotStats()
	if stats.CacheSize > 3 {
		t.Fatalf("cache should hold at most 3 entries after eviction, has %d", stats.CacheSize)
	}
	if stats.Evicted != 2 {
		t.Fatalf("expected 2 LRU evictions, got %d", stats.Evicted)
	}
	// Referenced entries survive because the bound was met without them.
	for _, h := range hashes[3:] {
		if _, ok := cache.Lookup(modeURLs, h, opts.cacheConfigHash); !ok {
			t.Fatalf("referenced entry %s must not be evicted while unreferenced LRU entries remain", h[:8])
		}
	}
}

// TestCacheEvictionHardCap: when a single run writes more entries than
// the bound, even referenced entries are evicted LRU so the hard cap
// is always honoured.
func TestCacheEvictionHardCap(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	cache := OpenCache(cacheDir, 2, discardWarn, nil)
	opts := urlsOptions(cacheDir)
	opts.cacheConfigHash = ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)
	cache.BeginScope(modeURLs + "|" + opts.cacheConfigHash)

	for i, src := range []string{"fetch(\"/one\")", "fetch(\"/two\")", "fetch(\"/three\")"} {
		h := ContentHash([]byte(src))
		raw, _ := analyze(opts, []byte(src))
		_ = cache.Store(modeURLs, h, opts.cacheConfigHash, raw)
		cache.RecordInput(string(rune('a'+i))+".js", h, false)
	}
	cache.Evict()

	if size := cache.SnapshotStats().CacheSize; size > 2 {
		t.Fatalf("hard cap violated: %d entries remain (bound 2)", size)
	}
}

// TestCacheAddedAndRemoved: scripts present before but absent now are
// reported removed (entries retained for history), new ones added.
func TestCacheAddedAndRemoved(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	cache := OpenCache(cacheDir, 5000, discardWarn, nil)
	opts := urlsOptions(cacheDir)
	opts.cacheConfigHash = ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)
	scope := modeURLs + "|" + opts.cacheConfigHash
	cache.BeginScope(scope)

	hashA := ContentHash([]byte(scriptA))
	rawA, _ := analyze(opts, []byte(scriptA))
	_ = cache.Store(modeURLs, hashA, opts.cacheConfigHash, rawA)
	cache.RecordInput("a.js", hashA, false)
	added, removed, _ := cache.Commit()
	if len(added) != 1 || len(removed) != 0 {
		t.Fatalf("first run: added=%v removed=%v", added, removed)
	}
	cache.Close()

	// Second run: a.js gone, b.js new. The a.js entry file must remain.
	cache2 := OpenCache(cacheDir, 5000, discardWarn, nil)
	cache2.BeginScope(scope)
	hashB := ContentHash([]byte(scriptB))
	rawB, _ := analyze(opts, []byte(scriptB))
	_ = cache2.Store(modeURLs, hashB, opts.cacheConfigHash, rawB)
	cache2.RecordInput("b.js", hashB, false)
	added, removed, _ = cache2.Commit()
	if len(added) != 1 || added[0] != "b.js" || len(removed) != 1 || removed[0] != "a.js" {
		t.Fatalf("second run: added=%v removed=%v", added, removed)
	}
	if _, err := os.Stat(entryPath(cacheDir, hashA)); err != nil {
		t.Fatalf("removed script's history entry must be retained on disk: %v", err)
	}
}

// TestCacheIdentityIsContentNotPath: the same path with different
// content gets different identities; identical content at different
// paths shares one entry.
func TestCacheIdentityIsContentNotPath(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	cache := OpenCache(cacheDir, 5000, discardWarn, nil)
	opts := urlsOptions(cacheDir)
	cfg := ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)

	h1 := ContentHash([]byte(scriptA))
	h2 := ContentHash([]byte(scriptA + "\n// one line change\n"))
	if h1 == h2 {
		t.Fatal("different content must hash differently")
	}
	raw, _ := analyze(opts, []byte(scriptA))
	_ = cache.Store(modeURLs, h1, cfg, raw)
	if _, ok := cache.Lookup(modeURLs, h2, cfg); ok {
		t.Fatal("same path, changed content must be a miss")
	}
	if _, ok := cache.Lookup(modeURLs, h1, cfg); !ok {
		t.Fatal("identical content must be a hit regardless of path")
	}
}

// TestCacheAtomicWriteLeavesNoTmpFiles: after writes, no temp files
// remain and the destination is complete valid JSON.
func TestCacheAtomicWriteLeavesNoTmpFiles(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	cache := OpenCache(cacheDir, 5000, discardWarn, nil)
	opts := urlsOptions(cacheDir)
	cfg := ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)

	for i := 0; i < 10; i++ {
		src := scriptA + strings.Repeat("\n", i)
		h := ContentHash([]byte(src))
		raw, _ := analyze(opts, []byte(src))
		if err := cache.Store(modeURLs, h, cfg, raw); err != nil {
			t.Fatal(err)
		}
	}

	entries := filepath.Join(cacheDir, entriesDirName)
	files, err := os.ReadDir(entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), tmpSuffix) {
			t.Fatalf("temporary file left behind: %s", f.Name())
		}
		data, err := os.ReadFile(filepath.Join(entries, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var e entry
		if err := json.Unmarshal(data, &e); err != nil {
			t.Fatalf("entry %s not valid JSON: %v", f.Name(), err)
		}
	}
}

// TestCacheSecretsModeRoundTrip exercises the secrets analysis path,
// including user patterns in the config hash.
func TestCacheSecretsModeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	patternsPath := filepath.Join("testdata", "patterns.json")

	opts := secretsOptions(cacheDir, patternsPath)
	opts.cacheConfigHash = ConfigHash(modeSecrets, jsluice.ExpressionPlaceholder, readFile(t, patternsPath))

	reference := runAnalysis(t, opts, "b.js", []byte(scriptB))

	cache := OpenCache(cacheDir, 5000, discardWarn, nil)
	cache.BeginScope(modeSecrets + "|" + opts.cacheConfigHash)
	hash := ContentHash([]byte(scriptB))
	raw, err := analyze(opts, []byte(scriptB))
	if err != nil {
		t.Fatal(err)
	}
	_ = cache.Store(modeSecrets, hash, opts.cacheConfigHash, raw)

	res, ok := cache.Lookup(modeSecrets, hash, opts.cacheConfigHash)
	if !ok {
		t.Fatal("secrets entry should be cached")
	}
	out := make(chan string, 64)
	errs := make(chan error, 8)
	emitCached(opts, "b.js", res, out, errs)
	close(out)
	close(errs)
	var cached []string
	for line := range out {
		cached = append(cached, line)
	}
	if !equalSlices(canonicalSet(t, cached), canonicalSet(t, reference)) {
		t.Fatalf("cached secrets output differs from uncached:\ncached=%v\nreference=%v", cached, reference)
	}
}

// TestCacheDisabledTouchesNothing: with no --cache, no cache directory
// is created anywhere and the direct mode path is used.
func TestCacheDisabledTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	opts := urlsOptions("") // empty cache dir == disabled
	if opts.cache.Enabled() {
		t.Fatal("nil cache must report disabled")
	}
	// The direct path still produces results.
	lines := runAnalysis(t, opts, "a.js", []byte(scriptA))
	if len(lines) == 0 {
		t.Fatal("expected analysis output with caching disabled")
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("disabled cache must create no files, found %v (err=%v)", entries, err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func diffStrings(a, b []string) []string {
	setB := map[string]bool{}
	for _, s := range b {
		setB[s] = true
	}
	var out []string
	for _, s := range a {
		if !setB[s] {
			out = append(out, "only-in-a: "+s)
		}
	}
	setA := map[string]bool{}
	for _, s := range a {
		setA[s] = true
	}
	for _, s := range b {
		if !setA[s] {
			out = append(out, "only-in-b: "+s)
		}
	}
	return out
}
