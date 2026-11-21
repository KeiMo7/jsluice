package main

// Cache bridge: connects the generic on-disk Cache to the two analysis
// modes. Everything here is only exercised when --cache is set; without
// it the worker calls the mode functions directly.

import (
	"bytes"
	"encoding/json"
	"net/url"

	"github.com/BishopFox/jsluice"
)

// LookupCached returns the cached raw result for the given content hash
// when one exists for the current mode/config, and false on a miss.
func (c *Cache) LookupCached(opts options, contentHash string) (cachedResult, bool) {
	if !c.Enabled() {
		return cachedResult{}, false
	}
	return c.Lookup(opts.mode, contentHash, opts.cacheConfigHash)
}

// StoreCachedResult persists raw matches for one script. Called once on
// a miss after a successful analysis.
func (c *Cache) StoreCachedResult(opts options, contentHash string, res cachedResult) {
	if !c.Enabled() {
		return
	}
	_ = c.Store(opts.mode, contentHash, opts.cacheConfigHash, res)
}

// analyze runs only the tree-sitter analysis (the expensive step) and
// returns the raw matches without any presentation processing.
func analyze(opts options, source []byte) (cachedResult, error) {
	switch opts.mode {
	case modeURLs:
		return analyzeURLs(opts, source)
	case modeSecrets:
		return analyzeSecrets(opts, source)
	default:
		return cachedResult{}, nil
	}
}

// present runs the unchanged presentation layer over raw matches.
func present(opts options, name string, raw cachedResult, output chan string, errs chan error) {
	switch opts.mode {
	case modeURLs:
		var resolveURL *url.URL
		if opts.resolvePaths != "" {
			parsed, err := url.Parse(opts.resolvePaths)
			if err != nil {
				errs <- err
				return
			}
			resolveURL = parsed
		}
		presentURLs(opts, name, resolveURL, raw.URLs, output, errs)
	case modeSecrets:
		presentSecrets(name, raw.Secrets, output, errs)
	}
}

// emitCached replays cached raw matches through the unchanged
// presentation layer. The cached value is deep-copied first because the
// presentation layer mutates the match structs (it sets Filename and may
// clear Source); without the copy two goroutines sharing one cache hit
// could observe each other's mutations.
func emitCached(opts options, name string, res cachedResult, output chan string, errs chan error) {
	cp := deepCopyResult(res)
	present(opts, name, cp, output, errs)
}

// deepCopyResult returns a value with no shared pointers/maps relative
// to in. The cache itself stores freshly unmarshalled structs on every
// Lookup, so each hit already owns its memory; this copy additionally
// guards the in-memory fallback and keeps the boundary explicit.
func deepCopyResult(in cachedResult) cachedResult {
	out := cachedResult{
		URLs:    make([]*jsluice.URL, 0, len(in.URLs)),
		Secrets: make([]*jsluice.Secret, 0, len(in.Secrets)),
	}
	for _, u := range in.URLs {
		if u == nil {
			continue
		}
		cp := *u
		if u.Headers != nil {
			cp.Headers = cloneStringMap(u.Headers)
		}
		// make+copy (not append-to-nil) so an empty but non-nil slice
		// stays non-nil: jsluice guarantees [] over null for these
		// fields, and the cached output must preserve that.
		cp.QueryParams = make([]string, len(u.QueryParams))
		copy(cp.QueryParams, u.QueryParams)
		cp.BodyParams = make([]string, len(u.BodyParams))
		copy(cp.BodyParams, u.BodyParams)
		out.URLs = append(out.URLs, &cp)
	}
	for _, s := range in.Secrets {
		if s == nil {
			continue
		}
		cp := *s
		// Data and Context are arbitrary values; round-trip them
		// through JSON so nested maps/slices are not shared.
		cp.Data = cloneAny(s.Data)
		cp.Context = cloneAny(s.Context)
		out.Secrets = append(out.Secrets, &cp)
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// cloneAny deep-copies an arbitrary JSON-compatible value. A nil input
// returns nil. json.Number survives the round trip as a json.Number,
// preserving integer digit spellings.
func cloneAny(in any) any {
	if in == nil {
		return nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		// Should be unreachable for values produced by the analyser,
		// all of which are JSON-compatible. Fall back to sharing rather
		// than dropping data.
		return in
	}
	var out any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return in
	}
	return out
}
