package main

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/BishopFox/jsluice"
)

// extractURLs is the original single-shot entry point: analyse the
// source and present the results in one call. Unchanged in behaviour
// when caching is disabled.
func extractURLs(opts options, filename string, source []byte, output chan string, errs chan error) {
	raw, err := analyzeURLs(opts, source)
	if err != nil {
		errs <- err
		return
	}

	var resolveURL *url.URL
	if opts.resolvePaths != "" {
		// err was already surfaced by analyzeURLs; re-parsing here only
		// happens on the success path.
		parsed, _ := url.Parse(opts.resolvePaths)
		resolveURL = parsed
	}

	presentURLs(opts, filename, resolveURL, raw.URLs, output, errs)
}

// analyzeURLs runs only the tree-sitter URL analysis (the expensive
// step) and returns raw matches, with no filename assigned and no
// presentation processing applied. The -R base URL parse is validated
// here so error timing matches the original implementation.
func analyzeURLs(opts options, source []byte) (cachedResult, error) {
	var resolveURL *url.URL
	if opts.resolvePaths != "" {
		parsed, err := url.Parse(opts.resolvePaths)
		if err != nil {
			return cachedResult{}, err
		}
		resolveURL = parsed
	}

	analzyer := jsluice.NewAnalyzer(source)
	matches := analzyer.GetURLs()

	// The resolution transform only rewrites the URL string and does
	// not depend on the filename or other presentation state, but the
	// cached value must describe the raw analysis. Resolution is
	// therefore applied in presentURLs below (as in the original code).
	_ = resolveURL

	return cachedResult{URLs: matches}, nil
}

// presentURLs runs the unchanged presentation layer over a set of raw
// URL matches. It is shared by the uncached path (fresh matches) and
// the cached path (matches loaded from disk), which is what guarantees
// byte-identical output in both cases.
func presentURLs(opts options, filename string, resolveURL *url.URL, matches []*jsluice.URL, output chan string, errs chan error) {
	seen := make(map[string]any, 0)

	for _, m := range matches {
		if opts.ignoreStrings && m.Type == "stringLiteral" {
			continue
		}

		m.Filename = filename

		// remove any souce if we don't want to display it
		if !opts.includeSource {
			m.Source = ""
		}

		if resolveURL != nil {
			parsed, err := url.Parse(m.URL)
			if err == nil {
				m.URL = resolveURL.ResolveReference(parsed).String()
			}
		}

		if _, exists := seen[m.URL]; opts.unique && exists {
			continue
		}
		seen[m.URL] = struct{}{}

		j, err := json.Marshal(m)
		if err != nil {
			errs <- err
			continue
		}
		output <- fmt.Sprintf("%s", j)
	}
}
