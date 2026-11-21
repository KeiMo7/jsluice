package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/BishopFox/jsluice"
)

// extractSecrets is the original single-shot entry point: analyse the
// source and present the results in one call. Unchanged in behaviour
// when caching is disabled.
func extractSecrets(opts options, filename string, source []byte, output chan string, errs chan error) {
	raw, err := analyzeSecrets(opts, source)
	if err != nil {
		errs <- err
		return
	}
	presentSecrets(filename, raw.Secrets, output, errs)
}

// analyzeSecrets runs only the tree-sitter secret analysis (the
// expensive step), including loading any user-supplied patterns, and
// returns the raw matches with no filename assigned. Pattern open/parse
// errors are returned exactly as the original implementation returned
// them on the error channel.
func analyzeSecrets(opts options, source []byte) (cachedResult, error) {
	analyzer := jsluice.NewAnalyzer(source)

	// TODO: come up with a nice way to cache the patterns file and
	// only throw any open or parse errors once
	if opts.patternsFile != "" {
		f, err := os.Open(opts.patternsFile)
		if err != nil {
			return cachedResult{}, err
		}

		patterns, err := jsluice.ParseUserPatterns(f)
		if err != nil {
			return cachedResult{}, err
		}

		analyzer.AddSecretMatchers(patterns.SecretMatchers())
	}

	return cachedResult{Secrets: analyzer.GetSecrets()}, nil
}

// presentSecrets runs the unchanged presentation layer over a set of
// raw secret matches, shared by the fresh and cached code paths.
func presentSecrets(filename string, matches []*jsluice.Secret, output chan string, errs chan error) {
	for _, match := range matches {

		match.Filename = filename

		j, err := json.Marshal(match)
		if err != nil {
			continue
		}
		output <- fmt.Sprintf("%s", j)
	}
}
