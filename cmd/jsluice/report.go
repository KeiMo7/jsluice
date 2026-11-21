package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/BishopFox/jsluice"
)

// extractReport implements the "report" mode: a single pass over the
// source that produces one structured JSON report per input file,
// covering endpoints, URL literals, credentials, internal domains and
// comments, with positions, de-duplication and optional masking.
func extractReport(opts options, filename string, source []byte, output chan string, errs chan error) {
	report := buildReport(opts, filename, source, errs)
	if report == nil {
		return
	}

	j, err := json.Marshal(report)
	if err != nil {
		errs <- err
		return
	}
	output <- string(j)
}

// buildReport runs the decode -> parse -> extract -> aggregate pipeline
// for one source. It always returns a complete report; sources that
// cannot be analyzed yield a skipped report with the reason recorded.
func buildReport(opts options, filename string, source []byte, errs chan error) *jsluice.Report {
	decoded, encoding, err := jsluice.DecodeSource(source)
	if err != nil {
		return jsluice.SkippedReport(filename, err.Error())
	}

	analyzer := jsluice.NewAnalyzer(decoded)

	// Files with syntax errors are skipped by default; --partial
	// downgrades that to a warning and extracts whatever is possible.
	if analyzer.HasSyntaxError() && !opts.partial {
		return jsluice.SkippedReport(filename, "syntax errors detected")
	}

	if opts.patternsFile != "" {
		f, err := os.Open(opts.patternsFile)
		if err != nil {
			errs <- err
			return nil
		}
		defer f.Close()

		patterns, err := jsluice.ParseUserPatterns(f)
		if err != nil {
			errs <- err
			return nil
		}
		analyzer.AddSecretMatchers(patterns.SecretMatchers())
	}

	findings, warnings := analyzer.ExtractFindings()

	report := jsluice.AggregateFindings(decoded, filename, findings, warnings, jsluice.AggregateOptions{
		Mask:  !opts.unmask,
		Kinds: opts.kinds,
	})
	if encoding != "utf-8" {
		report.Encoding = encoding
	}
	return report
}

// parseKinds parses a comma-separated list of finding kinds into the
// filter map used by AggregateOptions. An empty string means no filter.
func parseKinds(s string) (map[jsluice.FindingKind]bool, error) {
	if s == "" {
		return nil, nil
	}

	valid := make(map[jsluice.FindingKind]bool)
	for _, k := range jsluice.AllFindingKinds() {
		valid[k] = true
	}

	out := make(map[jsluice.FindingKind]bool)
	for _, part := range strings.Split(s, ",") {
		kind := jsluice.FindingKind(strings.TrimSpace(part))
		if !valid[kind] {
			return nil, fmt.Errorf("unknown finding kind %q (valid: %s)", part, allKindNames())
		}
		out[kind] = true
	}
	return out, nil
}

func allKindNames() string {
	names := make([]string, 0)
	for _, k := range jsluice.AllFindingKinds() {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}
