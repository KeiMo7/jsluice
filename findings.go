package jsluice

// This file implements the structured extraction layer. It sits on top
// of the existing URL and secret matchers (which are unchanged) and
// organizes their results into typed findings with position information.
//
// All type-classification rules (what counts as an endpoint vs a URL
// literal, what counts as an internal domain, how sensitive values are
// masked) live in this file and only in this file, so that every output
// path classifies and redacts findings the same way.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// FindingKind identifies the category of a Finding.
type FindingKind string

const (
	// KindEndpoint is a URL that is actually used by the code:
	// fetch() calls, XHR, $.ajax, location assignments etc.
	KindEndpoint FindingKind = "endpoint"

	// KindURLLiteral is a URL-looking string literal with no
	// known usage context.
	KindURLLiteral FindingKind = "urlLiteral"

	// KindCredential is a suspected secret: API keys, tokens etc.
	KindCredential FindingKind = "credential"

	// KindInternalDomain is a hostname that looks like it belongs
	// to an internal network (private IPs, .local/.corp/... names,
	// bare hostnames, localhost).
	KindInternalDomain FindingKind = "internalDomain"

	// KindComment is a source code comment, which often contains
	// TODOs, old endpoints, credentials or other clues.
	KindComment FindingKind = "comment"
)

// AllFindingKinds returns every FindingKind in a fixed order. It is the
// single definition of "which categories exist"; reports use it to make
// sure empty categories are represented explicitly rather than omitted.
func AllFindingKinds() []FindingKind {
	return []FindingKind{
		KindEndpoint,
		KindURLLiteral,
		KindCredential,
		KindInternalDomain,
		KindComment,
	}
}

// Location describes where a finding was found. Offset and EndOffset are
// byte offsets into the (decoded) source, which makes them reliable even
// for minified single-line files where line/column are less useful.
// Line and Column are 1-based. Context is a short source snippet.
type Location struct {
	Offset    int    `json:"offset"`
	EndOffset int    `json:"endOffset"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	Context   string `json:"context"`
}

// A Finding is a single typed extraction result. When duplicate values
// are merged, Count holds the number of occurrences and Location the
// position of the first one.
type Finding struct {
	Kind     FindingKind `json:"kind"`
	Value    string      `json:"value"`
	Detail   string      `json:"detail,omitempty"`
	Location Location    `json:"location"`
	Count    int         `json:"count"`

	// sensitive strings that must be masked in any output derived
	// from this finding (the value itself plus any sibling values
	// captured as context). Never serialized.
	sensitive []string
}

// Report is the structured result of analyzing one JavaScript source.
// Findings always contains every kind, even when empty, so that "no
// hits" is distinguishable from "not scanned".
type Report struct {
	Source     string                    `json:"source"`
	Encoding   string                    `json:"encoding,omitempty"`
	Findings   map[FindingKind][]Finding `json:"findings"`
	Counts     map[FindingKind]int       `json:"counts"`
	Warnings   []string                  `json:"warnings,omitempty"`
	Skipped    bool                      `json:"skipped"`
	SkipReason string                    `json:"skipReason,omitempty"`
}

// NewReport returns a Report with every finding kind initialized to an
// empty (non-nil) slice and zero count.
func NewReport(source string) *Report {
	r := &Report{
		Source:   source,
		Findings: make(map[FindingKind][]Finding),
		Counts:   make(map[FindingKind]int),
	}
	for _, k := range AllFindingKinds() {
		r.Findings[k] = []Finding{}
		r.Counts[k] = 0
	}
	return r
}

// SkippedReport returns a Report for a source that could not be
// analyzed, with the reason recorded.
func SkippedReport(source, reason string) *Report {
	r := NewReport(source)
	r.Skipped = true
	r.SkipReason = reason
	return r
}

// ClassifyURL is the single rule that decides which finding kind a URL
// match belongs to: URLs with usage context (fetch, XHR, location
// assignments, ...) are endpoints; bare string literals are URL literals.
func ClassifyURL(u *URL) FindingKind {
	if u.Type == "stringLiteral" {
		return KindURLLiteral
	}
	return KindEndpoint
}

// internalSuffixes are domain suffixes considered internal.
var internalSuffixes = []string{
	".local", ".lan", ".internal", ".corp",
	".intranet", ".home", ".localdomain",
}

// IsInternalDomain is the single rule that decides whether a hostname
// looks internal: loopback/private/link-local IPs, localhost, known
// internal suffixes, or a bare hostname with no dots.
func IsInternalDomain(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}

	if host == "localhost" {
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}

	for _, suffix := range internalSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	// a bare hostname like "fileserver" or "jenkins01"
	return !strings.Contains(host, ".")
}

// maskReplacement is the string sensitive data is replaced with.
const maskReplacement = "****"

// MaskSensitive is the single masking rule used for all output paths.
// Short values are fully masked; longer values keep a small prefix and
// suffix so that values can still be correlated by a human.
func MaskSensitive(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return maskReplacement
	}
	return s[:4] + maskReplacement + s[len(s)-2:]
}

// HasSyntaxError returns true if the parsed source contains syntax
// errors. Tree-sitter is error-tolerant, so a file with errors may still
// yield partial results; callers decide whether to use them.
func (a *Analyzer) HasSyntaxError() bool {
	return a.rootNode != nil &&
		a.rootNode.IsValid() &&
		a.rootNode.node.HasError()
}

// ExtractFindings runs all extractors (URLs, secrets, comments) over the
// analyzed source and returns raw, unaggregated findings: one per
// occurrence, unmasked, with position information but no context
// snippet. Snippets are produced later by AggregateFindings, which owns
// the masking decision. Any non-fatal problems are returned as warnings.
func (a *Analyzer) ExtractFindings() ([]Finding, []string) {
	findings := make([]Finding, 0)
	warnings := make([]string, 0)

	if a.rootNode == nil || !a.rootNode.IsValid() {
		return findings, append(warnings, "input could not be parsed")
	}

	if a.HasSyntaxError() {
		warnings = append(warnings, "syntax errors detected; results may be partial")
	}

	// URLs: endpoints, URL literals and internal domains
	for _, u := range a.GetURLs() {
		loc := nodeLocation(u.node)

		detail := u.Type
		if u.Method != "" {
			detail = u.Method + " " + u.Type
		}

		findings = append(findings, Finding{
			Kind:     ClassifyURL(u),
			Value:    u.URL,
			Detail:   detail,
			Location: loc,
			Count:    1,
		})

		if parsed, err := url.Parse(u.URL); err == nil {
			if host := parsed.Hostname(); IsInternalDomain(host) {
				findings = append(findings, Finding{
					Kind:     KindInternalDomain,
					Value:    host,
					Detail:   "seen in " + u.Type,
					Location: loc,
					Count:    1,
				})
			}
		}
	}

	// Secrets
	for _, s := range a.GetSecrets() {
		detail := s.Kind
		if s.Severity != "" {
			detail = fmt.Sprintf("%s (%s)", s.Kind, s.Severity)
		}

		findings = append(findings, Finding{
			Kind:      KindCredential,
			Value:     secretValue(s),
			Detail:    detail,
			Location:  nodeLocation(s.node),
			Count:     1,
			sensitive: sensitiveStrings(s),
		})
	}

	// Comments
	a.Query("(comment) @matches", func(n *Node) {
		value := strings.TrimSpace(n.Content())
		value = strings.TrimPrefix(value, "//")
		value = strings.TrimPrefix(value, "/*")
		value = strings.TrimSuffix(value, "*/")
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}

		findings = append(findings, Finding{
			Kind:     KindComment,
			Value:    value,
			Location: nodeLocation(n),
			Count:    1,
		})
	})

	return findings, warnings
}

// AggregateOptions controls how raw findings are aggregated into a Report.
type AggregateOptions struct {
	// Mask redacts sensitive values and their context snippets.
	Mask bool

	// Kinds limits the report to the given kinds. Nil means all kinds.
	Kinds map[FindingKind]bool
}

// AggregateFindings merges duplicate findings (keeping the occurrence
// count and first position), attaches context snippets, applies masking
// if requested, and organizes everything into a Report. The decoded
// source is required to build context snippets; offsets in the report
// refer to it.
func AggregateFindings(source []byte, sourceName string, findings []Finding, warnings []string, opts AggregateOptions) *Report {
	report := NewReport(sourceName)
	report.Warnings = warnings

	// Every sensitive string found anywhere in the source is masked in
	// every context snippet, so a secret cannot leak through a window
	// around a neighbouring, non-sensitive finding.
	maskList := make([]string, 0)
	for _, f := range findings {
		maskList = append(maskList, f.sensitive...)
	}

	type key struct {
		kind  FindingKind
		value string
	}
	merged := make(map[key]int) // key -> index into ordered
	ordered := make([]Finding, 0, len(findings))

	// Multiple matchers can fire on the same node (e.g. the fetch
	// matcher and the generic call matcher), producing identical
	// findings at the same offset. Count each distinct source
	// location only once so Count reflects occurrences in the file.
	type occurrence struct {
		kind   FindingKind
		value  string
		offset int
	}
	seenOccurrence := make(map[occurrence]bool)

	for _, f := range findings {
		if opts.Kinds != nil && !opts.Kinds[f.Kind] {
			continue
		}

		occ := occurrence{f.Kind, f.Value, f.Location.Offset}
		if seenOccurrence[occ] {
			continue
		}
		seenOccurrence[occ] = true

		k := key{f.Kind, f.Value}
		if idx, exists := merged[k]; exists {
			ordered[idx].Count++
			continue
		}
		merged[k] = len(ordered)
		ordered = append(ordered, f)
	}

	for _, f := range ordered {
		f.Location.Context = contextFor(source, f, opts.Mask, maskList)

		if opts.Mask && f.Kind == KindCredential {
			f.Value = MaskSensitive(f.Value)
		}
		f.sensitive = nil

		report.Findings[f.Kind] = append(report.Findings[f.Kind], f)
		report.Counts[f.Kind]++
	}

	// deterministic ordering within each kind: by first offset
	for _, list := range report.Findings {
		sort.SliceStable(list, func(i, j int) bool {
			return list[i].Location.Offset < list[j].Location.Offset
		})
	}

	return report
}

// contextRadius is the number of bytes of source shown on each side of
// a non-sensitive finding in context snippets.
const contextRadius = 60

// maxContextLen bounds the length of any context snippet.
const maxContextLen = 160

// contextFor builds the context snippet for a finding. For credentials
// with masking enabled the snippet is built from the finding's own node
// only (never the surrounding source) with every sensitive string
// replaced, so a secret can never leak through a snippet window. All
// other snippets have every known sensitive string masked out too.
func contextFor(source []byte, f Finding, mask bool, maskList []string) string {
	loc := f.Location
	if loc.Offset < 0 || loc.Offset > len(source) ||
		loc.EndOffset < loc.Offset || loc.EndOffset > len(source) {
		return ""
	}

	if f.Kind == KindCredential && mask {
		snippet := string(source[loc.Offset:loc.EndOffset])
		for _, s := range maskList {
			snippet = strings.ReplaceAll(snippet, s, MaskSensitive(s))
		}
		return truncate(snippet, maxContextLen)
	}

	lo := loc.Offset - contextRadius
	if lo < 0 {
		lo = 0
	}
	hi := loc.Offset + contextRadius
	if hi > len(source) {
		hi = len(source)
	}

	snippet := string(source[lo:hi])
	if mask {
		for _, s := range maskList {
			snippet = strings.ReplaceAll(snippet, s, MaskSensitive(s))
		}
	}
	if lo > 0 {
		snippet = "…" + snippet
	}
	if hi < len(source) {
		snippet += "…"
	}
	return truncate(snippet, maxContextLen+2)
}

// truncate shortens a string to at most n bytes, appending an ellipsis
// if anything was removed. It avoids splitting multi-byte runes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.ValidString(s[:n]) {
		n--
	}
	return s[:n] + "…"
}

// nodeLocation derives a Location (without context snippet) from a Node.
func nodeLocation(n *Node) Location {
	if n == nil || !n.IsValid() {
		return Location{Offset: -1, EndOffset: -1}
	}
	point := n.node.StartPoint()
	return Location{
		Offset:    int(n.node.StartByte()),
		EndOffset: int(n.node.EndByte()),
		Line:      int(point.Row) + 1,
		Column:    int(point.Column) + 1,
	}
}

// secretValue renders the most useful single string for a Secret: the
// key itself when the data is a map containing one, otherwise compact
// JSON of the data.
func secretValue(s *Secret) string {
	if data, ok := s.Data.(map[string]string); ok {
		if key, exists := data["key"]; exists {
			return key
		}
	}
	j, err := json.Marshal(s.Data)
	if err != nil {
		return fmt.Sprintf("%v", s.Data)
	}
	return string(j)
}

// sensitiveStrings collects every string in a Secret's data and context
// that is long enough to be worth masking.
func sensitiveStrings(s *Secret) []string {
	out := make([]string, 0)

	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if len(t) >= 8 {
				out = append(out, t)
			}
		case map[string]string:
			for _, val := range t {
				walk(val)
			}
		case map[string]any:
			for _, val := range t {
				walk(val)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		}
	}

	walk(s.Data)
	walk(s.Context)
	return out
}

// DecodeSource validates and, where possible, decodes source code into
// UTF-8. It returns the decoded source and the detected encoding name.
// UTF-8 (with or without BOM) and UTF-16 LE/BE (with BOM) are
// recognized; anything else that is not valid UTF-8 results in an error
// so the caller can skip the file and record why.
func DecodeSource(source []byte) ([]byte, string, error) {
	switch {
	case len(source) >= 3 && source[0] == 0xEF && source[1] == 0xBB && source[2] == 0xBF:
		return source[3:], "utf-8-sig", nil

	case len(source) >= 2 && source[0] == 0xFF && source[1] == 0xFE:
		return decodeUTF16(source[2:], binary.LittleEndian), "utf-16le", nil

	case len(source) >= 2 && source[0] == 0xFE && source[1] == 0xFF:
		return decodeUTF16(source[2:], binary.BigEndian), "utf-16be", nil
	}

	if !utf8.Valid(source) {
		return nil, "", fmt.Errorf("undetected non-UTF-8 encoding")
	}

	return source, "utf-8", nil
}

// decodeUTF16 converts UTF-16 encoded bytes to UTF-8.
func decodeUTF16(b []byte, bo binary.ByteOrder) []byte {
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, bo.Uint16(b[i:]))
	}
	return []byte(string(utf16.Decode(u16)))
}
