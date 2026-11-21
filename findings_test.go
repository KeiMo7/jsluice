package jsluice

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
)

// find returns all findings of a given kind from a report
func find(report *Report, kind FindingKind) []Finding {
	return report.Findings[kind]
}

func analyzeAndAggregate(t *testing.T, source string, mask bool) *Report {
	t.Helper()
	analyzer := NewAnalyzer([]byte(source))
	findings, warnings := analyzer.ExtractFindings()
	return AggregateFindings([]byte(source), "test.js", findings, warnings, AggregateOptions{Mask: mask})
}

// Mixed source: an endpoint, a URL literal, a credential, an internal
// domain and a comment should each land in their own category.
func TestExtractFindingsMixedTypes(t *testing.T) {
	source := `
// TODO: rotate this key before launch
fetch("https://api.example.com/v1/users", {method: "GET"});
const logo = "https://cdn.example.com/logo.png";
const key = "AKIAIOSFODNN7EXAMPLE";
const hr = "http://intranet.corp.local/hr";
`
	report := analyzeAndAggregate(t, source, true)

	endpoints := find(report, KindEndpoint)
	if len(endpoints) == 0 {
		t.Fatal("expected at least one endpoint finding")
	}
	foundEndpoint := false
	for _, f := range endpoints {
		if f.Value == "https://api.example.com/v1/users" {
			foundEndpoint = true
		}
	}
	if !foundEndpoint {
		t.Errorf("expected endpoint https://api.example.com/v1/users, got %+v", endpoints)
	}

	literals := find(report, KindURLLiteral)
	foundLiteral := false
	for _, f := range literals {
		if f.Value == "https://cdn.example.com/logo.png" {
			foundLiteral = true
		}
	}
	if !foundLiteral {
		t.Errorf("expected URL literal https://cdn.example.com/logo.png, got %+v", literals)
	}

	creds := find(report, KindCredential)
	if len(creds) != 1 {
		t.Fatalf("expected exactly one credential, got %+v", creds)
	}

	domains := find(report, KindInternalDomain)
	if len(domains) != 1 || domains[0].Value != "intranet.corp.local" {
		t.Errorf("expected internal domain intranet.corp.local, got %+v", domains)
	}

	comments := find(report, KindComment)
	if len(comments) != 1 || !strings.Contains(comments[0].Value, "rotate this key") {
		t.Errorf("expected comment finding, got %+v", comments)
	}
}

// The same value extracted multiple times must be merged into one
// finding with the correct count and the position of the first hit.
func TestAggregateFindingsMergesDuplicates(t *testing.T) {
	source := `fetch("/api/health");
fetch("/api/health");
fetch("/api/health");`

	report := analyzeAndAggregate(t, source, true)

	endpoints := find(report, KindEndpoint)
	if len(endpoints) != 1 {
		t.Fatalf("expected duplicates to merge into one endpoint, got %+v", endpoints)
	}
	if endpoints[0].Count != 3 {
		t.Errorf("expected count 3 for merged endpoint, got %d", endpoints[0].Count)
	}

	firstOffset := strings.Index(source, `fetch(`)
	if endpoints[0].Location.Offset != firstOffset {
		t.Errorf("expected first occurrence at offset %d, got %d", firstOffset, endpoints[0].Location.Offset)
	}

	// the URL literal matcher sees the same string three times too
	literals := find(report, KindURLLiteral)
	if len(literals) != 1 || literals[0].Count != 3 {
		t.Errorf("expected one urlLiteral finding with count 3, got %+v", literals)
	}
}

// Positions must map back into a huge single-line (minified) file.
func TestLocationInMinifiedSource(t *testing.T) {
	padding := strings.Repeat("var a=1;", 20000) // 160000 bytes, one line
	needle := `fetch("/api/health");`
	source := padding + needle + padding

	report := analyzeAndAggregate(t, source, true)

	endpoints := find(report, KindEndpoint)
	if len(endpoints) != 1 {
		t.Fatalf("expected one endpoint, got %+v", endpoints)
	}

	loc := endpoints[0].Location
	wantOffset := len(padding)
	if loc.Offset != wantOffset {
		t.Errorf("expected offset %d, got %d", wantOffset, loc.Offset)
	}
	if loc.Line != 1 {
		t.Errorf("expected line 1 for single-line source, got %d", loc.Line)
	}
	if loc.Column != wantOffset+1 {
		t.Errorf("expected column %d, got %d", wantOffset+1, loc.Column)
	}
	if len(loc.Context) > maxContextLen+3 {
		t.Errorf("context snippet not bounded for minified input: %d bytes", len(loc.Context))
	}
	if !strings.Contains(loc.Context, "fetch(") {
		t.Errorf("context snippet should contain the match, got %q", loc.Context)
	}
}

// Non-UTF-8 input: UTF-16 with BOM is decoded and labelled; undetectable
// encodings produce an error so the caller can skip and count the file.
func TestDecodeSourceEncodings(t *testing.T) {
	js := `fetch("/api/health");`

	// UTF-16LE with BOM
	u16 := utf16.Encode([]rune(js))
	le := []byte{0xFF, 0xFE}
	for _, u := range u16 {
		le = append(le, byte(u), byte(u>>8))
	}
	decoded, encoding, err := DecodeSource(le)
	if err != nil {
		t.Fatalf("expected UTF-16LE to decode, got error: %s", err)
	}
	if encoding != "utf-16le" {
		t.Errorf("expected encoding utf-16le, got %s", encoding)
	}
	if string(decoded) != js {
		t.Errorf("expected decoded source %q, got %q", js, decoded)
	}

	// UTF-16BE with BOM
	be := []byte{0xFE, 0xFF}
	for _, u := range u16 {
		be = append(be, byte(u>>8), byte(u))
	}
	decoded, encoding, err = DecodeSource(be)
	if err != nil || encoding != "utf-16be" || string(decoded) != js {
		t.Errorf("UTF-16BE decode failed: %q %s %v", decoded, encoding, err)
	}

	// plain UTF-8
	if _, encoding, err = DecodeSource([]byte(js)); err != nil || encoding != "utf-8" {
		t.Errorf("UTF-8 decode failed: %s %v", encoding, err)
	}

	// undetectable garbage
	if _, _, err = DecodeSource([]byte{0x80, 0x81, 0x82, 0x83}); err == nil {
		t.Error("expected error for undetectable encoding, got nil")
	}
}

// Sensitive values are masked by default and only shown in full when
// masking is explicitly disabled.
func TestCredentialsMaskedByDefault(t *testing.T) {
	key := "AKIAIOSFODNN7EXAMPLE"
	source := `const key = "` + key + `";`

	masked := analyzeAndAggregate(t, source, true)
	creds := find(masked, KindCredential)
	if len(creds) != 1 {
		t.Fatalf("expected one credential, got %+v", creds)
	}
	if creds[0].Value == key {
		t.Error("expected credential value to be masked by default")
	}
	if !strings.Contains(creds[0].Value, maskReplacement) {
		t.Errorf("expected masked value to contain %q, got %q", maskReplacement, creds[0].Value)
	}
	if strings.Contains(creds[0].Location.Context, key) {
		t.Errorf("expected context snippet to be masked, got %q", creds[0].Location.Context)
	}

	unmasked := analyzeAndAggregate(t, source, false)
	creds = find(unmasked, KindCredential)
	if len(creds) != 1 || creds[0].Value != key {
		t.Errorf("expected full credential value with masking disabled, got %+v", creds)
	}
}

// A secret must not leak through the context window of a neighbouring,
// non-credential finding either.
func TestSecretNotLeakedViaNeighbourContext(t *testing.T) {
	key := "AKIAIOSFODNN7EXAMPLE"
	source := `const key = "` + key + `"; fetch("/api/health");`

	report := analyzeAndAggregate(t, source, true)
	for _, kind := range AllFindingKinds() {
		for _, f := range find(report, kind) {
			if strings.Contains(f.Location.Context, key) {
				t.Errorf("secret leaked via %s finding context: %q", kind, f.Location.Context)
			}
		}
	}
}

// Every category must be present in the report even when it has no hits.
func TestEmptyCategoriesAreExplicit(t *testing.T) {
	report := analyzeAndAggregate(t, `var x = 1;`, true)

	for _, kind := range AllFindingKinds() {
		list, exists := report.Findings[kind]
		if !exists {
			t.Errorf("kind %s missing from report", kind)
			continue
		}
		if list == nil {
			t.Errorf("kind %s has nil slice; want empty non-nil slice", kind)
		}
		if report.Counts[kind] != 0 {
			t.Errorf("expected zero count for kind %s, got %d", kind, report.Counts[kind])
		}
	}

	j, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(j), `"comment":[]`) {
		t.Errorf("expected empty comment category to be explicit in JSON, got %s", j)
	}
}

// Kind filtering limits the report but keeps the remaining categories
// explicit.
func TestAggregateKindFilter(t *testing.T) {
	source := `fetch("https://api.example.com/v1/users");
const key = "AKIAIOSFODNN7EXAMPLE";`

	analyzer := NewAnalyzer([]byte(source))
	findings, warnings := analyzer.ExtractFindings()
	report := AggregateFindings([]byte(source), "test.js", findings, warnings, AggregateOptions{
		Mask:  true,
		Kinds: map[FindingKind]bool{KindEndpoint: true},
	})

	if len(find(report, KindEndpoint)) == 0 {
		t.Error("expected endpoint findings to survive filtering")
	}
	if len(find(report, KindCredential)) != 0 {
		t.Error("expected credentials to be filtered out")
	}
	if _, exists := report.Findings[KindCredential]; !exists {
		t.Error("filtered-out kinds should still be present (empty) in the report")
	}
}

// IsInternalDomain classification
func TestIsInternalDomain(t *testing.T) {
	internal := []string{
		"localhost", "intranet.corp.local", "jenkins01",
		"10.0.0.4", "192.168.1.10", "172.16.0.3", "127.0.0.1",
		"db.internal", "files.corp",
	}
	for _, h := range internal {
		if !IsInternalDomain(h) {
			t.Errorf("expected %s to be classified internal", h)
		}
	}

	external := []string{"example.com", "api.github.com", "8.8.8.8", "cdn.example.org"}
	for _, h := range external {
		if IsInternalDomain(h) {
			t.Errorf("expected %s to be classified external", h)
		}
	}
}
