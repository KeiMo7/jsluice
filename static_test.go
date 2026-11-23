package jsluice

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// evalFirst parses src, runs the query and returns the static value of the
// first captured node whose source contains wantSubstr (or the first match when
// wantSubstr is empty). When several nodes match, the shortest source wins,
// which selects the innermost node rather than an enclosing call expression.
func evalFirst(t *testing.T, src, query, wantSubstr string) StaticValue {
	t.Helper()
	a := NewAnalyzer([]byte(src))
	var best *Node
	a.Query(query, func(n *Node) {
		if wantSubstr != "" && !strings.Contains(n.Content(), wantSubstr) {
			return
		}
		if best == nil || len(n.Content()) < len(best.Content()) {
			best = n
		}
	})
	if best == nil {
		t.Fatalf("query %q matched nothing in %s", query, src)
	}
	return a.EvalStatic(best)
}

func TestStaticEvalFiveRequiredForms(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		query    string
		expected string
	}{
		{
			name:     "1_literal_plus_literal",
			src:      `fetch("https://a.example.com" + "/v1/users")`,
			query:    `(binary_expression) @x`,
			expected: "https://a.example.com/v1/users",
		},
		{
			name:     "2_constant_plus_literal",
			src:      `const HOST = "https://api.example.com"; fetch(HOST + "/v1/users")`,
			query:    `(binary_expression) @x`,
			expected: "https://api.example.com/v1/users",
		},
		{
			name:     "3_template_string",
			src:      "const P = \"/v2\"; fetch(`${P}/users`)",
			query:    `(template_string) @x`,
			expected: "/v2/users",
		},
		{
			name:     "4_array_join",
			src:      `fetch(["https://a.example.com", "path", "x"].join("/"))`,
			query:    `(call_expression) @x`,
			expected: "https://a.example.com/path/x",
		},
		{
			name:     "5_object_property",
			src:      `const cfg = {base: "https://o.example.com"}; fetch(cfg.base + "/q")`,
			query:    `(binary_expression) @x`,
			expected: "https://o.example.com/q",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := evalFirst(t, c.src, c.query, "")
			if got := v.String(); got != c.expected {
				t.Errorf("want %q, have %q (unknown=%v)", c.expected, got, v.Unknown)
			}
			if !v.FullyKnown() {
				t.Errorf("expected fully-known value, got unknown=%v truncated=%v parts=%d",
					v.Unknown, v.Truncated, len(v.Parts))
			}
		})
	}
}

func TestStaticEvalAllForms(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		query    string
		match    string
		expected []string
		known    bool
	}{
		{"destructuring",
			`const {base} = {base: "https://d.example.com"}; fetch(base + "/r")`,
			`(binary_expression) @x`, "", []string{"https://d.example.com/r"}, true},
		{"destructure_renamed",
			`const {base: b, port: p} = {base: "https://rn.example.com", port: "8443"}; fetch(b + ":" + p)`,
			`(binary_expression) @x`, `+ p`, []string{"https://rn.example.com:8443"}, true},
		{"reassignment_uses_latest",
			`let u = "https://r1.example.com"; u = "https://r2.example.com"; fetch(u + "/z")`,
			`(binary_expression) @x`, "", []string{"https://r2.example.com/z"}, true},
		{"reassignment_before_reference",
			`let u = "https://r1.example.com"; fetch(u + "/z"); u = "https://r2.example.com"`,
			`(binary_expression) @x`, "", []string{"https://r1.example.com/z"}, true},
		{"augmented_assignment",
			`let u = "https://aug.example.com"; u += "/a"; fetch(u + "/b")`,
			`(binary_expression) @x`, "", []string{"https://aug.example.com/a/b"}, true},
		{"property_mutation",
			`const c = {base: "https://pm.example.com"}; c.base = "https://pm2.example.com"; fetch(c.base + "/x")`,
			`(binary_expression) @x`, "", []string{"https://pm2.example.com/x"}, true},
		{"imported_unknown",
			`import {API} from './config.js'; fetch(API + "/imported")`,
			`(binary_expression) @x`, "", []string{ExpressionPlaceholder + "/imported"}, false},
		{"conditional_distinct_branches",
			`const t = cond ? "https://c1.example.com" : "https://c2.example.com"; fetch(t + "/c")`,
			`(binary_expression) @x`, "",
			[]string{"https://c1.example.com/c", "https://c2.example.com/c"}, false},
		{"conditional_identical_branches",
			`const t = cond ? "https://same.example.com" : "https://same.example.com"; fetch(t + "/e")`,
			`(binary_expression) @x`, "", []string{"https://same.example.com/e"}, true},
		{"conditional_assignment",
			`let t = "https://def.example.com"; if (c) { t = "https://if.example.com" } fetch(t + "/c")`,
			`(binary_expression) @x`, "",
			[]string{"https://def.example.com/c", "https://if.example.com/c"}, false},
		{"runtime_input_placeholder",
			`fetch("https://u.example.com/" + window.location.pathname)`,
			`(binary_expression) @x`, "", []string{"https://u.example.com/" + ExpressionPlaceholder}, false},
		{"encoded_literal_preserved",
			`const s = "https://e.example.com/a%2Fb"; fetch(s + "?x=1")`,
			`(binary_expression) @x`, "", []string{"https://e.example.com/a%2Fb?x=1"}, true},
		{"decoded_fragment",
			`const d = decodeURIComponent("https://x.example.com/%2Fok"); fetch(d + "/end")`,
			`(binary_expression) @x`, "", []string{"https://x.example.com//ok/end"}, true},
		{"encoded_fragment",
			`const e = encodeURIComponent("a b"); fetch("/q?x=" + e)`,
			`(binary_expression) @x`, "", []string{"/q?x=a%20b"}, true},
		{"escaped_fragment",
			`const v = "a\x3db"; fetch(v + "&c")`,
			`(binary_expression) @x`, "", []string{"a=b&c"}, true},
		{"computed_object_key",
			"const K = \"url\"; const o = {[K]: \"https://k.example.com/p\"}; fetch(o[K] + \"/k\")",
			`(binary_expression) @x`, "", []string{"https://k.example.com/p/k"}, true},
		{"computed_key_in_object_key",
			`const K = "base"; const o = {[K]: "https://ck.example.com"}; fetch(o.base + "/k")`,
			`(binary_expression) @x`, "", []string{"https://ck.example.com/k"}, true},
		{"subscript_string_key",
			`const c = {base: "https://s.example.com"}; fetch(c["base"] + "/w")`,
			`(binary_expression) @x`, "", []string{"https://s.example.com/w"}, true},
		{"nested_member",
			`const c = {a:{b:"https://n.example.com/n"}}; fetch(c.a.b + "/i")`,
			`(binary_expression) @x`, "", []string{"https://n.example.com/n/i"}, true},
		{"variable_held_array_join",
			`const parts = ["https://j.example.com","j1","j2"]; fetch(parts.join("/"))`,
			`(call_expression) @x`, `parts.join("/")`, []string{"https://j.example.com/j1/j2"}, true},
		{"array_join_with_unknown_element",
			`const parts = ["https://j.example.com", runtime, "j2"]; fetch(parts.join("/"))`,
			`(call_expression) @x`, `parts.join("/")`,
			[]string{"https://j.example.com/" + ExpressionPlaceholder + "/j2"}, false},
		{"template_multiple",
			"const A = \"https://t.example.com\"; const B = \"v1\"; fetch(`${A}/${B}/x`)",
			`(template_string) @x`, "", []string{"https://t.example.com/v1/x"}, true},
		{"template_unknown_sub",
			"const A = \"https://t2.example.com\"; fetch(`${A}/${runtime}`)",
			`(template_string) @x`, "", []string{"https://t2.example.com/" + ExpressionPlaceholder}, false},
		{"template_escapes",
			"const A = \"x\"; fetch(`a\\nb${A}\\tc`)",
			`(template_string) @x`, "", []string{"a\nbx\tc"}, true},
		{"parenthesized",
			`fetch(("https://pa.example.com") + "/g")`,
			`(binary_expression) @x`, "", []string{"https://pa.example.com/g"}, true},
		{"number_concatenation",
			`const n = "/v"; fetch(n + 2)`,
			`(binary_expression) @x`, "", []string{"/v2"}, true},
		{"numeric_addition_not_string",
			`fetch(1 + 2)`,
			`(call_expression) @x`, "", []string{ExpressionPlaceholder}, false},
		{"function_parameter_unknown",
			`function f(p){ return fetch(p + "/b") }`,
			`(binary_expression) @x`, "", []string{ExpressionPlaceholder + "/b"}, false},
		{"function_call_not_evaluated",
			`fetch(buildUrl() + "/after")`,
			`(binary_expression) @x`, "", []string{ExpressionPlaceholder + "/after"}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := evalFirst(t, c.src, c.query, c.match)
			got := v.AllStrings()
			if strings.Join(got, "|") != strings.Join(c.expected, "|") {
				t.Errorf("want %v, have %v", c.expected, got)
			}
			if c.known && !v.FullyKnown() {
				t.Errorf("expected fully-known result; got unknown=%v truncated=%v", v.Unknown, v.Truncated)
			}
			if !c.known && v.FullyKnown() {
				t.Errorf("expected a placeholder, but value is fully known: %v", v.AllStrings())
			}
		})
	}
}

func TestStaticEvalCrossFileImport(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, body string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	writeFile("config.js", `export const API_BASE = "https://internal.example.com";`+"\n"+
		`export const VERSION = "v2";`+"\n")
	writeFile("common.js", `module.exports = {REGION: "eu-west-1"};`)
	main := writeFile("main.js", `
import { API_BASE, VERSION } from "./config.js";
const { REGION } = require("./common.js");
function go() {
  fetch(API_BASE + "/api/" + VERSION + "/orders");
  fetch("https://" + REGION + ".example.com/ping");
}
`)

	a := NewAnalyzer([]byte(mustRead(t, main)))
	a.SetFilename(main)
	res := NewModuleResolver()
	defer res.Close()
	a.SetModuleResolver(res)

	got := map[string]bool{}
	for _, u := range a.GetURLs() {
		if u.Type == "fetch" {
			got[u.URL] = true
		}
	}
	for _, want := range []string{
		"https://internal.example.com/api/v2/orders",
		"https://eu-west-1.example.com/ping",
	} {
		if !got[want] {
			t.Errorf("missing reconstructed URL %q; got %v", want, keysOf(got))
		}
	}
	for u := range got {
		if strings.Contains(u, ExpressionPlaceholder) {
			t.Errorf("expected no placeholders, got %q", u)
		}
	}
}

func TestStaticEvalCrossFileMissingStaysPlaceholder(t *testing.T) {
	dir := t.TempDir()
	main := dir + "/main.js"
	if err := os.WriteFile(main, []byte(`import { X } from "./nope.js"; fetch(X + "/y")`), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewAnalyzer([]byte(mustRead(t, main)))
	a.SetFilename(main)
	res := NewModuleResolver()
	defer res.Close()
	a.SetModuleResolver(res)

	for _, u := range a.GetURLs() {
		if u.Type == "fetch" && u.URL != ExpressionPlaceholder+"/y" {
			t.Errorf("want placeholder for missing module, got %q", u.URL)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestStaticEvalProvenance(t *testing.T) {
	src := `const HOST = "https://api.example.com"; fetch(HOST + "/v1/users")`
	v := evalFirst(t, src, `(binary_expression) @x`, "")

	if len(v.Parts) < 2 {
		t.Fatalf("want at least 2 traceable parts, got %d", len(v.Parts))
	}
	for _, p := range v.Parts {
		if p.IsPlaceholder() {
			continue
		}
		if p.StartByte >= p.EndByte || int(p.EndByte) > len(src) {
			t.Errorf("part %q has invalid byte range %d-%d", p.Value, p.StartByte, p.EndByte)
			continue
		}
		if p.Source == "" {
			t.Errorf("part %q carries no original source fragment", p.Value)
		}
		// The reported byte range must locate the fragment's original source.
		snippet := src[p.StartByte:p.EndByte]
		if !strings.Contains(snippet, p.Source) && !strings.Contains(p.Source, snippet) {
			t.Errorf("byte range %d-%d gives %q, which does not match source %q",
				p.StartByte, p.EndByte, snippet, p.Source)
		}
	}
}

func TestStaticEvalCycleDetection(t *testing.T) {
	src := `var x = x; fetch(x + "/loop")`
	v := evalFirst(t, src, `(binary_expression) @x`, "")
	if !v.Truncated {
		t.Errorf("expected Truncated on circular reference; got %+v", v)
	}
	if v.TruncationReason == "" {
		t.Errorf("expected a truncation reason")
	}
	if !strings.Contains(v.String(), ExpressionPlaceholder) {
		t.Errorf("expected placeholder in truncated result, got %q", v.String())
	}
}

func TestStaticEvalDepthBudget(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`fetch(`)
	for i := 0; i < maxEvalDepth*2; i++ {
		sb.WriteString(`(`)
	}
	sb.WriteString(`"https://deep.example.com"`)
	for i := 0; i < maxEvalDepth*2; i++ {
		sb.WriteString(`)`)
	}
	sb.WriteString(`)`)

	a := NewAnalyzer([]byte(sb.String()))
	call := a.RootNode().NamedChild(0).NamedChild(0)
	outer := call.ChildByFieldName("arguments").NamedChild(0)
	v := a.EvalStatic(outer)
	if !v.Truncated {
		t.Errorf("expected truncation beyond depth budget; got parts=%d unknown=%v", len(v.Parts), v.Unknown)
	}
}

func TestStaticEvalOversize(t *testing.T) {
	big := strings.Repeat("a", maxStaticValueLength+10)
	src := `const HUGE = "` + big + `"; fetch(HUGE)`
	a := NewAnalyzer([]byte(src))
	var v StaticValue
	a.Query(`(identifier) @x`, func(n *Node) {
		if n.Content() == "HUGE" {
			v = a.EvalStatic(n)
		}
	})
	if !v.Oversize {
		t.Errorf("expected oversize value to be discarded; got oversize=%v len=%d", v.Oversize, len(v.String()))
	}
	if a.OversizeCount() < 1 {
		t.Errorf("expected oversize counter >= 1, got %d", a.OversizeCount())
	}
}

func TestStaticEvalMemoizationConsistency(t *testing.T) {
	src := `const BASE = "https://m.example.com"; fetch(BASE + "/a"); fetch(BASE + "/b")`
	a := NewAnalyzer([]byte(src))
	var got []string
	a.Query(`(binary_expression) @x`, func(n *Node) {
		got = append(got, a.EvalStatic(n).String())
	})
	want := []string{"https://m.example.com/a", "https://m.example.com/b"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("want %v, have %v", want, got)
	}
}

func TestStaticEvalDeterministicAcrossRuns(t *testing.T) {
	src := `
		const H = "https://h.example.com";
		const arr = ["a", "b", "c"];
		fetch(H + "/x");
		fetch(arr.join("/"));
		const o = {k: "https://k.example.com"};
		fetch(o.k + "/y");
	`
	run := func() []string {
		a := NewAnalyzer([]byte(src))
		out := make([]string, 0)
		for _, u := range a.GetURLs() {
			out = append(out, u.Type+":"+u.URL+":"+strings.Join(u.QueryParams, ","))
		}
		return out
	}
	first := run()
	for i := 0; i < 5; i++ {
		again := run()
		if strings.Join(first, "|") != strings.Join(again, "|") {
			t.Fatalf("non-deterministic output:\nfirst=%v\nrun%d=%v", first, i, again)
		}
	}
}

func TestStaticEvalDoesNotExecuteOrFetch(t *testing.T) {
	src := `fetch(buildUrl() + "/after")`
	v := evalFirst(t, src, `(binary_expression) @x`, "")
	if v.FullyKnown() {
		t.Errorf("call expression must not be evaluated; got %q", v.String())
	}
	if want := ExpressionPlaceholder + "/after"; v.String() != want {
		t.Errorf("want %q, got %q", want, v.String())
	}
}

func TestStaticEvalURLRecoveryEndToEnd(t *testing.T) {
	src := `
		const API_BASE = "https://internal.example.com";
		function call() {
			fetch(API_BASE + "/api/v2/orders")
		}
	`
	a := NewAnalyzer([]byte(src))
	var found []string
	for _, u := range a.GetURLs() {
		if u.Type == "fetch" {
			found = append(found, u.URL)
		}
	}
	want := "https://internal.example.com/api/v2/orders"
	for _, f := range found {
		if f == want {
			return
		}
	}
	t.Fatalf("want fully reconstructed fetch URL %q, got %v", want, found)
}

func TestStaticEvalRuntimeInputNotFullURL(t *testing.T) {
	// A URL that is mostly runtime input must keep its placeholder and must
	// not be reported as if it were a complete address.
	src := `fetch(window.location.origin + "/api/" + userId)`
	a := NewAnalyzer([]byte(src))
	for _, u := range a.GetURLs() {
		if u.Type != "fetch" {
			continue
		}
		if !strings.Contains(u.URL, ExpressionPlaceholder) {
			t.Errorf("expected placeholder for runtime value, got %q", u.URL)
		}
	}
}

func TestStaticEvalUseBeforeDeclaration(t *testing.T) {
	// A reference before the declaration must not pick up the declared value.
	src := `fetch(BASE + "/early"); const BASE = "https://late.example.com";`
	v := evalFirst(t, src, `(binary_expression) @x`, "")
	if v.FullyKnown() {
		t.Errorf("reference before declaration must stay unknown; got %q", v.String())
	}
}

func TestStaticEvalImportedProvenance(t *testing.T) {
	dir := t.TempDir()
	cfg := dir + "/config.js"
	if err := os.WriteFile(cfg, []byte(`export const BASE = "https://prov.example.com";`), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `import { BASE } from "./config.js"; fetch(BASE + "/x")`
	a := NewAnalyzer([]byte(src))
	a.SetFilename(dir + "/main.js")
	res := NewModuleResolver()
	defer res.Close()
	a.SetModuleResolver(res)

	// Evaluate the binary expression directly to inspect provenance.
	var bin *Node
	a.Query(`(binary_expression) @x`, func(n *Node) { bin = n })
	if bin == nil {
		t.Fatal("no binary expression")
	}
	var imported *StaticPart
	v := a.EvalStatic(bin)
	for i := range v.Parts {
		if strings.Contains(v.Parts[i].Value, "prov.example.com") {
			imported = &v.Parts[i]
		}
	}
	if imported == nil {
		t.Fatal("imported fragment not found")
	}
	if imported.File == "" || !strings.HasSuffix(imported.File, "config.js") {
		t.Errorf("imported fragment should name the module it came from; got file=%q", imported.File)
	}
}

func TestStaticEvalObjectReassignment(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"reassigned_object",
			`let o = {a: "https://one.example.com"}; o = {a: "https://two.example.com"}; fetch(o.a + "/x")`,
			[]string{"https://two.example.com/x"}},
		{"property_after_reassignment",
			`let o = {a: "https://one.example.com"}; o = {}; o.a = "https://three.example.com"; fetch(o.a + "/x")`,
			[]string{"https://three.example.com/x"}},
		{"property_before_reassignment_lost",
			`let o = {a: "https://one.example.com"}; o.a = "https://tmp.example.com"; o = {a: "https://final.example.com"}; fetch(o.a + "/x")`,
			[]string{"https://final.example.com/x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := evalFirst(t, c.src, `(binary_expression) @x`, "")
			if strings.Join(v.AllStrings(), "|") != strings.Join(c.want, "|") {
				t.Errorf("want %v, have %v", c.want, v.AllStrings())
			}
		})
	}
}

func TestStaticEvalConditionalURLsEnumerated(t *testing.T) {
	// A URL whose base is chosen by a conditional must be reported for every
	// branch, not just the first.
	src := `const base = isProd ? "https://prod.example.com" : "https://stage.example.com"; fetch(base + "/api")`
	a := NewAnalyzer([]byte(src))
	got := map[string]bool{}
	for _, u := range a.GetURLs() {
		if u.Type == "fetch" {
			got[u.URL] = true
		}
	}
	for _, want := range []string{
		"https://prod.example.com/api",
		"https://stage.example.com/api",
	} {
		if !got[want] {
			t.Errorf("missing branch URL %q; got %v", want, keysOf(got))
		}
	}
}
