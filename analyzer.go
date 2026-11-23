package jsluice

import (
	"bytes"
	"sync"
	"unicode"

	"github.com/PuerkitoBio/goquery"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
)

// Analyzer could be considered the core type of jsluice. It wraps
// the parse tree for a JavaScript file and provides mechanisms to
// extract URLs, secrets etc
type Analyzer struct {
	urlMatchers        []URLMatcher
	rootNode           *Node
	userSecretMatchers []SecretMatcher

	// evaluator performs conservative static evaluation of expressions.
	// It is created lazily so analyses that never need it (tree printing,
	// queries) pay no construction cost.
	evaluatorOnce sync.Once
	evaluator     *staticEvaluator

	// resolver reads modules imported by this file. It is optional; when
	// unset, imported values stay unknown.
	resolver *ModuleResolver
	// filename is the path this source was read from, used to resolve
	// relative imports. Empty means unknown, disabling cross-file
	// resolution.
	filename string
}

// NewAnalyzer accepts a slice of bytes representing some JavaScript
// source code and returns a pointer to a new Analyzer
func NewAnalyzer(source []byte) *Analyzer {
	parser := sitter.NewParser()

	parser.SetLanguage(javascript.GetLanguage())

	if isProbablyHTML(source) {
		source = extractInlineJS(source)
	}

	tree := parser.Parse(nil, source)

	// TODO: Align how URLMatcher and SecretMatcher slices
	// are loaded. At the moment we load URLMatchers now,
	// and SecretMatchers only when GetSecrets is called.
	// This is mostly because URL matching was written first,
	// and then secret matching was added later.
	a := &Analyzer{
		urlMatchers: AllURLMatchers(),
		rootNode:    NewNode(tree.RootNode(), source),
	}
	// Every node derived from the root carries the analyzer so that
	// CollapsedString can use the shared static evaluator.
	a.rootNode = a.rootNode.withAnalyzer(a)
	return a
}

// SetFilename records the path the analyzed source came from. When set, the
// static evaluator may follow relative imports from this file to reconstruct
// values defined in other modules. This is read-only filesystem access; no
// script is executed and no network request is made.
func (a *Analyzer) SetFilename(path string) {
	a.filename = path
}

// SetModuleResolver supplies the resolver used to follow imports. Passing nil
// disables cross-file resolution (imported values become placeholders).
func (a *Analyzer) SetModuleResolver(r *ModuleResolver) {
	a.resolver = r
}

// static returns the Analyzer's lazily-initialized static evaluator.
func (a *Analyzer) static() *staticEvaluator {
	a.evaluatorOnce.Do(func() {
		a.evaluator = newStaticEvaluator(a.rootNode.node, a.rootNode.source, a.filename)
		a.evaluator.resolver = a.resolver
	})
	return a.evaluator
}

// EvalStatic conservatively evaluates a JavaScript expression without
// executing it. Statically-determinable fragments (literal concatenation,
// constants, templates, array joins, object properties and imported constants)
// are collapsed; anything that cannot be proven statically is left as an
// expression placeholder. The returned StaticValue keeps every source fragment
// and its byte range so results can be traced back to their origin.
func (a *Analyzer) EvalStatic(n *Node) StaticValue {
	if n == nil || !n.IsValid() {
		return StaticValue{Unknown: true}
	}
	return a.static().Eval(n.node)
}

// EvalStaticString is a convenience wrapper around EvalStatic that returns the
// rendered string, with unknown chunks replaced by ExpressionPlaceholder.
func (a *Analyzer) EvalStaticString(n *Node) string {
	return a.EvalStatic(n).String()
}

// OversizeCount reports how many evaluated values were discarded for exceeding
// the static value length budget.
func (a *Analyzer) OversizeCount() int {
	return a.static().OversizeCount()
}

// Query peforms a tree-sitter query on the JavaScript being analyzed.
// The provided function is called once for every node that captured by the query.
// See https://tree-sitter.github.io/tree-sitter/using-parsers#query-syntax
// for details on query syntax.
func (a *Analyzer) Query(q string, fn func(*Node)) {
	a.rootNode.Query(q, fn)
}

// Query peforms a tree-sitter query on the JavaScript being analyzed.
// The provided function is called for every query match, with captured nodes
// grouped into a QueryResult
// See https://tree-sitter.github.io/tree-sitter/using-parsers#query-syntax
// for details on query syntax.
func (a *Analyzer) QueryMulti(q string, fn func(QueryResult)) {
	a.rootNode.QueryMulti(q, fn)
}

// RootNode returns the root note of the parsed JavaScript
func (a *Analyzer) RootNode() *Node {
	return a.rootNode
}

// HasSyntaxError reports whether the parsed source contains syntax errors. The
// analyzer can still produce partial results for such input; callers that want
// to skip malformed files should check this first.
func (a *Analyzer) HasSyntaxError() bool {
	return a.rootNode != nil && a.rootNode.IsValid() && a.rootNode.node.HasError()
}

// isProbablyHTML returns true for source that is probably HTML.
// False positives are OK as long as the false positives are not
// JavaScript source.
func isProbablyHTML(source []byte) bool {
	for _, b := range source {
		if unicode.IsSpace(rune(b)) {
			continue
		}

		if b == '<' {
			return true
		}
		break
	}

	return false
}

// extractInlineJS extracts inline JavaScript from HTML pages using goquery.
func extractInlineJS(source []byte) []byte {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(source))
	if err != nil {
		// Not a valid HTML document, so just return the source.
		return source
	}

	var inline []byte
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		if s.Is("script") {
			inline = append(inline, []byte(s.Text()+"\n")...)
		}
	})
	if len(inline) == 0 {
		return source
	}
	return inline
}
