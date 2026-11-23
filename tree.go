package jsluice

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
)

// ExpressionPlaceholder is the string used to replace any
// expressions when string concatenations are collapsed. E.g:
//   "prefix" + someVar + "suffix"
// Would become:
//   prefixEXPRsuffix
var ExpressionPlaceholder = "EXPR"

// Node is a wrapper around a tree-sitter node. It serves as
// an attachment point for convenience methods, and also to
// store the raw JavaScript source that is a required argument
// for many tree-sitter functions.
type Node struct {
	node        *sitter.Node
	source      []byte
	captureName string

	// analyzer, when set, provides the static evaluator used by
	// CollapsedString. It is optional: nodes created standalone fall back
	// to the legacy local collapsing behavior.
	analyzer *Analyzer
}

// NewNode creates a new Node for the provided tree-sitter
// node and a byte-slice containing the JavaScript source.
// The source provided should be the complete source code
// and not just the source for the node in question.
func NewNode(n *sitter.Node, source []byte) *Node {
	return &Node{
		node:   n,
		source: source,
	}
}

// withAnalyzer returns a copy of the Node carrying the Analyzer reference
// needed for cross-node static evaluation.
func (n *Node) withAnalyzer(a *Analyzer) *Node {
	return &Node{
		node:        n.node,
		source:      n.source,
		captureName: n.captureName,
		analyzer:    a,
	}
}

// wrap creates a Node for a child tree-sitter node, propagating the analyzer
// reference so static evaluation remains available.
func (n *Node) wrap(child *sitter.Node) *Node {
	return &Node{
		node:     child,
		source:   n.source,
		analyzer: n.analyzer,
	}
}

// AsObject returns a Node as jsluice's internal object type,
// to allow the fetching of keys etc
func (n *Node) AsObject() Object {
	return NewObject(n, n.source)
}

// Content returns the source code for a particular node.
func (n *Node) Content() string {
	if n.node == nil {
		return ""
	}
	return n.node.Content(n.source)
}

// Type returns the tree-sitter type string for a Node.
// E.g. string, object, call_expression. If the node is
// nil then an empty string is returned.
func (n *Node) Type() string {
	if n.node == nil {
		return ""
	}
	return n.node.Type()
}

// Fetches a child Node from a named field. For example,
// the 'pair' node has two fields: key, and value.
func (n *Node) ChildByFieldName(name string) *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.ChildByFieldName(name))
}

// Child returns the child Node at the provided index
func (n *Node) Child(index int) *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.Child(index))
}

// NamedChild returns the 'named' child Node at the provided
// index. Tree-sitter considers a child to be named if it has
// a name in the syntax tree. Things like brackets are not named,
// but things like variables and function calls are named.
// See https://tree-sitter.github.io/tree-sitter/using-parsers#named-vs-anonymous-nodes
// for more details.
func (n *Node) NamedChild(index int) *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.NamedChild(index))
}

// ChildCount returns the number of children a node has
func (n *Node) ChildCount() int {
	if !n.IsValid() {
		return 0
	}
	return int(n.node.ChildCount())
}

// NamedChildCount returns the number of named children a Node has.
func (n *Node) NamedChildCount() int {
	if !n.IsValid() {
		return 0
	}
	return int(n.node.NamedChildCount())
}

// Childten returns a slide of *Node containing all children for a node
func (n *Node) Children() []*Node {
	count := n.ChildCount()
	out := make([]*Node, 0, count)

	for i := 0; i < count; i++ {
		out = append(out, n.Child(i))
	}

	return out
}

// NamedChildren returns a slice of *Node containg all
// named children for a node.
func (n *Node) NamedChildren() []*Node {
	count := n.NamedChildCount()
	out := make([]*Node, 0, count)

	for i := 0; i < count; i++ {
		out = append(out, n.NamedChild(i))
	}

	return out
}

// NextSibling returns the next sibling in the tree
func (n *Node) NextSibling() *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.NextSibling())
}

// NextNamedSibling returns the next named sibling in the tree
func (n *Node) NextNamedSibling() *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.NextNamedSibling())
}

// PrevSibling returns the previous sibling in the tree
func (n *Node) PrevSibling() *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.PrevSibling())
}

// PrevNamedSibling returns the previous named sibling in the tree
func (n *Node) PrevNamedSibling() *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.PrevNamedSibling())
}

// CollapsedString takes a node representing a URL and attempts to make it
// at least somewhat easily parseable. It's common to build URLs out
// of variables and function calls so we want to turn something like:
//
//  './upload.php?profile='+res.id+'&show='+$('.participate_modal_container').attr('data-val')
//
// Into something more like:
//
//  ./upload.php?profile=EXPR&show=EXPR
//
// The value of ExpressionPlaceholder is used as a placeholder, defaulting to 'EXPR'.
//
// When the Node is attached to an Analyzer, CollapsedString uses the
// analyzer's conservative static evaluator: constants (including those
// declared elsewhere in the file or imported from another module), template
// strings, array joins and object properties are resolved before any
// placeholder is emitted. Nodes created without an Analyzer retain the
// original local behavior.
func (n *Node) CollapsedString() string {
	if !n.IsValid() {
		return ""
	}
	if n.analyzer != nil {
		return n.analyzer.EvalStaticString(n)
	}
	return n.collapsedStringLocal()
}

// StaticValue returns the full provenance-carrying result of statically
// evaluating the node. It requires the node to be attached to an Analyzer;
// standalone nodes fall back to local collapsing wrapped in a StaticValue.
func (n *Node) StaticValue() StaticValue {
	if !n.IsValid() {
		return StaticValue{Unknown: true}
	}
	if n.analyzer != nil {
		return n.analyzer.EvalStatic(n)
	}
	return StaticValue{Parts: []StaticPart{{
		Value:  n.collapsedStringLocal(),
		Source: n.Content(),
	}}}
}

// collapsedStringLocal is the original, purely local collapsing logic that
// only understands binary expressions and string literals.
func (n *Node) collapsedStringLocal() string {
	if !n.IsValid() {
		return ""
	}
	switch n.Type() {
	case "binary_expression":
		return fmt.Sprintf(
			"%s%s",
			n.ChildByFieldName("left").collapsedStringLocal(),
			n.ChildByFieldName("right").collapsedStringLocal(),
		)
	case "string":
		return n.RawString()
	default:
		return ExpressionPlaceholder
	}
}

// IsValid returns true if the *Node and the underlying
// tree-sitter node are both not nil.
func (n *Node) IsValid() bool {
	return n != nil && n.node != nil
}

// RawString returns the raw JavaScript representation
// of a string (i.e. escape sequences are left undecoded)
// but with the surrounding quotes removed.
func (n *Node) RawString() string {
	return dequote(n.Content())
}

// DecodedString returns a fully decoded version of a
// JavaScript string. It is just a convenience wrapper
// around the DecodeString function.
func (n *Node) DecodedString() string {
	return DecodeString(n.Content())
}

// AsGoType returns a representation of a Node as a native
// Go type, defaulting to a string containing the JavaScript
// source for the Node. Return types are:
//
//   string => string
//   number => int, float64
//   object => map[string]any
//   array  => []any
//   false  => false
//   true   => true
//   null   => nil
//   other  => string
//
func (n *Node) AsGoType() any {
	if n == nil {
		return nil
	}

	switch n.Type() {
	case "string":
		return n.DecodedString()
	case "number":
		return n.AsNumber()
	case "object":
		return n.AsMap()
	case "array":
		return n.AsArray()
	case "false":
		return false
	case "true":
		return true
	case "null":
		return nil
	default:
		return n.Content()
	}
}

// AsMap returns a representation of the Node as a map[string]any
func (n *Node) AsMap() map[string]any {
	if n.Type() != "object" {
		return map[string]any{}
	}

	pairs := n.NamedChildren()

	out := make(map[string]any, len(pairs))

	for _, pair := range pairs {
		if pair.Type() != "pair" {
			continue
		}

		key := DecodeString(pair.ChildByFieldName("key").RawString())
		value := pair.ChildByFieldName("value").AsGoType()

		out[key] = value
	}
	return out
}

// AsArray returns a representation of the Node as a []any
func (n *Node) AsArray() []any {
	if n.Type() != "array" {
		return []any{}
	}

	values := n.NamedChildren()

	out := make([]any, 0, len(values))

	for _, v := range values {
		out = append(out, v.AsGoType())
	}

	return out
}

// AsNumber returns a representation of the Node as an int or float64.
//
// Note: hex, octal etc number formats are currently unsupported
func (n *Node) AsNumber() any {
	if n.Type() != "number" {
		return 0
	}

	// TODO: handle hex, octal etc

	content := n.Content()
	if strings.Contains(content, ".") {
		// float
		f, err := strconv.ParseFloat(content, 64)
		if err != nil {
			return 0
		}
		return f
	}

	// int
	i, err := strconv.ParseInt(content, 10, 64)
	if err != nil {
		return 0
	}
	return i
}

// Parent returns the Parent Node for a Node
func (n *Node) Parent() *Node {
	if !n.IsValid() {
		return nil
	}
	return n.wrap(n.node.Parent())
}

// IsNamed returns true if the underlying node is named
func (n *Node) IsNamed() bool {
	if !n.IsValid() {
		return false
	}
	return n.node.IsNamed()
}

// ForEachChild iterates over a node's children in a depth-first
// manner, calling the supplied function for each node
func (n *Node) ForEachChild(fn func(*Node)) {
	it := sitter.NewIterator(n.node, sitter.DFSMode)

	it.ForEach(func(sn *sitter.Node) error {
		fn(n.wrap(sn))
		return nil
	})
}

// ForEachNamedChild iterates over a node's named children in a
// depth-first manner, calling the supplied function for each node
func (n *Node) ForEachNamedChild(fn func(*Node)) {
	it := sitter.NewNamedIterator(n.node, sitter.DFSMode)

	it.ForEach(func(sn *sitter.Node) error {
		fn(n.wrap(sn))
		return nil
	})
}

// Format outputs a nicely formatted version of the source code for the
// Node. Formatting is done by https://github.com/ditashi/jsbeautifier-go/
func (n *Node) Format() (string, error) {
	source := n.Content()
	return jsbeautifier.Beautify(&source, jsbeautifier.DefaultOptions())
}

// Query executes a tree-sitter query on a specific Node.
// Nodes captured by the query are passed one at a time to the
// provided callback function.
//
// See https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries
// for query syntax documentation.
func (n *Node) Query(query string, fn func(*Node)) {
	n.QueryMulti(query, func(qr QueryResult) {
		for _, n := range qr {
			fn(n)
		}
	})
}

// QueryResult is a map of capture names to the corresponding nodes that they matched
type QueryResult map[string]*Node

// NewQueryResult returns a QueryResult containing the provided *Nodes
func NewQueryResult(nodes ...*Node) QueryResult {
	out := make(QueryResult)

	for _, n := range nodes {
		out.Add(n)
	}

	return out
}

// Add accepts a *Node and adds it to the QueryResult,
// provided it has a valid CaptureName
func (qr QueryResult) Add(n *Node) {
	key := n.CaptureName()
	if key == "" {
		return
	}
	qr[key] = n
}

// Has returns true if the QueryResult contains a *Node
// for the provided capture name
func (qr QueryResult) Has(captureName string) bool {
	_, exists := qr[captureName]
	return exists
}

// Get returns the corresponding *Node for the provided
// capture name, or nil if no such *Node exists
func (qr QueryResult) Get(captureName string) *Node {
	if !qr.Has(captureName) {
		return nil
	}
	return qr[captureName]
}

// QueryMulti executes a tree-sitter query on a specific Node.
// Nodes captured by the query are grouped into a QueryResult
// and passed to the provided callback function.
//
// See https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries
// for query syntax documentation.
func (n *Node) QueryMulti(query string, fn func(QueryResult)) {
	if !n.IsValid() {
		return
	}
	q, err := sitter.NewQuery(
		[]byte(query),
		javascript.GetLanguage(),
	)
	if err != nil {
		return
	}

	qc := sitter.NewQueryCursor()
	defer qc.Close()

	qc.Exec(q, n.node)

	for {
		match, exists := qc.NextMatch()
		if !exists || match == nil {
			break
		}

		match = qc.FilterPredicates(match, n.source)

		qr := NewQueryResult()

		for _, capture := range match.Captures {
			node := n.wrap(capture.Node)
			node.captureName = q.CaptureNameForId(capture.Index)
			qr.Add(node)
		}
		if len(qr) == 0 {
			continue
		}
		fn(qr)
	}
}

// IsStringy returns true if a Node is a string
// or is an expression starting with a string
// (e.g. a string concatenation expression).
func (n *Node) IsStringy() bool {
	if n.Type() == "string" {
		return true
	}

	c := n.Content()
	if len(c) == 0 {
		return false
	}

	switch c[0:1] {
	case `"`, "'", "`":
		return true
	default:
		return false
	}
}

// HasStaticString reports whether conservative static evaluation can produce
// at least one concrete string fragment for the node. Unlike IsStringy, this
// does not require the expression to begin with a literal: an expression such
// as BASE + "/login", where BASE is a string constant, also qualifies. URL
// matchers use it to accept expressions the static evaluator can partially
// resolve. A wholly runtime-dependent expression still returns false.
func (n *Node) HasStaticString() bool {
	if !n.IsValid() {
		return false
	}
	if n.analyzer == nil {
		return n.IsStringy()
	}
	return n.analyzer.EvalStatic(n).HasKnownFragment()
}

// CaptureName returns the name given to a node in a
// query if one exists, and an empty string otherwise
func (n *Node) CaptureName() string {
	return n.captureName
}

// dequote removes surround quotes from the provided string
func dequote(in string) string {
	return strings.Trim(in, "'\"`")
}

// content returns the source for the provided tree-sitter
// node, checking if the node is nil first.
func content(n *sitter.Node, source []byte) string {
	if n == nil {
		return ""
	}
	return n.Content(source)
}

// PrintTree returns a string representation of the syntax tree
// for the provided JavaScript source
func PrintTree(source []byte) string {
	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())

	tree := parser.Parse(nil, source)
	root := tree.RootNode()

	return getTree(root, source)
}

// getTree does the actual heavy lifting and recursion for PrintTree
// TODO: provide a way to print the tree as a JSON object?
func getTree(n *sitter.Node, source []byte) string {

	out := &strings.Builder{}

	c := sitter.NewTreeCursor(n)
	defer c.Close()

	// walkies
	depth := 0
	recurse := true
	for {
		if recurse && c.CurrentNode().IsNamed() {
			fieldName := c.CurrentFieldName()
			if fieldName != "" {
				fieldName += ": "
			}

			contentStr := ""
			if c.CurrentNode().ChildCount() == 0 || c.CurrentNode().Type() == "string" {
				contentStr = fmt.Sprintf(" (%s)", content(c.CurrentNode(), source))
			}
			fmt.Fprintf(out, "%s%s%s%s\n", strings.Repeat("  ", depth), fieldName, c.CurrentNode().Type(), contentStr)
		}

		// descend into the tree
		if recurse && c.GoToFirstChild() {
			recurse = true
			depth++
			continue
		}

		// move sideways
		if c.GoToNextSibling() {
			recurse = true
			continue
		}

		// climb back up the tree, but make sure we don't descend right back to where we were
		if c.GoToParent() {
			depth--
			recurse = false
			continue
		}
		break
	}

	return strings.TrimSpace(out.String())
}
