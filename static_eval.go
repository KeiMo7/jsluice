package jsluice

import (
	"net/url"

	sitter "github.com/smacker/go-tree-sitter"
)

// This file holds the recursive part of the static evaluator. Evaluation works
// directly on tree-sitter nodes (rather than the jsluice Node wrapper) so that
// a value assembled from hundreds of fragments does not allocate a wrapper per
// child. The public entry points wrap the root node and return StaticValue.

// staticEvaluator evaluates expressions in one JavaScript file. It is created
// lazily per Analyzer and is not safe for concurrent use; a single Analyzer is
// driven from a single goroutine.
type staticEvaluator struct {
	source []byte
	root   *sitter.Node
	file   string

	// bindings resolves identifiers to the value that dominates a use.
	bindings *bindingTable

	// resolver resolves imports that name other files. It may be nil, in
	// which case imported values stay placeholders.
	resolver *ModuleResolver

	// exports caches this file's module interface.
	exports *moduleExports

	// memo caches evaluations keyed by node identity so a constant
	// referenced from several places is evaluated only once.
	memo map[nodeKey]StaticValue

	// active is the stack of nodes currently being evaluated, used for cycle
	// detection. A small slice is cheaper than a map on the hot path.
	active []*sitter.Node

	// state carries the per-evaluation budgets.
	state evalState

	// oversize counts values that were discarded for being too long.
	oversize int
}

// evalState carries the mutable budget counters for one evaluation.
type evalState struct {
	depth int
	nodes int
}

// nodeKey identifies a memoised evaluation.
type nodeKey struct {
	node      *sitter.Node
	startByte uint32
}

func newStaticEvaluator(root *sitter.Node, source []byte, file string) *staticEvaluator {
	e := &staticEvaluator{
		source: source,
		root:   root,
		file:   file,
		memo:   make(map[nodeKey]StaticValue),
	}
	e.bindings = newBindingTable(e, root)
	return e
}

// Eval evaluates a node in this file, honouring all budgets.
func (e *staticEvaluator) Eval(n *sitter.Node) StaticValue {
	if n == nil {
		return e.unknownValue(nil)
	}
	e.state.depth = 0
	e.state.nodes = 0
	e.active = e.active[:0]
	v := e.evalSN(n)
	return sanitizeAlternatives(v)
}

// OversizeCount reports how many values were discarded for being too long.
func (e *staticEvaluator) OversizeCount() int {
	return e.oversize
}

// evalSN evaluates a single syntax node.
func (e *staticEvaluator) evalSN(n *sitter.Node) StaticValue {
	if n == nil {
		return e.unknownValue(nil)
	}

	key := nodeKey{node: n, startByte: n.StartByte()}
	if v, ok := e.memo[key]; ok {
		return v
	}

	for _, a := range e.active {
		if a == n {
			return e.truncateValue(n, "circular reference")
		}
	}

	e.state.nodes++
	if e.state.nodes > maxEvalNodes {
		return e.truncateValue(n, "node budget exceeded")
	}
	if e.state.depth >= maxEvalDepth {
		return e.truncateValue(n, "depth budget exceeded")
	}

	e.active = append(e.active, n)
	e.state.depth++
	v := e.dispatch(n)
	e.state.depth--
	e.active = e.active[:len(e.active)-1]

	if v.nbytes > maxStaticValueLength && !v.Oversize {
		return e.oversizeValue(n)
	}
	e.memo[key] = v
	return v
}

// dispatch selects an evaluation strategy for a node.
func (e *staticEvaluator) dispatch(n *sitter.Node) StaticValue {
	switch n.Type() {
	case "string":
		return e.knownPart(n, decodeEscapes(stringBody(n.Content(e.source))))
	case "template_string":
		return e.evalTemplate(n)
	case "number":
		return e.knownPart(n, n.Content(e.source))
	case "true", "false":
		return e.knownPart(n, n.Content(e.source))
	case "undefined":
		return e.knownPart(n, "undefined")
	case "null":
		return e.unknownValue(n)
	case "identifier":
		return e.evalIdentifier(n)
	case "binary_expression":
		return e.evalBinary(n)
	case "parenthesized_expression":
		return e.evalSN(firstNamedChild(n))
	case "member_expression", "subscript_expression":
		return e.evalMember(n)
	case "call_expression":
		return e.evalCall(n)
	case "array":
		return e.evalArray(n)
	case "object":
		return e.unknownValue(n)
	case "ternary_expression":
		return e.evalTernary(n)
	case "assignment_expression":
		return e.evalSN(n.ChildByFieldName("right"))
	case "augmented_assignment_expression":
		return e.evalAugmented(n)
	case "sequence_expression":
		// The value of a comma expression is its final operand.
		return e.evalSN(lastNamedChild(n))
	default:
		return e.unknownValue(n)
	}
}

// evalBinary collapses the "+" operator. Every other operator (comparison,
// subtraction, multiplication and so on) does not concatenate strings, so its
// result is left unknown.
func (e *staticEvaluator) evalBinary(n *sitter.Node) StaticValue {
	if binaryOperator(n, e.source) != "+" {
		return e.unknownValue(n)
	}
	left := n.ChildByFieldName("left")
	right := n.ChildByFieldName("right")
	// Pure numeric addition (1 + 2) is arithmetic rather than string
	// concatenation; jsluice only reconstructs text.
	if isNumberNode(left) && isNumberNode(right) {
		return e.unknownValue(n)
	}
	return appendValue(e.evalSN(left), e.evalSN(right))
}

// evalAugmented handles compound assignment such as `u += "/x"`.
func (e *staticEvaluator) evalAugmented(n *sitter.Node) StaticValue {
	if binaryOperator(n, e.source) != "+=" {
		return e.unknownValue(n)
	}
	return appendValue(
		e.evalSN(n.ChildByFieldName("left")),
		e.evalSN(n.ChildByFieldName("right")),
	)
}

// evalTernary evaluates a conditional. When both arms are identical the
// condition does not matter. Otherwise both arms are kept as alternatives so a
// downstream matcher can report every URL the code can produce.
func (e *staticEvaluator) evalTernary(n *sitter.Node) StaticValue {
	cons := sanitizeAlternatives(e.evalSN(n.ChildByFieldName("consequence")))
	alt := sanitizeAlternatives(e.evalSN(n.ChildByFieldName("alternative")))

	if cons.String() == alt.String() && cons.FullyKnown() == alt.FullyKnown() {
		return cons
	}

	prim := cons.primaryOnly()
	rest := make([]StaticValue, 0, len(cons.Alternatives)+1+len(alt.Alternatives))
	rest = append(rest, cons.Alternatives...)
	rest = append(rest, alt.primaryOnly())
	rest = append(rest, alt.Alternatives...)
	out := withAlternatives(prim, rest)
	out.Unknown = cons.Unknown || alt.Unknown
	out.Truncated = cons.Truncated || alt.Truncated
	if out.Truncated {
		out.TruncationReason = cons.TruncationReason
		if out.TruncationReason == "" {
			out.TruncationReason = alt.TruncationReason
		}
	}
	return out
}

// evalArray concatenates an array literal's elements. This matches how an
// array is commonly used to assemble a path: ["a", "b"].join("/") evaluates the
// elements; evalJoin interleaves the separator.
func (e *staticEvaluator) evalArray(n *sitter.Node) StaticValue {
	out := StaticValue{}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if child.Type() == "spread_element" {
			out = appendValue(out, e.unknownValue(child))
			continue
		}
		out = appendValue(out, e.evalSN(child))
	}
	return out
}

// evalIdentifier resolves a variable or constant reference from the binding
// table. Unknown identifiers (globals, undeclared runtime values) stay
// placeholders.
func (e *staticEvaluator) evalIdentifier(n *sitter.Node) StaticValue {
	name := n.Content(e.source)
	if name == "undefined" {
		return e.knownPart(n, "undefined")
	}
	if v, ok := e.bindings.resolveValue(name, n); ok {
		return v
	}
	return e.unknownValue(n)
}

// evalMember resolves `object.property` and `object["property"]` by following
// the object back to an object literal or an object binding where possible.
func (e *staticEvaluator) evalMember(n *sitter.Node) StaticValue {
	key, ok := e.staticPropertyKey(n)
	if !ok {
		return e.unknownValue(n)
	}
	obj := n.ChildByFieldName("object")
	if obj == nil && int(n.NamedChildCount()) > 0 {
		obj = n.NamedChild(0)
	}
	if obj == nil {
		return e.unknownValue(n)
	}
	if v, ok := e.memberValue(obj, key, n); ok {
		return v
	}
	return e.unknownValue(n)
}

// memberValue resolves `obj.key` where obj and key are already known. ref is the
// node positioned at the reference (used for flow ordering and provenance). It
// is shared by member access and by destructuring.
func (e *staticEvaluator) memberValue(obj *sitter.Node, key string, ref *sitter.Node) (StaticValue, bool) {
	switch obj.Type() {
	case "identifier":
		if b, refFn := e.bindings.bindingAndContext(obj.Content(e.source), ref); b != nil {
			if v, ok := e.bindings.propertyValue(b, key, ref, refFn); ok {
				return v, true
			}
			if b.kind == kindImport {
				if v, ok := e.importMemberValue(b.imported, key, ref); ok {
					return v, true
				}
			}
		}
	case "call_expression":
		// require("./m").key
		if mod, ok := requireModule(obj, e.source); ok {
			if v, ok := e.moduleExportValue(mod, key, ref, 0); ok {
				return v, true
			}
		}
	case "member_expression", "subscript_expression":
		if inner := obj.ChildByFieldName("object"); inner != nil && inner.Type() == "call_expression" {
			if mod, ok := requireModule(inner, e.source); ok {
				if innerKey, ok := e.staticPropertyKey(obj); ok {
					if v, ok := e.moduleExportValue(mod, innerKey, ref, 0); ok {
						return v, true
					}
				}
			}
		}
	}
	if literal := e.objectLiteral(obj); literal != nil {
		if v, ok := e.objectPairValue(literal, key); ok {
			return v, true
		}
	}
	return StaticValue{}, false
}

// staticPropertyKey returns the statically-known name of a member access.
func (e *staticEvaluator) staticPropertyKey(n *sitter.Node) (string, bool) {
	switch n.Type() {
	case "member_expression":
		prop := n.ChildByFieldName("property")
		if prop == nil {
			return "", false
		}
		return prop.Content(e.source), true
	case "subscript_expression":
		idx := n.ChildByFieldName("index")
		if idx == nil && int(n.NamedChildCount()) > 1 {
			idx = n.NamedChild(1)
		}
		if idx == nil {
			return "", false
		}
		if idx.Type() == "string" {
			return decodeEscapes(stringBody(idx.Content(e.source))), true
		}
		v := e.evalSN(idx)
		if v.FullyKnown() {
			return v.String(), true
		}
		return "", false
	}
	return "", false
}

// objectPairValue returns the value stored for key in an object literal.
func (e *staticEvaluator) objectPairValue(literal *sitter.Node, key string) (StaticValue, bool) {
	v := e.objectPairValueNode(literal, key)
	if v == nil {
		return StaticValue{}, false
	}
	return e.evalSN(v), true
}

// objectPairValueNode returns the raw value node stored for key in an object
// literal, without evaluating it. It is used when collecting bindings.
func (e *staticEvaluator) objectPairValueNode(literal *sitter.Node, key string) *sitter.Node {
	if literal == nil || literal.Type() != "object" {
		return nil
	}
	for i := 0; i < int(literal.NamedChildCount()); i++ {
		item := literal.NamedChild(i)
		switch item.Type() {
		case "pair":
			if e.pairKey(item) != key {
				continue
			}
			return item.ChildByFieldName("value")
		case "shorthand_property_identifier":
			if item.Content(e.source) == key {
				return item
			}
		}
	}
	return nil
}

// objectPropertyFromLiteral evaluates the value stored for key in an object
// literal.
func (e *staticEvaluator) objectPropertyFromLiteral(literal *sitter.Node, key string) (StaticValue, bool) {
	v := e.objectPairValueNode(literal, key)
	if v == nil {
		return StaticValue{}, false
	}
	return e.evalSN(v), true
}

// requireModule reports the module specifier of a require("...") call.
func requireModule(n *sitter.Node, source []byte) (string, bool) {
	if n == nil || n.Type() != "call_expression" {
		return "", false
	}
	fn := n.ChildByFieldName("function")
	args := n.ChildByFieldName("arguments")
	if fn == nil || fn.Type() != "identifier" || fn.Content(source) != "require" {
		return "", false
	}
	if args == nil || int(args.NamedChildCount()) != 1 {
		return "", false
	}
	arg := args.NamedChild(0)
	if arg.Type() != "string" {
		return "", false
	}
	return decodeEscapes(stringBody(arg.Content(source))), true
}

// and member accesses. It returns nil when the value is not statically an
// object literal.
func (e *staticEvaluator) objectLiteral(n *sitter.Node) *sitter.Node {
	if n == nil {
		return nil
	}
	switch n.Type() {
	case "object":
		return n
	case "parenthesized_expression":
		return e.objectLiteral(firstNamedChild(n))
	case "identifier":
		b := e.bindings.bindingFor(n.Content(e.source), n)
		if b == nil || b.declNode == nil {
			return nil
		}
		return e.objectLiteral(b.declNode)
	case "member_expression", "subscript_expression":
		key, ok := e.staticPropertyKey(n)
		if !ok {
			return nil
		}
		obj := n.ChildByFieldName("object")
		if obj == nil && int(n.NamedChildCount()) > 0 {
			obj = n.NamedChild(0)
		}
		parent := e.objectLiteral(obj)
		if parent == nil {
			return nil
		}
		for i := 0; i < int(parent.NamedChildCount()); i++ {
			pair := parent.NamedChild(i)
			if pair.Type() != "pair" || e.pairKey(pair) != key {
				continue
			}
			v := pair.ChildByFieldName("value")
			if v != nil && (v.Type() == "object" || v.Type() == "array") {
				return v
			}
			return nil
		}
	}
	return nil
}

// pairKey returns the statically-known key of an object pair, including keys
// computed from constants (computed_property_name).
func (e *staticEvaluator) pairKey(pair *sitter.Node) string {
	key := pair.ChildByFieldName("key")
	if key == nil {
		return ""
	}
	switch key.Type() {
	case "property_identifier", "identifier":
		return key.Content(e.source)
	case "string":
		return decodeEscapes(stringBody(key.Content(e.source)))
	case "number":
		return key.Content(e.source)
	case "computed_property_name":
		inner := firstNamedChild(key)
		if inner == nil {
			return ""
		}
		v := e.evalSN(inner)
		if v.FullyKnown() {
			return v.String()
		}
	}
	return ""
}

// evalTemplate evaluates a template string. The grammar exposes substitutions
// and escape sequences as named children but not the literal text between
// them, so the literal chunks are recovered from the source byte ranges.
func (e *staticEvaluator) evalTemplate(n *sitter.Node) StaticValue {
	start := n.StartByte()
	end := n.EndByte()
	bodyStart := start + 1
	bodyEnd := end
	if bodyEnd > bodyStart {
		bodyEnd-- // drop the closing backtick
	}

	out := StaticValue{}
	cursor := bodyStart
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		if child.StartByte() > cursor {
			out = appendValue(out, e.knownPart(n, decodeEscapes(e.slice(cursor, child.StartByte()))))
		}
		switch child.Type() {
		case "template_substitution":
			inner := firstNamedChild(child)
			if inner == nil {
				out = appendValue(out, e.unknownValue(child))
			} else {
				out = appendValue(out, e.evalSN(inner))
			}
		case "escape_sequence":
			out = appendValue(out, e.knownPart(child, decodeEscapes(child.Content(e.source))))
		}
		if child.EndByte() > cursor {
			cursor = child.EndByte()
		}
	}
	if cursor < bodyEnd {
		out = appendValue(out, e.knownPart(n, decodeEscapes(e.slice(cursor, bodyEnd))))
	}
	if len(out.Parts) == 0 {
		return e.knownPart(n, "")
	}
	return out
}

// slice returns the source text between two byte offsets.
func (e *staticEvaluator) slice(start, end uint32) string {
	if start >= end || int(end) > len(e.source) {
		return ""
	}
	return string(e.source[start:end])
}

// evalCall evaluates the small, fixed set of calls whose result can be known
// statically without executing anything: array.join and the standard
// encode/decode string functions. Every other call stays a placeholder.
func (e *staticEvaluator) evalCall(n *sitter.Node) StaticValue {
	fn := n.ChildByFieldName("function")
	args := n.ChildByFieldName("arguments")

	if fn != nil && fn.Type() == "member_expression" {
		if prop := fn.ChildByFieldName("property"); prop != nil &&
			prop.Content(e.source) == "join" {
			return e.evalJoin(n, fn, args)
		}
	}

	name := ""
	if fn != nil {
		name = fn.Content(e.source)
	}
	switch name {
	case "decodeURIComponent", "decodeURI", "unescape":
		return e.evalDecode(n, args, decodeURI)
	case "encodeURIComponent", "encodeURI", "escape":
		return e.evalDecode(n, args, encodeURI)
	}
	return e.unknownValue(n)
}

// evalJoin evaluates array.join(sep) where the array is an array literal or an
// identifier bound to one, and the separator is statically known.
func (e *staticEvaluator) evalJoin(n, fn, args *sitter.Node) StaticValue {
	obj := fn.ChildByFieldName("object")
	if obj == nil {
		return e.unknownValue(n)
	}
	if obj.Type() == "identifier" {
		b := e.bindings.bindingFor(obj.Content(e.source), obj)
		if b == nil || b.declNode == nil || b.declNode.Type() != "array" {
			return e.unknownValue(n)
		}
		obj = b.declNode
	}
	if obj.Type() != "array" {
		return e.unknownValue(n)
	}

	sep := ""
	if args != nil && int(args.NamedChildCount()) > 0 {
		sepVal := e.evalSN(args.NamedChild(0))
		if !sepVal.FullyKnown() {
			return e.unknownValue(n)
		}
		sep = sepVal.String()
	}

	out := StaticValue{}
	count := int(obj.NamedChildCount())
	for i := 0; i < count; i++ {
		if i > 0 && sep != "" {
			out = appendValue(out, e.knownPart(n, sep))
		}
		out = appendValue(out, e.evalSN(obj.NamedChild(i)))
	}
	return out
}

// uriTransform selects the pure String-to-String transformation applied by
// evalDecode.
type uriTransform int

const (
	decodeURI uriTransform = iota
	encodeURI
)

// evalDecode applies a standard decode/encode function to a statically-known
// argument. The functions are pure and well-defined, so applying them mirrors
// what the browser would do without executing any script.
func (e *staticEvaluator) evalDecode(n, args *sitter.Node, t uriTransform) StaticValue {
	if args == nil || int(args.NamedChildCount()) < 1 {
		return e.unknownValue(n)
	}
	v := e.evalSN(args.NamedChild(0))
	if !v.FullyKnown() {
		return e.unknownValue(n)
	}
	raw := v.String()
	out := raw
	switch t {
	case decodeURI:
		if decoded, err := url.PathUnescape(raw); err == nil {
			out = decoded
		}
	case encodeURI:
		out = url.PathEscape(raw)
	}
	return e.knownPart(n, out)
}

// --- small tree-sitter helpers ---------------------------------------------

func firstNamedChild(n *sitter.Node) *sitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(0)
}

func lastNamedChild(n *sitter.Node) *sitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(int(n.NamedChildCount()) - 1)
}

func isNumberNode(n *sitter.Node) bool {
	return n != nil && n.Type() == "number"
}

// binaryOperator returns the operator text of a binary or augmented-assignment
// expression, e.g. "+" or "+=".
func binaryOperator(n *sitter.Node, source []byte) string {
	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if c.IsNamed() {
			continue
		}
		if s := c.Content(source); s != "" {
			return s
		}
	}
	return ""
}

// stringBody strips the surrounding quotes from a string literal's source.
func stringBody(raw string) string {
	if len(raw) >= 2 {
		return raw[1 : len(raw)-1]
	}
	return raw
}
