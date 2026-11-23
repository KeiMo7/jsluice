package jsluice

import (
	"sort"

	sitter "github.com/smacker/go-tree-sitter"
)

// This file resolves identifiers to the value that dominates a reference at a
// given position. It is the part that turns BASE + "/login" into a complete
// address when BASE is a constant, a destructured property, a reassigned
// variable, or an imported value.
//
// The rules are intentionally conservative. A constant is only substituted
// when doing so cannot change which value the code would use at runtime:
//   - a reference resolves to the nearest enclosing scope that binds the name;
//   - a value is only taken from an assignment or declaration that is textually
//     before the reference, in the same function, and not inside a construct
//     that may execute a different number of times (if/else, loops, switch,
//     try/catch) unless every branch yields the same value;
//   - a reassignment inside a conditional makes the value branch-dependent:
//     both the previous value and the conditional one are kept as alternatives;
//   - function parameters and values from modules that cannot be read stay
//     unknown.
type bindingTable struct {
	e         *staticEvaluator
	source    []byte
	rootScope *scope
	scopes    map[*sitter.Node]*scope
}

// binding is one name in one scope.
type binding struct {
	name     string
	scope    *scope
	kind     bindingKind
	declNode *sitter.Node // value the name was initialized with
	declPos  uint32       // byte offset of that value
	flow     []flowItem   // later whole-identifier assignments, in source order
	mutate   []flowItem   // property assignments to this binding (obj.key = v)
	imported importRef

	// destructured is set when the name was bound by destructuring.
	// destructureSource is the object it was destructured from, retained so
	// the member can be resolved lazily when the object is not a literal.
	destructured      bool
	memberKey         string
	destructureSource *sitter.Node
}

type bindingKind int

const (
	kindLexical bindingKind = iota
	kindVar
	kindParam
	kindImport
	kindFunction
)

// flowItem is one assignment to a binding.
type flowItem struct {
	value     *sitter.Node // right-hand side
	left      *sitter.Node // left-hand identifier (for += only)
	pos       uint32
	fnScope   *sitter.Node
	branches  bool // assigned under a conditional construct
	augmented bool
	property  string // non-empty for obj.key = value mutations
}

// importRef describes what an imported binding refers to.
type importRef struct {
	module      string
	name        string
	isDefault   bool
	isNamespace bool
}

// scope is a lexical scope.
type scope struct {
	parent   *scope
	node     *sitter.Node
	bindings map[string]*binding
}

func (s *scope) lookup(name string) *binding {
	for cur := s; cur != nil; cur = cur.parent {
		if b, ok := cur.bindings[name]; ok {
			return b
		}
	}
	return nil
}

func isScopeNodeType(t string) bool {
	switch t {
	case "program", "statement_block", "function_declaration", "function",
		"generator_function_declaration", "arrow_function", "method_definition",
		"class", "class_declaration", "class_body",
		"for_statement", "for_in_statement", "catch_clause", "switch_body":
		return true
	}
	return false
}

func isFunctionNodeType(t string) bool {
	switch t {
	case "function_declaration", "function", "generator_function_declaration",
		"arrow_function", "method_definition":
		return true
	}
	return false
}

func isBranchNodeType(t string) bool {
	switch t {
	case "if_statement", "switch_case", "switch_default", "ternary_expression",
		"try_statement", "catch_clause", "for_statement", "for_in_statement",
		"while_statement", "do_statement", "conditional_expression":
		return true
	}
	return false
}

// newBindingTable builds the table in one depth-first pass.
func newBindingTable(e *staticEvaluator, root *sitter.Node) *bindingTable {
	t := &bindingTable{
		e:      e,
		source: e.source,
		scopes: make(map[*sitter.Node]*scope),
	}
	if root == nil {
		return t
	}
	t.rootScope = &scope{node: root, bindings: make(map[string]*binding)}
	t.scopes[root] = t.rootScope
	t.walk(root, t.rootScope, root, nil)
	t.finalize()
	return t
}

func (t *bindingTable) walk(n *sitter.Node, sc *scope, fnScope *sitter.Node, branches []*sitter.Node) {
	if n == nil {
		return
	}
	if isScopeNodeType(n.Type()) {
		if n != t.rootScope.node {
			sc = &scope{parent: sc, node: n, bindings: make(map[string]*binding)}
			t.scopes[n] = sc
		}
	}
	if isFunctionNodeType(n.Type()) {
		fnScope = n
	}
	if isBranchNodeType(n.Type()) {
		// Copy so sibling subtrees never share the enclosing list.
		nb := make([]*sitter.Node, len(branches), len(branches)+1)
		copy(nb, branches)
		branches = append(nb, n)
	}

	t.collect(n, sc, fnScope, branches)

	for i := 0; i < int(n.NamedChildCount()); i++ {
		t.walk(n.NamedChild(i), sc, fnScope, branches)
	}
}

func (t *bindingTable) collect(n *sitter.Node, sc *scope, fnScope *sitter.Node, branches []*sitter.Node) {
	switch n.Type() {
	case "variable_declarator":
		t.recordPattern(
			n.ChildByFieldName("name"),
			n.ChildByFieldName("value"),
			sc,
			kindFromDeclaration(n.Parent()),
			branches,
		)
	case "assignment_expression":
		left := n.ChildByFieldName("left")
		right := n.ChildByFieldName("right")
		if left == nil || right == nil {
			return
		}
		switch left.Type() {
		case "identifier":
			t.recordAssignment(left, right, nil, sc, fnScope, branches, false)
		case "member_expression", "subscript_expression":
			t.recordPropertyAssignment(left, right, sc, fnScope, branches)
		}
	case "augmented_assignment_expression":
		if binaryOperator(n, t.source) != "+=" {
			return
		}
		left := n.ChildByFieldName("left")
		right := n.ChildByFieldName("right")
		if left != nil && right != nil && left.Type() == "identifier" {
			t.recordAssignment(left, right, left, sc, fnScope, branches, true)
		}
	case "function_declaration", "function", "generator_function_declaration",
		"arrow_function", "method_definition":
		// The function's own scope is the one just created for its node.
		fnSc := t.scopes[n]
		if fnSc == nil {
			fnSc = sc
		}
		t.recordParameters(n, fnSc)
	case "class_declaration":
		if name := n.ChildByFieldName("name"); name != nil {
			t.declare(sc, name.Content(t.source), kindLexical, n)
		}
	case "import_statement":
		t.recordImport(n, sc)
	}
}

func kindFromDeclaration(parent *sitter.Node) bindingKind {
	if parent != nil && parent.Type() == "variable_declaration" {
		return kindVar
	}
	return kindLexical
}

// recordPattern records identifiers bound by a declaration pattern.
func (t *bindingTable) recordPattern(name, value *sitter.Node, sc *scope, kind bindingKind, branches []*sitter.Node) {
	if name == nil {
		return
	}
	switch name.Type() {
	case "identifier":
		t.declare(sc, name.Content(t.source), kind, value)
	case "object_pattern":
		for i := 0; i < int(name.NamedChildCount()); i++ {
			p := name.NamedChild(i)
			switch p.Type() {
			case "shorthand_property_identifier_pattern":
				t.recordDestructured(sc, p, p.Content(t.source), value)
			case "pair_pattern":
				keyNode := p.ChildByFieldName("key")
				valNode := p.ChildByFieldName("value")
				if keyNode == nil || valNode == nil || valNode.Type() != "identifier" {
					continue
				}
				key := keyNode.Content(t.source)
				if keyNode.Type() == "string" {
					key = decodeEscapes(stringBody(keyNode.Content(t.source)))
				}
				t.recordDestructured(sc, valNode, key, value)
			}
		}
	case "array_pattern":
		for i := 0; i < int(name.NamedChildCount()); i++ {
			elem := name.NamedChild(i)
			if elem.Type() != "identifier" {
				continue
			}
			var elemValue *sitter.Node
			if value != nil && value.Type() == "array" && i < int(value.NamedChildCount()) {
				elemValue = value.NamedChild(i)
			}
			t.declare(sc, elem.Content(t.source), kindLexical, elemValue)
		}
	}
}

// recordDestructured binds a name extracted from an object literal member. The
// member value becomes the declaration value, so `const {base} = {base: "x"}`
// resolves exactly like `const base = "x"`. When the source object is not a
// literal now (for example `const {REGION} = require("./m")`), the destructured
// binding keeps its source so it can be resolved lazily at a reference site.
func (t *bindingTable) recordDestructured(sc *scope, nameNode *sitter.Node, key string, value *sitter.Node) {
	var memberValue *sitter.Node
	if value != nil && value.Type() == "object" {
		memberValue = t.e.objectPairValueNode(value, key)
	}
	b := t.declare(sc, nameNode.Content(t.source), kindLexical, memberValue)
	b.destructured = true
	b.memberKey = key
	// Keep the source object so the member can be resolved lazily at a
	// reference site. This avoids evaluating during table construction
	// (which would run with an incomplete binding table) and also serves
	// the `const {REGION} = require("./m")` case.
	b.destructureSource = value
}

func (t *bindingTable) declare(sc *scope, name string, kind bindingKind, value *sitter.Node) *binding {
	b := &binding{name: name, scope: sc, kind: kind, declNode: value}
	if value != nil {
		b.declPos = value.StartByte()
	}
	sc.bindings[name] = b
	return b
}

// bindingFor returns the binding visible for name at ref.
func (t *bindingTable) bindingFor(name string, ref *sitter.Node) *binding {
	return t.scopeAt(ref).lookup(name)
}

// bindingAndContext returns the binding visible for name at ref together with
// the reference's enclosing function, resolved in a single parent climb.
func (t *bindingTable) bindingAndContext(name string, ref *sitter.Node) (*binding, *sitter.Node) {
	sc, fn := t.referenceContext(ref)
	return sc.lookup(name), fn
}

func (t *bindingTable) recordAssignment(left, right, augLeft *sitter.Node, sc *scope, fnScope *sitter.Node, branches []*sitter.Node, augmented bool) {
	name := left.Content(t.source)
	b := sc.lookup(name)
	if b == nil {
		// Undeclared assignment behaves like a global in sloppy mode; record
		// it in the root scope so later references can still resolve.
		b = t.declare(t.rootScope, name, kindLexical, nil)
	}
	b.flow = append(b.flow, flowItem{
		value:     right,
		left:      augLeft,
		pos:       left.StartByte(),
		fnScope:   fnScope,
		branches:  len(branches) > 0,
		augmented: augmented,
	})
}

func (t *bindingTable) recordPropertyAssignment(left, right *sitter.Node, sc *scope, fnScope *sitter.Node, branches []*sitter.Node) {
	key, ok := t.e.staticPropertyKey(left)
	if !ok {
		return
	}
	obj := left.ChildByFieldName("object")
	if obj == nil && int(left.NamedChildCount()) > 0 {
		obj = left.NamedChild(0)
	}
	if obj == nil || obj.Type() != "identifier" {
		return
	}
	b := t.scopeAt(obj).lookup(obj.Content(t.source))
	if b == nil {
		return
	}
	b.mutate = append(b.mutate, flowItem{
		value:    right,
		pos:      left.StartByte(),
		fnScope:  fnScope,
		branches: len(branches) > 0,
		property: key,
	})
}

func (t *bindingTable) recordParameters(fn *sitter.Node, fnSc *scope) {
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	for i := 0; i < int(params.NamedChildCount()); i++ {
		p := params.NamedChild(i)
		switch p.Type() {
		case "identifier":
			t.declare(fnSc, p.Content(t.source), kindParam, nil)
		case "assignment_pattern":
			if left := p.ChildByFieldName("left"); left != nil && left.Type() == "identifier" {
				t.declare(fnSc, left.Content(t.source), kindParam, nil)
			}
		case "rest_pattern":
			if inner := firstNamedChild(p); inner != nil && inner.Type() == "identifier" {
				t.declare(fnSc, inner.Content(t.source), kindParam, nil)
			}
		}
	}
}

func (t *bindingTable) recordImport(n *sitter.Node, sc *scope) {
	module := ""
	if src := n.ChildByFieldName("source"); src != nil {
		module = decodeEscapes(stringBody(src.Content(t.source)))
	}
	clause := n.ChildByFieldName("import")
	if clause == nil {
		clause = firstNamedChildOfType(n, "import_clause")
	}
	if clause == nil {
		return
	}
	for i := 0; i < int(clause.NamedChildCount()); i++ {
		c := clause.NamedChild(i)
		switch c.Type() {
		case "identifier":
			b := t.declare(sc, c.Content(t.source), kindImport, nil)
			b.imported = importRef{module: module, name: "default", isDefault: true}
		case "namespace_import":
			if inner := firstNamedChild(c); inner != nil {
				b := t.declare(sc, inner.Content(t.source), kindImport, nil)
				b.imported = importRef{module: module, name: "*", isNamespace: true}
			}
		case "named_imports":
			for j := 0; j < int(c.NamedChildCount()); j++ {
				spec := c.NamedChild(j)
				if spec.Type() != "import_specifier" {
					continue
				}
				nameNode := spec.ChildByFieldName("name")
				if nameNode == nil {
					continue
				}
				local := spec.ChildByFieldName("alias")
				if local == nil {
					local = nameNode
				}
				b := t.declare(sc, local.Content(t.source), kindImport, nil)
				b.imported = importRef{module: module, name: nameNode.Content(t.source)}
			}
		}
	}
}

// finalize sorts each binding's flow entries by position so resolution can
// stop scanning at the reference position.
func (t *bindingTable) finalize() {
	var walk func(sc *scope)
	walk = func(sc *scope) {
		for _, b := range sc.bindings {
			if len(b.flow) > 1 {
				sort.SliceStable(b.flow, func(i, j int) bool {
					return b.flow[i].pos < b.flow[j].pos
				})
			}
			if len(b.mutate) > 1 {
				sort.SliceStable(b.mutate, func(i, j int) bool {
					return b.mutate[i].pos < b.mutate[j].pos
				})
			}
		}
	}
	// Scopes form a tree, but bindings only appear in the scope that created
	// them, so a flat pass over the map is enough.
	for _, sc := range t.scopes {
		walk(sc)
	}
}

// scopeAt returns the innermost scope containing ref.
func (t *bindingTable) scopeAt(ref *sitter.Node) *scope {
	for cur := ref; cur != nil; cur = cur.Parent() {
		if sc, ok := t.scopes[cur]; ok {
			return sc
		}
	}
	return t.rootScope
}

// referenceContext returns both the enclosing scope and enclosing function of
// ref in a single climb of the parent chain. Each Parent() call is a cgo round
// trip, so one climb instead of several materially reduces analyse time on
// large inputs.
func (t *bindingTable) referenceContext(ref *sitter.Node) (*scope, *sitter.Node) {
	sc := t.rootScope
	var fn *sitter.Node
	for cur := ref; cur != nil; cur = cur.Parent() {
		if fn == nil && isFunctionNodeType(cur.Type()) {
			fn = cur
		}
		if found, ok := t.scopes[cur]; ok {
			// The innermost scope is encountered first during the climb.
			sc = found
			break
		}
	}
	if fn == nil {
		fn = t.rootScope.node
	}
	return sc, fn
}

// resolveValue returns the statically-known value of a reference to name at
// ref, or ok=false if the name is not bound.
func (t *bindingTable) resolveValue(name string, ref *sitter.Node) (StaticValue, bool) {
	b, refFn := t.bindingAndContext(name, ref)
	if b == nil {
		return StaticValue{}, false
	}
	return t.evalBinding(b, ref, refFn), true
}

// evalBinding computes b's value at the reference position, which lies in
// function refFn.
func (t *bindingTable) evalBinding(b *binding, ref, refFn *sitter.Node) StaticValue {
	e := t.e
	switch b.kind {
	case kindImport:
		return e.resolveImport(ref, b.imported)
	case kindParam:
		return e.unknownValue(ref)
	}

	curr := t.initialValue(b, ref)
	refByte := ref.StartByte()

	var alts []StaticValue
	for _, f := range b.flow {
		if f.pos >= refByte {
			break
		}
		if f.property != "" || f.fnScope != refFn {
			// Property mutations are resolved by evalMember; assignments in a
			// different function do not dominate this reference.
			continue
		}
		var v StaticValue
		if f.augmented {
			v = appendValue(e.evalSN(f.left), e.evalSN(f.value))
		} else {
			v = e.evalSN(f.value)
		}
		if f.branches {
			alts = append(alts, v)
			continue
		}
		curr = v
		alts = alts[:0]
	}
	if len(alts) > 0 {
		curr = withAlternatives(curr, alts)
	}
	return sanitizeAlternatives(curr)
}

// initialValue is the value of b before any reassignment: its declaration, or
// a member of the object it was destructured from.
func (t *bindingTable) initialValue(b *binding, ref *sitter.Node) StaticValue {
	e := t.e
	// A reference textually before the declaration does not see the declared
	// value: `const`/`let` are in the temporal dead zone and `var` would be
	// undefined. Either way the value is not statically known here.
	if b.declNode != nil && b.declPos != 0 && ref.StartByte() >= b.declPos {
		return e.evalSN(b.declNode)
	}
	// Retry a destructuring against its source object.
	if b.destructured && b.destructureSource != nil && b.memberKey != "" {
		if b.destructureSource.Type() == "object" {
			if v, ok := e.objectPairValue(b.destructureSource, b.memberKey); ok {
				return v
			}
		} else if v, ok := e.memberValue(b.destructureSource, b.memberKey, ref); ok {
			return v
		}
	}
	return e.unknownValue(ref)
}

// propertyValue resolves `obj.key` for an object binding, honouring both
// property assignments (obj.key = value) and whole-object reassignments
// (obj = {...}) that precede the reference.
func (t *bindingTable) propertyValue(b *binding, key string, ref, refFn *sitter.Node) (StaticValue, bool) {
	e := t.e
	refByte := ref.StartByte()

	// Walk declarations and whole-object reassignments up to the reference,
	// tracking the object value in force. A property assignment applies only
	// to the object that is current at its position.
	type event struct {
		pos    uint32
		value  *sitter.Node
		branch bool
		isMut  bool
	}
	objectValue := b.declNode
	var events []event
	for _, f := range b.flow {
		if f.pos >= refByte || f.fnScope != refFn || f.property != "" {
			continue
		}
		events = append(events, event{pos: f.pos, value: f.value, branch: f.branches})
	}
	for _, f := range b.mutate {
		if f.pos >= refByte || f.fnScope != refFn || f.property != key {
			continue
		}
		events = append(events, event{pos: f.pos, value: f.value, branch: f.branches, isMut: true})
	}
	if len(events) == 0 {
		v, ok := e.objectPropertyFromLiteral(objectValue, key)
		return v, ok
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].pos < events[j].pos })

	curr, found := e.objectPropertyFromLiteral(objectValue, key)
	known := found
	var alts []StaticValue
	for _, ev := range events {
		if !ev.isMut {
			// A whole-object reassignment replaces both the object and the
			// property value derived from it.
			objectValue = ev.value
			curr, found = e.objectPropertyFromLiteral(objectValue, key)
			known = found
			alts = alts[:0]
			continue
		}
		v := e.evalSN(ev.value)
		if ev.branch {
			alts = append(alts, v)
			continue
		}
		curr = v
		known = true
		alts = alts[:0]
	}
	if !known && len(alts) == 0 {
		return StaticValue{}, false
	}
	if len(alts) > 0 {
		curr = withAlternatives(curr, alts)
	}
	return sanitizeAlternatives(curr), true
}

func firstNamedChildOfType(n *sitter.Node, typ string) *sitter.Node {
	if n == nil {
		return nil
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		c := n.NamedChild(i)
		if c.Type() == typ {
			return c
		}
	}
	return nil
}
