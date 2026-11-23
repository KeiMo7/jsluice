package jsluice

import (
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
)

// Module resolution lets a value defined in one file be used when evaluating an
// expression in another. This is what makes an address assembled from a
// constant that lives in a separate config module come out complete.
//
// Resolution is local and read-only: only files that already exist next to (or
// below) the file being analyzed are read. Nothing is executed and nothing is
// fetched over the network. A module that cannot be found is treated as
// unknown, so the referencing value keeps its placeholder.

// ModuleResolver reads sibling modules referenced by import/require. It caches
// parsed modules by absolute path so a shared config file is parsed once per
// run.
type ModuleResolver struct {
	// cache maps an absolute path to its parsed module, or to nil when the
	// file could not be read or parsed.
	cache map[string]*parsedModule
	// maxBytes bounds the size of any single file read.
	maxBytes int64
}

// parsedModule is a loaded module's syntax tree together with the evaluator
// that can evaluate expressions in it.
type parsedModule struct {
	path string
	tree *sitter.Tree
	root *sitter.Node
	src  []byte
	eval *staticEvaluator
	ex   *moduleExports
}

// NewModuleResolver returns a resolver that reads modules from the filesystem.
func NewModuleResolver() *ModuleResolver {
	return &ModuleResolver{
		cache:    make(map[string]*parsedModule),
		maxBytes: 8 * 1024 * 1024,
	}
}

// Close releases the syntax trees held by the resolver.
func (r *ModuleResolver) Close() {
	if r == nil {
		return
	}
	for _, m := range r.cache {
		if m != nil && m.tree != nil {
			m.tree.Close()
		}
	}
	r.cache = make(map[string]*parsedModule)
}

// moduleExports is the interface a module presents to its importers: the
// value bound to each exported name.
type moduleExports struct {
	// names maps an exported name to the syntax node that defines it.
	names map[string]*sitter.Node
	// namespace exports (module.exports = {...}, export default {...}).
	defaultValue *sitter.Node
	// starFrom names modules re-exported wholesale (`export * from "m"`).
	starFrom []string
	// reExports records names re-exported from another module
	// (`export { a } from "m"`).
	reExports []reExport
	// evaluator that owns the nodes in this interface.
	eval *staticEvaluator
}

// importDepthLimit bounds how many modules a single resolution may traverse,
// so a cycle of re-exports cannot expand without end.
const importDepthLimit = 8

// resolveImport evaluates an imported binding at a reference site.
func (e *staticEvaluator) resolveImport(ref *sitter.Node, ref2 importRef) StaticValue {
	return e.resolveModuleName(ref, ref2.module, ref2.name, ref2.isNamespace, 0)
}

// importMemberValue resolves member access on a namespace import, reporting
// whether the name could be resolved at all.
func (e *staticEvaluator) importMemberValue(imp importRef, key string, ref *sitter.Node) (StaticValue, bool) {
	if !imp.isNamespace {
		return StaticValue{}, false
	}
	return e.moduleExportValue(imp.module, key, ref, 0)
}

// moduleExportValue resolves an exported name, reporting success.
func (e *staticEvaluator) moduleExportValue(module, name string, ref *sitter.Node, depth int) (StaticValue, bool) {
	if e.resolver == nil || depth > importDepthLimit {
		return StaticValue{}, false
	}
	spec, ok := splitModuleSpecifier(module)
	if !ok {
		return StaticValue{}, false
	}
	pm := e.resolver.load(filepath.Join(filepath.Dir(e.file), spec))
	if pm == nil {
		return StaticValue{}, false
	}
	v := pm.exportValue(name, false, depth+1)
	return v, true
}

// resolveModuleName loads the module named by module (relative to this file),
// then evaluates the value it exports under name.
func (e *staticEvaluator) resolveModuleName(ref *sitter.Node, module, name string, namespace bool, depth int) StaticValue {
	if e.resolver == nil || module == "" || depth > importDepthLimit {
		return e.unknownValue(ref)
	}
	spec, ok := splitModuleSpecifier(module)
	if !ok {
		return e.unknownValue(ref)
	}
	pm := e.resolver.load(filepath.Join(filepath.Dir(e.file), spec))
	if pm == nil {
		return e.unknownValue(ref)
	}
	return pm.exportValue(name, namespace, depth+1)
}

// splitModuleSpecifier normalises a module specifier, rejecting absolute URLs
// and bare package names that are not resolvable from disk here.
func splitModuleSpecifier(spec string) (string, bool) {
	if spec == "" {
		return "", false
	}
	// Only relative or absolute filesystem paths are followed. Bare package
	// names ("lodash") and URLs are not resolvable without executing the
	// module system, so they stay unknown.
	if strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://") ||
		strings.HasPrefix(spec, "//") {
		return "", false
	}
	if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") &&
		!strings.HasPrefix(spec, "/") {
		return "", false
	}
	return spec, true
}

// load parses the module at path (trying common extensions and directory
// index files) and caches the result. It returns nil when the module cannot be
// read or does not parse.
func (r *ModuleResolver) load(path string) *parsedModule {
	candidates := moduleCandidates(path)
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if pm, ok := r.cache[abs]; ok {
			return pm
		}
		pm := r.parseFile(abs)
		r.cache[abs] = pm
		if pm != nil {
			return pm
		}
	}
	return nil
}

// moduleCandidates lists the files that could satisfy a specifier, in the
// order Node's resolver would try them.
func moduleCandidates(path string) []string {
	candidates := []string{path}
	for _, ext := range []string{".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"} {
		candidates = append(candidates, path+ext)
	}
	for _, index := range []string{"index.js", "index.mjs", "index.cjs"} {
		candidates = append(candidates, filepath.Join(path, index))
	}
	return candidates
}

// parseFile reads and parses one module. Directories and unreadable files
// yield nil.
func (r *ModuleResolver) parseFile(path string) *parsedModule {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil
	}
	if info.Size() > r.maxBytes {
		return nil
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(javascript.GetLanguage())
	tree := parser.Parse(nil, src)
	if tree == nil {
		return nil
	}
	root := tree.RootNode()
	if root == nil {
		tree.Close()
		return nil
	}
	if root.HasError() {
		// A module that does not parse cleanly could still be partially
		// usable, but its export map would be unreliable. Treat it as
		// unreadable so the reference keeps its placeholder.
		tree.Close()
		return nil
	}

	e := &staticEvaluator{
		source: src,
		root:   root,
		file:   path,
		memo:   make(map[nodeKey]StaticValue),
	}
	e.bindings = newBindingTable(e, root)
	e.resolver = r
	pm := &parsedModule{path: path, tree: tree, root: root, src: src, eval: e}
	pm.ex = pm.buildExports()
	return pm
}

// buildExports computes the module's export interface.
func (pm *parsedModule) buildExports() *moduleExports {
	ex := &moduleExports{names: make(map[string]*sitter.Node), eval: pm.eval}
	root := pm.root
	for i := 0; i < int(root.NamedChildCount()); i++ {
		n := root.NamedChild(i)
		switch n.Type() {
		case "export_statement":
			pm.collectExportStatement(ex, n)
		case "expression_statement":
			// module.exports = {...} / exports.name = ...
			pm.collectCommonJSExport(ex, firstNamedChild(n))
		}
	}
	return ex
}

// collectExportStatement handles export declarations and clauses.
func (pm *parsedModule) collectExportStatement(ex *moduleExports, n *sitter.Node) {
	decl := n.ChildByFieldName("declaration")
	if decl != nil {
		pm.collectExportedDeclaration(ex, decl)
		return
	}
	if value := n.ChildByFieldName("value"); value != nil {
		// export default <value>
		ex.defaultValue = value
		return
	}
	// export { a, b as c } [from "m"] ; export * from "m"
	if src := n.ChildByFieldName("source"); src != nil {
		module := decodeEscapes(stringBody(src.Content(pm.eval.source)))
		if firstNamedChildOfType(n, "export_clause") == nil {
			// export * from "m" (possibly with an ERROR "as ns"
			// segment this grammar produces); treat as a
			// star re-export.
			ex.starFrom = append(ex.starFrom, module)
			return
		}
		// Re-exports from another module are resolved lazily by name.
		clause := firstNamedChildOfType(n, "export_clause")
		for j := 0; j < int(clause.NamedChildCount()); j++ {
			spec := clause.NamedChild(j)
			if spec.Type() != "export_specifier" {
				continue
			}
			nameNode := spec.ChildByFieldName("name")
			if nameNode == nil {
				continue
			}
			alias := spec.ChildByFieldName("alias")
			exported := nameNode.Content(pm.eval.source)
			if alias != nil {
				exported = alias.Content(pm.eval.source)
			}
			ex.reExports = append(ex.reExports, reExport{
				exported: exported,
				module:   module,
				name:     nameNode.Content(pm.eval.source),
			})
		}
		return
	}

	clause := firstNamedChildOfType(n, "export_clause")
	if clause == nil {
		return
	}
	for j := 0; j < int(clause.NamedChildCount()); j++ {
		spec := clause.NamedChild(j)
		if spec.Type() != "export_specifier" {
			continue
		}
		nameNode := spec.ChildByFieldName("name")
		if nameNode == nil {
			continue
		}
		alias := spec.ChildByFieldName("alias")
		exported := nameNode.Content(pm.eval.source)
		if alias != nil {
			exported = alias.Content(pm.eval.source)
		}
		ex.names[exported] = nameNode
	}
}

// collectExportedDeclaration records names introduced by `export const ...`
// and `export function ...`.
func (pm *parsedModule) collectExportedDeclaration(ex *moduleExports, decl *sitter.Node) {
	switch decl.Type() {
	case "lexical_declaration", "variable_declaration":
		for i := 0; i < int(decl.NamedChildCount()); i++ {
			item := decl.NamedChild(i)
			if item.Type() != "variable_declarator" {
				continue
			}
			name := item.ChildByFieldName("name")
			if name == nil || name.Type() != "identifier" {
				continue
			}
			ex.names[name.Content(pm.eval.source)] = item.ChildByFieldName("value")
		}
	case "function_declaration", "class_declaration", "generator_function_declaration":
		if name := decl.ChildByFieldName("name"); name != nil {
			ex.names[name.Content(pm.eval.source)] = decl
		}
	}
}

// collectCommonJSExport records `module.exports = {...}` and `exports.x = ...`.
func (pm *parsedModule) collectCommonJSExport(ex *moduleExports, expr *sitter.Node) {
	if expr == nil || expr.Type() != "assignment_expression" {
		return
	}
	left := expr.ChildByFieldName("left")
	right := expr.ChildByFieldName("right")
	if left == nil || right == nil {
		return
	}
	key, ok := pm.eval.staticPropertyKey(left)
	if !ok {
		return
	}
	obj := left.ChildByFieldName("object")
	if obj == nil {
		return
	}
	objName := obj.Content(pm.eval.source)
	if objName == "module" && key == "exports" {
		ex.defaultValue = right
		return
	}
	if objName == "exports" || (obj.Type() == "member_expression" &&
		objName == "module.exports") {
		ex.names[key] = right
	}
}

// reExport records one name re-exported from another module.
type reExport struct {
	exported string
	module   string
	name     string
}

// exportValue evaluates the value exported under name.
func (pm *parsedModule) exportValue(name string, namespace bool, depth int) StaticValue {
	e := pm.eval
	if namespace {
		return e.unknownValue(nil)
	}
	if pm.ex != nil {
		if node, ok := pm.ex.names[name]; ok && node != nil {
			return e.evalSN(node)
		}
		for _, re := range pm.ex.reExports {
			if re.exported == name {
				return e.resolveModuleName(nil, re.module, re.name, false, depth)
			}
		}
		if name == "default" && pm.ex.defaultValue != nil {
			return e.evalSN(pm.ex.defaultValue)
		}
		// CommonJS: module.exports = {...}; the exported name is a member
		// of that object literal.
		if pm.ex.defaultValue != nil {
			if v, ok := e.objectPairValue(pm.ex.defaultValue, name); ok {
				return v
			}
		}
		for _, mod := range pm.ex.starFrom {
			if v := e.resolveModuleName(nil, mod, name, false, depth); v.FullyKnown() {
				return v
			}
		}
	}
	return e.unknownValue(nil)
}
