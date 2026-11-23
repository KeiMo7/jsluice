package jsluice

import (
	"sort"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// Static evaluation of JavaScript expressions.
//
// jsluice is a static analyser: it never executes the scripts it is given and
// never makes network requests on their behalf. Historically only string
// literals joined by "+" were understood, so an address assembled from
// constants was reported as a half-address with a placeholder in the middle.
// The code in this file reconstructs as much of such an expression as can be
// proven from its syntax alone and leaves a placeholder for everything else.
//
// The evaluator is deliberately conservative. A value is only merged when it
// is statically certain; anything that depends on the runtime environment, on
// the contents of a module that cannot be read, or on a value that can change
// between statements stays a placeholder. Every statically-known fragment
// keeps the exact source text and byte range it came from, plus the file it
// came from when it was imported, so a result can be traced back to the code
// that produced it.

// Evaluation budgets. Real-world JavaScript can contain deeply nested,
// self-referential, or enormous expressions. These bounds keep evaluation
// linear in the size of the input and stop it from ever producing a value
// that could blow up the output.
const (
	// maxEvalDepth is the maximum nesting depth of a single evaluation.
	// Real concatenations nest a few dozen levels at most; 256 leaves ample
	// headroom while still bounding recursive evaluation.
	maxEvalDepth = 256
	// maxEvalNodes is the maximum number of syntax nodes visited while
	// evaluating a single expression.
	maxEvalNodes = 8192
	// maxStaticValueLength is the maximum length of an evaluated value.
	// Longer results are discarded and counted rather than emitted.
	maxStaticValueLength = 16 * 1024
	// maxStaticAlternatives bounds the number of distinct values a
	// branch-dependent expression may expand to. Beyond it evaluation is
	// marked truncated instead of growing the output combinatorially.
	maxStaticAlternatives = 16
)

// placeholderSentinel marks a fragment whose value is not statically known.
// It is a string that cannot legitimately occur in decoded JavaScript source
// (the NUL bytes cannot appear in source at all), so it can never collide
// with a real value. It is rendered as ExpressionPlaceholder on output.
const placeholderSentinel = "\x00jsluice:unknown\x00"

// StaticValue is the result of conservatively evaluating a JavaScript
// expression without executing it. It is a list of fragments in source order;
// each fragment is either statically known (a decoded value plus provenance)
// or a placeholder standing in for something that could not be determined.
type StaticValue struct {
	// Parts are the fragments of the value, in order.
	Parts []StaticPart `json:"parts"`
	// Unknown reports whether any fragment could not be determined.
	Unknown bool `json:"unknown"`
	// Truncated reports whether evaluation stopped early because a budget
	// (depth, node count) was exhausted or a circular reference was hit.
	Truncated bool `json:"truncated"`
	// TruncationPoint, when non-zero, is the byte offset in the source at
	// which evaluation was cut short.
	TruncationPoint uint32 `json:"truncationPoint,omitempty"`
	// TruncationReason describes why evaluation stopped (e.g. "circular
	// reference", "depth budget exceeded").
	TruncationReason string `json:"truncationReason,omitempty"`
	// Oversize is true if the resolved value exceeded maxStaticValueLength.
	// Such a value is discarded entirely.
	Oversize bool `json:"oversize"`
	// Alternatives holds the other values the expression may take along
	// different branches. The primary Parts hold the first alternative.
	Alternatives []StaticValue `json:"alternatives,omitempty"`

	// nbytes approximates the rendered length of the value, including
	// alternatives, so oversize values are caught before they are built.
	nbytes int
}

// StaticPart is one fragment of a StaticValue.
type StaticPart struct {
	// Value is the decoded string content of the fragment, or
	// placeholderSentinel when the fragment is not statically known.
	Value string `json:"value"`
	// Source is the original, unmodified source text for the fragment,
	// including quotes and escape sequences where applicable. It lets a
	// human reviewer compare the result against the code.
	Source string `json:"source"`
	// StartByte and EndByte are the fragment's byte offsets within the
	// source file it came from. For fragments imported from another
	// module, File names that module.
	StartByte uint32 `json:"startByte"`
	EndByte   uint32 `json:"endByte"`
	// File is the path of the module the fragment came from, when it is
	// not the file being analyzed directly. Empty means the current file.
	File string `json:"file,omitempty"`
}

// IsPlaceholder reports whether the part stands for unknown source.
func (p StaticPart) IsPlaceholder() bool {
	return p.Value == placeholderSentinel
}

// String renders the value, replacing unknown fragments with
// ExpressionPlaceholder.
func (v StaticValue) String() string {
	out := &strings.Builder{}
	for _, p := range v.Parts {
		if p.IsPlaceholder() {
			out.WriteString(ExpressionPlaceholder)
			continue
		}
		out.WriteString(p.Value)
	}
	return out.String()
}

// FullyKnown reports whether the whole value was determined statically, with
// no unknown fragments, no truncation, and no competing alternatives.
func (v StaticValue) FullyKnown() bool {
	if v.Unknown || v.Truncated || v.Oversize || len(v.Alternatives) > 0 {
		return false
	}
	for _, p := range v.Parts {
		if p.IsPlaceholder() {
			return false
		}
	}
	return true
}

// HasKnownFragment reports whether at least one branch yields at least one
// statically-known non-empty fragment. This is what lets a matcher accept an
// expression such as BASE + "/login" while still rejecting something that is
// wholly runtime-dependent.
func (v StaticValue) HasKnownFragment() bool {
	if hasKnownInParts(v.Parts) {
		return true
	}
	for _, alt := range v.Alternatives {
		if hasKnownInParts(alt.Parts) {
			return true
		}
	}
	return false
}

func hasKnownInParts(parts []StaticPart) bool {
	for _, p := range parts {
		if p.IsPlaceholder() {
			continue
		}
		if p.Value != "" {
			return true
		}
	}
	return false
}

// AllStrings returns every distinct rendering this value can take, in a
// stable order with the primary value first. A fully-known value returns a
// single string; a branch-dependent value returns one string per alternative.
func (v StaticValue) AllStrings() []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(v.Alternatives)+1)
	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	add(v.String())
	for _, alt := range v.Alternatives {
		add(alt.String())
	}
	return out
}

// primaryOnly returns a shallow copy of v without its alternatives.
func (v StaticValue) primaryOnly() StaticValue {
	v.Alternatives = nil
	return v
}

// unknownValue builds a one-fragment placeholder value carrying the source
// text and position of the node it stands for.
func (e *staticEvaluator) unknownValue(n *sitter.Node) StaticValue {
	p := StaticPart{Value: placeholderSentinel}
	if n != nil {
		p.Source = n.Content(e.source)
		p.StartByte = n.StartByte()
		p.EndByte = n.EndByte()
		p.File = e.file
	}
	return StaticValue{Parts: []StaticPart{p}, Unknown: true}
}

// knownPart builds a one-fragment value from decoded text, attributing it to
// a source node. The value and its raw source are kept side by side so the
// result can be reviewed against the original code.
func (e *staticEvaluator) knownPart(n *sitter.Node, value string) StaticValue {
	if len(value) > maxStaticValueLength {
		return e.oversizeValue(n)
	}
	p := StaticPart{Value: value}
	if n != nil {
		p.Source = n.Content(e.source)
		p.StartByte = n.StartByte()
		p.EndByte = n.EndByte()
		p.File = e.file
	}
	return StaticValue{Parts: []StaticPart{p}, nbytes: len(value)}
}

// oversizeValue records and returns a discarded, too-large value.
func (e *staticEvaluator) oversizeValue(n *sitter.Node) StaticValue {
	e.oversize++
	return StaticValue{Oversize: true, Unknown: true}
}

// truncateValue records a budget/cycle stop and returns a placeholder that
// carries the reason and position.
func (e *staticEvaluator) truncateValue(n *sitter.Node, reason string) StaticValue {
	v := e.unknownValue(n)
	v.Truncated = true
	v.TruncationReason = reason
	if n != nil {
		v.TruncationPoint = n.StartByte()
	}
	return v
}

// appendValue concatenates b onto a. It never reuses either operand's backing
// array: cached values may be returned to several callers, so mutating them
// here would corrupt the memoised results.
//
// Alternatives are distributed across the concatenation, so (A|B) + "/x"
// becomes (A/x)|(B/x). The number of expanded alternatives is bounded.
func appendValue(a, b StaticValue) StaticValue {
	if len(a.Alternatives) == 0 && len(b.Alternatives) == 0 {
		return concatValues(a, b)
	}

	as := make([]StaticValue, 0, 1+len(a.Alternatives))
	as = append(as, a.primaryOnly())
	as = append(as, a.Alternatives...)
	bs := make([]StaticValue, 0, 1+len(b.Alternatives))
	bs = append(bs, b.primaryOnly())
	bs = append(bs, b.Alternatives...)

	prim := concatValues(as[0], bs[0])
	alts := make([]StaticValue, 0, len(as)*len(bs))
	truncated := false
	for i := range as {
		for j := range bs {
			if i == 0 && j == 0 {
				continue
			}
			if len(alts) >= maxStaticAlternatives {
				truncated = true
				break
			}
			alts = append(alts, concatValues(as[i], bs[j]))
		}
	}
	out := withAlternatives(prim, alts)
	if truncated {
		out.Truncated = true
		out.TruncationReason = "alternative budget exceeded"
	}
	return out
}

// concatValues joins two values without distributing alternatives.
func concatValues(a, b StaticValue) StaticValue {
	out := StaticValue{
		Unknown:          a.Unknown || b.Unknown,
		Truncated:        a.Truncated || b.Truncated,
		TruncationPoint:  a.TruncationPoint,
		TruncationReason: a.TruncationReason,
		Oversize:         a.Oversize || b.Oversize,
		nbytes:           a.nbytes + b.nbytes,
	}
	if out.TruncationPoint == 0 && b.TruncationPoint != 0 {
		out.TruncationPoint = b.TruncationPoint
		out.TruncationReason = b.TruncationReason
	}
	if out.nbytes > maxStaticValueLength {
		out.Parts = nil
		out.Oversize = true
		out.Unknown = true
		return out
	}
	out.Parts = make([]StaticPart, 0, len(a.Parts)+len(b.Parts))
	out.Parts = append(out.Parts, a.Parts...)
	out.Parts = append(out.Parts, b.Parts...)
	return out
}

// withAlternatives attaches a set of branch alternatives to a value. It always
// allocates a fresh slice so a memoised value is never mutated.
func withAlternatives(primary StaticValue, alts []StaticValue) StaticValue {
	merged := make([]StaticValue, 0, len(primary.Alternatives)+len(alts))
	merged = append(merged, primary.Alternatives...)
	merged = append(merged, alts...)
	primary.Alternatives = merged
	for _, alt := range merged {
		primary.nbytes += alt.nbytes
	}
	if primary.nbytes > maxStaticValueLength {
		primary.Parts = nil
		primary.Alternatives = nil
		primary.Oversize = true
		primary.Unknown = true
	}
	return primary
}

// sanitizeAlternatives drops alternatives equal to the primary value,
// de-duplicates the remainder, and sorts them so output never depends on
// discovery order or Go map iteration.
func sanitizeAlternatives(v StaticValue) StaticValue {
	if len(v.Alternatives) < 2 {
		return v
	}
	primary := v.String()
	seen := make(map[string]struct{}, len(v.Alternatives))
	uniq := make([]StaticValue, 0, len(v.Alternatives))
	for _, alt := range v.Alternatives {
		key := alt.String()
		if key == primary {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		uniq = append(uniq, alt)
	}
	sort.SliceStable(uniq, func(i, j int) bool {
		return uniq[i].String() < uniq[j].String()
	})
	v.Alternatives = uniq
	// Recompute the approximate size including the surviving alternatives.
	v.nbytes = 0
	for _, p := range v.Parts {
		v.nbytes += len(p.Value)
	}
	for _, alt := range uniq {
		v.nbytes += alt.nbytes
	}
	return v
}
