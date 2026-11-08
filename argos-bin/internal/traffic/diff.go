package traffic

import (
	"fmt"
	"strings"
)

// HeaderChange describes a header that appeared, disappeared or changed
// between two exchanges.
type HeaderChange struct {
	Name string `json:"name"`
	A    string `json:"a"`
	B    string `json:"b"`
}

// DiffResult is the structural difference between two exchanges.
//
// Es la respuesta de `web.compare`: el auditor compara la respuesta original
// contra la reenviada y lee qué cambió sin tener que eyeballar dos dumps.
type DiffResult struct {
	AID              string         `json:"a_id"`
	BID              string         `json:"b_id"`
	Identical        bool           `json:"identical"`
	StatusChanged    bool           `json:"status_changed"`
	StatusA          int            `json:"status_a"`
	StatusB          int            `json:"status_b"`
	HeadersAdded     []HeaderChange `json:"headers_added"`
	HeadersRemoved   []HeaderChange `json:"headers_removed"`
	HeadersChanged   []HeaderChange `json:"headers_changed"`
	BodyChanged      bool           `json:"body_changed"`
	BodySHA256A      string         `json:"body_sha256_a"`
	BodySHA256B      string         `json:"body_sha256_b"`
	BodyDiff         string         `json:"body_diff"`
	BodyLinesAdded   int            `json:"body_lines_added"`
	BodyLinesRemoved int            `json:"body_lines_removed"`
}

// DiffExchanges compares two exchanges.
func DiffExchanges(a, b Exchange) DiffResult {
	result := DiffResult{
		AID:         a.ID,
		BID:         b.ID,
		StatusA:     a.Status,
		StatusB:     b.Status,
		BodySHA256A: BodyHash(a.ResponseBody),
		BodySHA256B: BodyHash(b.ResponseBody),
	}
	result.StatusChanged = a.Status != b.Status
	result.HeadersAdded, result.HeadersRemoved, result.HeadersChanged = diffHeaders(a.ResponseHeaders, b.ResponseHeaders)
	result.BodyChanged = result.BodySHA256A != result.BodySHA256B
	if result.BodyChanged {
		result.BodyDiff = UnifiedDiff("a", "b", a.ResponseBody, b.ResponseBody)
		result.BodyLinesAdded, result.BodyLinesRemoved = countDiffLines(result.BodyDiff)
	}
	result.Identical = !result.StatusChanged &&
		len(result.HeadersAdded) == 0 &&
		len(result.HeadersRemoved) == 0 &&
		len(result.HeadersChanged) == 0 &&
		!result.BodyChanged
	return result
}

// diffHeaders compares two header sets by name (case-insensitive).
func diffHeaders(a, b map[string][]string) (added, removed, changed []HeaderChange) {
	namesA := headerNames(a)
	namesB := headerNames(b)
	for name := range namesA {
		valueA := headerValue(a, name)
		if _, ok := namesB[name]; !ok {
			removed = append(removed, HeaderChange{Name: name, A: valueA})
			continue
		}
		valueB := headerValue(b, name)
		if valueA != valueB {
			changed = append(changed, HeaderChange{Name: name, A: valueA, B: valueB})
		}
	}
	for name := range namesB {
		if _, ok := namesA[name]; !ok {
			added = append(added, HeaderChange{Name: name, B: headerValue(b, name)})
		}
	}
	return added, removed, changed
}

// headerNames returns the lowercased header names of a set.
func headerNames(headers map[string][]string) map[string]bool {
	out := make(map[string]bool, len(headers))
	for name := range headers {
		out[strings.ToLower(strings.TrimSpace(name))] = true
	}
	return out
}

// headerValue joins the values of a header into a single comparable string.
func headerValue(headers map[string][]string, lowerName string) string {
	for name, values := range headers {
		if strings.ToLower(strings.TrimSpace(name)) != lowerName {
			continue
		}
		return strings.Join(values, ", ")
	}
	return ""
}

// diffCellBudget caps the LCS matrix: dos cuerpos de 2000 líneas ya son un
// dump, y el diff de ese caso se degrada a "los cuerpos difieren" en vez de
// quemarse la CPU.
const diffCellBudget = 4_000_000

// diffContextLines is how many lines of context each hunk carries.
const diffContextLines = 3

// UnifiedDiff renders the difference between two bodies in the unified diff
// format (`--- a`, `+++ b`, `@@ -l,s +l,s @@`).
func UnifiedDiff(nameA, nameB string, a, b []byte) string {
	linesA := splitLines(a)
	linesB := splitLines(b)
	ops := diffOps(linesA, linesB)
	if ops == nil {
		// Cuerpo demasiado grande para un diff línea a línea: el hash ya
		// dice que son distintos.
		return fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ bodies differ (too large to diff line by line) @@\n", nameA, nameB)
	}
	hunks := buildHunks(ops, diffContextLines)
	if len(hunks) == 0 {
		return ""
	}
	var out strings.Builder
	fmt.Fprintf(&out, "--- a/%s\n", nameA)
	fmt.Fprintf(&out, "+++ b/%s\n", nameB)
	for _, hunk := range hunks {
		hunk.write(&out)
	}
	return out.String()
}

// splitLines splits a body into lines, dropping the trailing empty line that
// a final "\n" produces.
func splitLines(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

type opKind int

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

type editOp struct {
	kind opKind
	text string
}

// diffOps computes the line-level edit script between two line slices.
//
// Devuelve nil cuando el cuerpo es demasiado grande para la matriz LCS: en
// ese caso el diff se degrada a un resumen, nunca a un cuelgue.
func diffOps(a, b []string) []editOp {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	if len(a)*len(b) > diffCellBudget {
		return nil
	}
	n, m := len(a), len(b)
	table := make([][]int, n+1)
	for i := range table {
		table[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
				continue
			}
			if table[i+1][j] >= table[i][j+1] {
				table[i][j] = table[i+1][j]
			} else {
				table[i][j] = table[i][j+1]
			}
		}
	}

	ops := make([]editOp, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, editOp{kind: opEqual, text: a[i]})
			i++
			j++
		case table[i+1][j] >= table[i][j+1]:
			ops = append(ops, editOp{kind: opDelete, text: a[i]})
			i++
		default:
			ops = append(ops, editOp{kind: opInsert, text: b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, editOp{kind: opDelete, text: a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, editOp{kind: opInsert, text: b[j]})
	}
	return ops
}

type diffHunk struct {
	aStart int
	aCount int
	bStart int
	bCount int
	lines  []string
}

// buildHunks groups the edit script into unified-diff hunks.
//
// Los clusters de cambios se separan cuando hay más de 2*context líneas
// iguales en medio: dos bloques lejos no comparten hunk.
func buildHunks(ops []editOp, context int) []diffHunk {
	changed := make([]int, 0, len(ops))
	for idx, op := range ops {
		if op.kind != opEqual {
			changed = append(changed, idx)
		}
	}
	if len(changed) == 0 {
		return nil
	}

	aBefore := make([]int, len(ops)+1)
	bBefore := make([]int, len(ops)+1)
	for idx, op := range ops {
		aBefore[idx+1] = aBefore[idx]
		bBefore[idx+1] = bBefore[idx]
		switch op.kind {
		case opEqual:
			aBefore[idx+1]++
			bBefore[idx+1]++
		case opDelete:
			aBefore[idx+1]++
		case opInsert:
			bBefore[idx+1]++
		}
	}

	type cluster struct{ from, to int }
	clusters := make([]cluster, 0, len(changed))
	for _, idx := range changed {
		if len(clusters) > 0 && idx-clusters[len(clusters)-1].to <= 2*context {
			clusters[len(clusters)-1].to = idx
			continue
		}
		clusters = append(clusters, cluster{from: idx, to: idx})
	}

	hunks := make([]diffHunk, 0, len(clusters))
	for _, c := range clusters {
		from := c.from - context
		if from < 0 {
			from = 0
		}
		to := c.to + context
		if to >= len(ops) {
			to = len(ops) - 1
		}
		hunk := diffHunk{
			aStart: aBefore[from] + 1,
			aCount: aBefore[to+1] - aBefore[from],
			bStart: bBefore[from] + 1,
			bCount: bBefore[to+1] - bBefore[from],
		}
		if hunk.aCount == 0 {
			hunk.aStart = aBefore[from]
		}
		if hunk.bCount == 0 {
			hunk.bStart = bBefore[from]
		}
		for idx := from; idx <= to; idx++ {
			hunk.lines = append(hunk.lines, renderOp(ops[idx]))
		}
		hunks = append(hunks, hunk)
	}
	return hunks
}

// write renders a hunk in unified-diff notation.
func (h diffHunk) write(out *strings.Builder) {
	fmt.Fprintf(out, "@@ -%d,%d +%d,%d @@\n", h.aStart, h.aCount, h.bStart, h.bCount)
	for _, line := range h.lines {
		out.WriteString(line)
		out.WriteString("\n")
	}
}

// renderOp renders one line of the edit script in unified-diff notation.
func renderOp(op editOp) string {
	switch op.kind {
	case opDelete:
		return "-" + op.text
	case opInsert:
		return "+" + op.text
	default:
		return " " + op.text
	}
}

// countDiffLines counts the added and removed lines of a unified diff.
func countDiffLines(diff string) (added, removed int) {
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"):
			continue
		case strings.HasPrefix(line, "+"):
			added++
		case strings.HasPrefix(line, "-"):
			removed++
		}
	}
	return added, removed
}
