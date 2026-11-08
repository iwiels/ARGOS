// Package contract define el contrato canónico de un hallazgo de seguridad:
// la forma que cruza la frontera entre los scanners (los binarios Go de
// argos-bin) y el backend de Argos.
//
// El struct Go y las interfaces de packages/core/src/security/contract.ts
// tienen que mantenerse en sync (los compara el test de contrato ARG-053).
//
// Vive en internal/ para que los dos consumidores lo compartan sin
// importarse entre sí: cmd/web/tools (los scanners web, que producen los
// hallazgos) y cmd/orquestador/tools (el store de memoria, que los
// persiste). Importar cmd/web/tools desde el orquestador ataría el binario
// del orquestador a todo el stack web (scanner, sandbox, colector OOB) por
// un simple struct.
package contract

import "strings"

// Canonical severities. The backend normalizes every incoming finding to this
// closed set, so the tools emit it directly instead of leaving the mapping to
// the transcription step.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Canonical confidences.
//
//	confirmed — the tool asserted the condition deterministically
//	probable  — heuristic detection backed by captured evidence
//	possible  — exposure or missing control, no impact demonstrated
//
// A tool must never claim "confirmed" without a deterministic confirmation of
// its own; the compliance and ATT&CK engines treat confidence as a signal.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceProbable  = "probable"
	ConfidencePossible  = "possible"
)

// SessionIDPrefix es el prefijo de un Session ID real de Argos Desktop.
//
// El store de memoria es compartido entre campañas: el campo `session` es una
// etiqueta de campaña legible y NO identifica una sesión. El backend
// reconcilia comparando `argos_session_id` de forma exacta (ver
// packages/core/src/security/agent-findings-reconcile.ts), así que un valor
// que no lleva este prefijo nunca llegaría al panel.
const SessionIDPrefix = "ses_"

// Finding is the canonical contract between the Go security tools and the
// Argos backend. It must stay in sync with
// packages/core/src/security/contract.ts (verified by the ARG-053 contract
// test).
//
// The fields that drive the deterministic engines are SourceTool, Tags, CWE
// and Vector: compliance (packages/core/src/compliance/derive.ts) and MITRE
// ATT&CK (packages/core/src/threat-intel/attack.ts) match on those, so a
// finding without them is invisible to the scoring pipeline.
type Finding struct {
	ID          string         `json:"id,omitempty"`
	Source      string         `json:"source"`                // "web.scan"
	SourceTool  string         `json:"source_tool,omitempty"` // "web.sqli" (canonico)
	RuleID      string         `json:"rule_id,omitempty"`     // "nuclei:exposed-env-file"
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`             // critical|high|medium|low|info
	Confidence  string         `json:"confidence,omitempty"` // confirmed|probable|possible
	CWE         string         `json:"cwe,omitempty"`        // "CWE-89"
	OWASP       []string       `json:"owasp,omitempty"`      // ["A03:2021"]
	Target      string         `json:"target"`
	Vector      string         `json:"vector,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	CVSS        *CVSSVector    `json:"cvss,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	References  []string       `json:"references,omitempty"`
}

// CVSSVector carries the eight base metrics of CVSS v3.1. The backend scores
// the vector deterministically (packages/core/src/security/cvss.ts), so a tool
// only declares the metrics it observed — never the score.
type CVSSVector struct {
	AV string `json:"AV"`
	AC string `json:"AC"`
	PR string `json:"PR"`
	UI string `json:"UI"`
	S  string `json:"S"`
	C  string `json:"C"`
	I  string `json:"I"`
	A  string `json:"A"`
}

// ToMap serializes the base metrics into the plain map shape of the contract.
func (v CVSSVector) ToMap() map[string]any {
	return map[string]any{
		"AV": v.AV,
		"AC": v.AC,
		"PR": v.PR,
		"UI": v.UI,
		"S":  v.S,
		"C":  v.C,
		"I":  v.I,
		"A":  v.A,
	}
}

// ToMap serializes the finding into the plain map the MCP tools return. The
// keys mirror the JSON tags exactly: empty optional fields are omitted so the
// wire shape stays stable for the transcription step.
func (f Finding) ToMap() map[string]any {
	m := map[string]any{
		"source":   f.Source,
		"title":    f.Title,
		"severity": f.Severity,
		"target":   f.Target,
	}
	if f.ID != "" {
		m["id"] = f.ID
	}
	if f.SourceTool != "" {
		m["source_tool"] = f.SourceTool
	}
	if f.RuleID != "" {
		m["rule_id"] = f.RuleID
	}
	if f.Confidence != "" {
		m["confidence"] = f.Confidence
	}
	if f.CWE != "" {
		m["cwe"] = f.CWE
	}
	if len(f.OWASP) > 0 {
		m["owasp"] = f.OWASP
	}
	if f.Vector != "" {
		m["vector"] = f.Vector
	}
	if len(f.Evidence) > 0 {
		m["evidence"] = f.Evidence
	}
	if f.Remediation != "" {
		m["remediation"] = f.Remediation
	}
	if f.CVSS != nil {
		m["cvss"] = f.CVSS.ToMap()
	}
	if len(f.Tags) > 0 {
		m["tags"] = f.Tags
	}
	if len(f.References) > 0 {
		m["references"] = f.References
	}
	return m
}

// FindingsToMaps converts a finding slice into the map slice the MCP tools
// publish under "findings".
func FindingsToMaps(fs []Finding) []map[string]any {
	out := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ToMap())
	}
	return out
}

// NormalizeSeverity maps the severity vocabularies the scanners use (English
// variants, Spanish variants) onto the canonical closed set. Unknown values
// degrade to "info" instead of inventing a level.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit", "critico", "crítico":
		return SeverityCritical
	case "high", "alto", "alta":
		return SeverityHigh
	case "medium", "medio", "media", "moderate":
		return SeverityMedium
	case "low", "bajo", "baja":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// NormalizeConfidence keeps the confidence inside the closed vocabulary.
func NormalizeConfidence(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case ConfidenceConfirmed:
		return ConfidenceConfirmed
	case ConfidenceProbable:
		return ConfidenceProbable
	default:
		return ConfidencePossible
	}
}

// cvssBaseMetrics lists the accepted values for every CVSS v3.1 base metric.
var cvssBaseMetrics = map[string][]string{
	"AV": {"N", "A", "L", "P"},
	"AC": {"L", "H"},
	"PR": {"N", "L", "H"},
	"UI": {"N", "R"},
	"S":  {"U", "C"},
	"C":  {"N", "L", "H"},
	"I":  {"N", "L", "H"},
	"A":  {"N", "L", "H"},
}

// ParseCvssVectorString extracts the eight base metrics out of a CVSS vector
// string ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
//
// It returns nil unless every base metric is present and valid: a partial
// vector would force the backend to guess the missing metrics, and an invented
// score is worse than no score.
func ParseCvssVectorString(raw string) *CVSSVector {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(strings.ToUpper(raw), "CVSS:") {
		return nil
	}
	values := map[string]string{}
	for _, part := range strings.Split(raw, "/") {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		key = strings.ToUpper(strings.TrimSpace(key))
		allowed, isBase := cvssBaseMetrics[key]
		if !isBase {
			continue
		}
		value = strings.ToUpper(strings.TrimSpace(value))
		if !containsString(allowed, value) {
			return nil
		}
		values[key] = value
	}
	if len(values) != len(cvssBaseMetrics) {
		return nil
	}
	return &CVSSVector{
		AV: values["AV"],
		AC: values["AC"],
		PR: values["PR"],
		UI: values["UI"],
		S:  values["S"],
		C:  values["C"],
		I:  values["I"],
		A:  values["A"],
	}
}

// containsString reports whether the slice holds the value.
func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// DedupeTags removes repeated tags while preserving the emission order.
func DedupeTags(tags []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizeCWE accepts the "CWE-89", "cwe-89" and bare "89" spellings and
// returns the canonical "CWE-89" form. It returns "" when the input does not
// parse — an invented CWE is worse than a missing one.
func NormalizeCWE(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	upper := strings.ToUpper(trimmed)
	digits := upper
	if strings.HasPrefix(upper, "CWE") {
		digits = strings.TrimLeft(upper[3:], "-_ ")
	}
	// No published CWE id has more than four digits; anything longer is noise.
	if digits == "" || len(digits) > 6 {
		return ""
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return "CWE-" + digits
}

// IsSessionID reports whether the value looks like a real Argos Session ID.
//
// The check is a prefix, no un descubrimiento: un Session ID inventado
// produce un archivo que se guarda bien pero que el panel nunca ve.
func IsSessionID(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), SessionIDPrefix)
}
