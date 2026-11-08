package tools

import (
	"strings"

	"github.com/iwiels/ARGOS/argos-bin/internal/contract"
)

// El contrato canónico vive en internal/contract: lo comparten los scanners
// web (que producen los hallazgos) y el orquestador (que los persiste en el
// store de memoria). Acá solo quedan los alias y los atajos que el resto del
// paquete ya usa — el struct y sus helpers tienen una sola definición.
type (
	// Finding is the canonical contract between the Go security tools and the
	// Argos backend. It must stay in sync with
	// packages/core/src/security/contract.ts (verified by the ARG-053 contract
	// test).
	Finding = contract.Finding
	// CVSSVector carries the eight base metrics of CVSS v3.1.
	CVSSVector = contract.CVSSVector
)

// Canonical severities. The backend normalizes every incoming finding to this
// closed set, so the tools emit it directly instead of leaving the mapping to
// the transcription step.
const (
	SeverityCritical = contract.SeverityCritical
	SeverityHigh     = contract.SeverityHigh
	SeverityMedium   = contract.SeverityMedium
	SeverityLow      = contract.SeverityLow
	SeverityInfo     = contract.SeverityInfo
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
	ConfidenceConfirmed = contract.ConfidenceConfirmed
	ConfidenceProbable  = contract.ConfidenceProbable
	ConfidencePossible  = contract.ConfidencePossible
)

// findingsToMaps converts a finding slice into the map slice the MCP tools
// publish under "findings".
func findingsToMaps(fs []Finding) []map[string]any {
	return contract.FindingsToMaps(fs)
}

// normalizeSeverity maps the severity vocabularies the scanners use (English
// variants, Spanish variants) onto the canonical closed set. Unknown values
// degrade to "info" instead of inventing a level.
func normalizeSeverity(s string) string {
	return contract.NormalizeSeverity(s)
}

// normalizeConfidence keeps the confidence inside the closed vocabulary.
func normalizeConfidence(s string) string {
	return contract.NormalizeConfidence(s)
}

// parseCvssVectorString extracts the eight base metrics out of a CVSS vector
// string ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
//
// It returns nil unless every base metric is present and valid: a partial
// vector would force the backend to guess the missing metrics, and an invented
// score is worse than no score.
func parseCvssVectorString(raw string) *CVSSVector {
	return contract.ParseCvssVectorString(raw)
}

// dedupeTags removes repeated tags while preserving the emission order.
func dedupeTags(tags []string) []string {
	return contract.DedupeTags(tags)
}

// normalizeCWE accepts the "CWE-89", "cwe-89" and bare "89" spellings and
// returns the canonical "CWE-89" form. It returns "" when the input does not
// parse — an invented CWE is worse than a missing one.
func normalizeCWE(raw string) string {
	return contract.NormalizeCWE(raw)
}

// stringList coerces a JSON value that may be a string or an array of strings
// into a slice of non-empty strings.
func stringList(value any) []string {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{strings.TrimSpace(typed)}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return nil
}

// mapString reads a string entry out of a decoded JSON object.
func mapString(source map[string]any, key string) string {
	value, _ := source[key].(string)
	return strings.TrimSpace(value)
}
