package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/contract"
)

// canonicalFinding es el hallazgo que emite una tool: trae el CWE, las tags
// y el vector de CVSS que el LLM NO tiene que transcribir.
func canonicalFinding() contract.Finding {
	return contract.Finding{
		ID:          "finding_tool_1",
		Source:      "web.scan",
		SourceTool:  "web.scan",
		RuleID:      "nuclei:exposed-env-file",
		Title:       "Exposed environment file",
		Severity:    contract.SeverityHigh,
		Confidence:  contract.ConfidenceConfirmed,
		CWE:         "CWE-200",
		OWASP:       []string{"A05:2021"},
		Target:      "https://example.com/.env",
		Vector:      "https://example.com/.env",
		Evidence:    map[string]any{"template": "exposed-env-file", "marker": true},
		Remediation: "Remove the file from the web root",
		CVSS:        &contract.CVSSVector{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"},
		Tags:        []string{"secret-exposure", ".env"},
		References:  []string{"https://example.com/advisory"},
	}
}

func SaveFindingTo(dir string, f contract.Finding, sessionID, campaign, agent string) (string, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "", fmt.Errorf("missing session id: the finding would never reach the Argos panels")
	}
	if !contract.IsSessionID(sessionID) {
		return "", fmt.Errorf("invalid session id %q: it must start with %q", sessionID, contract.SessionIDPrefix)
	}
	rec := contract.Record{
		Kind:           "finding",
		Agent:          agent,
		Session:        campaign,
		ArgosSessionID: sessionID,
		ID:             f.ID,
		Source:         f.Source,
		Title:          f.Title,
		Target:         f.Target,
		Severity:       f.Severity,
		Status:         contract.DefaultStatus,
		Confidence:     f.Confidence,
		CWE:            f.CWE,
		RuleID:         f.RuleID,
		OWASP:          f.OWASP,
		Vector:         f.Vector,
		Remediation:    f.Remediation,
		CVSS:           f.CVSS,
		Tags:           f.Tags,
		References:     f.References,
		SourceTool:     f.SourceTool,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}
	if len(f.Evidence) > 0 {
		rec.Evidence = f.Evidence
	}
	return contract.WriteRecord(dir, rec)
}

// TestSaveFindingWritesTheCanonicalShape verifica el round-trip: lo que la
// tool produce llega al disco con TODOS los campos del contrato, más el
// `kind` y el `argos_session_id` que el reconciliador necesita para saber
// qué es un hallazgo y a qué sesión pertenece.
func TestSaveFindingWritesTheCanonicalShape(t *testing.T) {
	dir := t.TempDir()

	path, err := SaveFindingTo(dir, canonicalFinding(), "ses_test_canonical_01", "example-target-2026-08-14", "argos-web")
	if err != nil {
		t.Fatalf("SaveFindingTo failed: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("path = %q, want it inside %q", path, dir)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read the persisted finding: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("cannot decode the persisted finding: %v", err)
	}

	if record["kind"] != "finding" {
		t.Errorf("kind = %v, want finding (sin esto el reconciliador lo descarta)", record["kind"])
	}
	if record["argos_session_id"] != "ses_test_canonical_01" {
		t.Errorf("argos_session_id = %v, want ses_test_canonical_01", record["argos_session_id"])
	}
	if record["session"] != "example-target-2026-08-14" {
		t.Errorf("session = %v, want the campaign label", record["session"])
	}
	if record["agent"] != "argos-web" {
		t.Errorf("agent = %v, want argos-web", record["agent"])
	}
	if record["status"] != contract.DefaultStatus {
		t.Errorf("status = %v, want %s", record["status"], contract.DefaultStatus)
	}
	if record["title"] != "Exposed environment file" {
		t.Errorf("title = %v", record["title"])
	}
	if record["severity"] != contract.SeverityHigh {
		t.Errorf("severity = %v, want high", record["severity"])
	}
	if record["confidence"] != contract.ConfidenceConfirmed {
		t.Errorf("confidence = %v, want confirmed", record["confidence"])
	}
	if record["cwe"] != "CWE-200" {
		t.Errorf("cwe = %v, want CWE-200", record["cwe"])
	}
	if record["rule_id"] != "nuclei:exposed-env-file" {
		t.Errorf("rule_id = %v", record["rule_id"])
	}
	if record["source_tool"] != "web.scan" {
		t.Errorf("source_tool = %v, want web.scan", record["source_tool"])
	}
	if record["target"] != "https://example.com/.env" {
		t.Errorf("target = %v", record["target"])
	}
	if record["vector"] != "https://example.com/.env" {
		t.Errorf("vector = %v", record["vector"])
	}
	if record["remediation"] != "Remove the file from the web root" {
		t.Errorf("remediation = %v", record["remediation"])
	}
	if _, ok := record["evidence"].(map[string]any); !ok {
		t.Errorf("evidence = %v, want the tool's evidence object", record["evidence"])
	}
	if _, ok := record["cvss"].(map[string]any); !ok {
		t.Fatalf("cvss = %v, want the base metrics object", record["cvss"])
	}
	tags, ok := record["tags"].([]any)
	if !ok || len(tags) != 2 {
		t.Fatalf("tags = %v, want the tool's tags", record["tags"])
	}
	owasp, ok := record["owasp"].([]any)
	if !ok || len(owasp) != 1 || owasp[0] != "A05:2021" {
		t.Errorf("owasp = %v", record["owasp"])
	}
	references, ok := record["references"].([]any)
	if !ok || len(references) != 1 || references[0] != "https://example.com/advisory" {
		t.Errorf("references = %v", record["references"])
	}
	if record["timestamp"] == "" {
		t.Error("timestamp is empty")
	}
}

// El store es compartido entre campañas: dos hallazgos distintos tienen que
// acabar en archivos distintos.
func TestSaveFindingUsesAUniqueFilePerFinding(t *testing.T) {
	dir := t.TempDir()

	first, err := SaveFindingTo(dir, canonicalFinding(), "ses_test_unique_01", "campaign", "argos-web")
	if err != nil {
		t.Fatalf("SaveFindingTo failed: %v", err)
	}
	second, err := SaveFindingTo(dir, contract.Finding{
		Source:     "web.scan",
		SourceTool: "web.scan",
		Title:      "Another finding",
		Severity:   contract.SeverityLow,
		Target:     "https://example.com/other",
	}, "ses_test_unique_01", "campaign", "argos-web")
	if err != nil {
		t.Fatalf("SaveFindingTo failed: %v", err)
	}
	if first == second {
		t.Errorf("both findings landed in %q", first)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read the findings dir: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("wrote %d files, want 2", len(entries))
	}
}

// Un hallazgo sin Session ID no se puede reconciliar con ninguna sesión:
// mejor un error explícito que un archivo que nadie va a leer.
func TestSaveFindingRejectsAMissingSessionID(t *testing.T) {
	dir := t.TempDir()

	if _, err := SaveFindingTo(dir, canonicalFinding(), "", "campaign", "argos-web"); err == nil {
		t.Fatal("expected an error for a missing session id")
	}
	if _, err := SaveFindingTo(dir, canonicalFinding(), "example-target-2026-08-14", "campaign", "argos-web"); err == nil {
		t.Fatal("expected an error for a session id that is not a real Argos session")
	}

	entries, err := os.ReadDir(dir)
	if err == nil && len(entries) != 0 {
		t.Errorf("a rejected save wrote %d file(s); want none", len(entries))
	}
}

// El archivo escrito tiene que ser legible por el reconciliador: los campos
// del contrato se leen con estos nombres exactos.
func TestSaveFindingIsReadableAsAStoreRecord(t *testing.T) {
	dir := t.TempDir()

	path, err := SaveFindingTo(dir, canonicalFinding(), "ses_test_readable_01", "campaign", "argos-web")
	if err != nil {
		t.Fatalf("SaveFindingTo failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read the persisted finding: %v", err)
	}
	var record Finding
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("cannot decode the persisted finding: %v", err)
	}
	if record.Kind != "finding" {
		t.Errorf("kind = %q", record.Kind)
	}
	if record.ArgosSessionID != "ses_test_readable_01" {
		t.Errorf("argos_session_id = %q", record.ArgosSessionID)
	}
	if record.CWE != "CWE-200" {
		t.Errorf("cwe = %q", record.CWE)
	}
	if record.CVSS == nil || record.CVSS.AV != "N" || record.CVSS.A != "H" {
		t.Errorf("cvss = %+v", record.CVSS)
	}
	if len(record.Tags) != 2 {
		t.Errorf("tags = %v", record.Tags)
	}
	if !strings.HasSuffix(record.Timestamp, "Z") {
		t.Errorf("timestamp = %q, want a UTC RFC3339 timestamp", record.Timestamp)
	}
}
