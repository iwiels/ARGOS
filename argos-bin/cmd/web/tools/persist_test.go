package tools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/iwiels/argos-auditor/argos-bin/internal/contract"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

// toolFinding es el hallazgo que emite una tool: el CWE, las tags y el vector
// de CVSS vienen de la tool, no de un LLM transcribiendo la salida.
func toolFinding() Finding {
	return Finding{
		ID:          "finding_web_1",
		Source:      "web.scan",
		SourceTool:  "web.scan",
		RuleID:      "nuclei:exposed-env-file",
		Title:       "Exposed environment file",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceConfirmed,
		CWE:         "CWE-200",
		OWASP:       []string{"A05:2021"},
		Target:      "https://example.com/.env",
		Vector:      "https://example.com/.env",
		Evidence:    map[string]any{"template": "exposed-env-file"},
		Remediation: "Remove the file from the web root",
		CVSS:        &CVSSVector{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"},
		Tags:        []string{"secret-exposure"},
		References:  []string{"https://example.com/advisory"},
	}
}

func TestPublishFindingsReturnsCandidatesWithoutPersistence(t *testing.T) {
	memoryDir := t.TempDir()
	env := &Env{MemoryDir: memoryDir}
	res := map[string]interface{}{}
	env.publishFindings(res, []Finding{toolFinding()})
	findings, ok := res["findings"].([]map[string]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("the response does not carry the findings: %+v", res["findings"])
	}
	if findings[0]["cwe"] != "CWE-200" {
		t.Errorf("the response lost the tool's CWE: %+v", findings[0])
	}
	if _, err := os.Stat(filepath.Join(memoryDir, "findings")); !os.IsNotExist(err) {
		t.Fatalf("candidate output created the canonical store: %v", err)
	}
}

// El E2E escribe un registro que ya contiene la decisión explícita del agente.
func TestE2EWriteStoreForTheBackend(t *testing.T) {
	dir := os.Getenv("ARGOS_E2E_STORE_DIR")
	if dir == "" {
		t.Skip("ARGOS_E2E_STORE_DIR is not set: run scripts/argos-013-e2e.ts")
	}
	sessionID := os.Getenv("ARGOS_E2E_SESSION_ID")
	if sessionID == "" {
		sessionID = "ses_agent_go_store"
	}
	record := contract.Record{
		Kind:            "finding",
		Agent:           "security-web",
		Session:         "example-target-2026-08-14",
		ArgosSessionID:  sessionID,
		Title:           "Exposed environment file",
		Target:          "https://example.com/.env",
		Severity:        "high",
		Status:          "observed",
		CWE:             "CWE-200",
		Evidence:        "The endpoint returned a private environment file containing credentials.",
		AgentAssessment: "I fetched the exact in-scope endpoint and verified that the response contains live credential values.",
		Impact:          "An unauthenticated attacker can use those credentials to access protected services.",
		Timestamp:       "2026-08-14T17:46:32Z",
	}
	if _, err := contract.WriteRecord(filepath.Join(dir, "findings"), record); err != nil {
		t.Fatalf("write reviewed agent record: %v", err)
	}
}

// RegisterAll must expose each MCP tool only once.
func TestRegisterAllDoesNotDuplicateTheToolList(t *testing.T) {
	s := mcp.NewServer(mcp.ServerInfo{Name: "Argos Web Scanner", Version: "1.0.0"})
	RegisterAll(s, &Env{MemoryDir: t.TempDir(), SessionID: "ses_test_register_all"})

	seen := map[string]int{}
	for _, def := range s.ToolDefinitions() {
		seen[def.Name]++
	}
	if len(seen) == 0 {
		t.Fatal("no tools were registered")
	}
	for name, count := range seen {
		if count != 1 {
			t.Errorf("tool %q appears %d times in tools/list, want 1", name, count)
		}
	}
}
