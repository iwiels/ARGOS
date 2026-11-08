package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// newProductionServer spins up a real mcp.Server — the same one RegisterAll
// wires the production handlers into — over an in-memory pipe, driven by its
// own s.Run loop (the exact request loop the compiled binary uses). Calls
// issued through the returned function share one running server instance, so
// state written by one call (e.g. memory.save) is visible to a later one
// (e.g. memory.search) exactly as it would be for a real client.
//
// This replaces an earlier test double that reimplemented each handler
// locally (handleMemorySave, handleScout, ...) and had silently drifted from
// the shipped code without any test failing — e.g. it hardcoded a hallucinated
// timestamp and skipped the argos_session_id field entirely. Every test
// in this file now exercises RegisterAll's actual production handlers.
func newProductionServer(t *testing.T, memDir string) func(method string, params map[string]interface{}) map[string]interface{} {
	t.Helper()
	serverR, clientW := io.Pipe()
	clientR, serverW := io.Pipe()

	s := mcp.NewServerWithIO(mcp.ServerInfo{Name: "Argos Orquestador", Version: "1.0.0"}, serverR, serverW)
	s.SetMemoryDir(memDir)
	RegisterAll(s)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Run(ctx)
	}()

	scanner := bufio.NewScanner(clientR)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	t.Cleanup(func() {
		cancel()
		_ = clientW.Close()
		<-done
		_ = serverR.Close()
		_ = serverW.Close()
		_ = clientR.Close()
	})

	reqID := 0
	return func(method string, params map[string]interface{}) map[string]interface{} {
		t.Helper()
		reqID++
		req := map[string]interface{}{"jsonrpc": "2.0", "id": reqID, "method": method}
		if params != nil {
			req["params"] = params
		}
		payload, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("failed to marshal %s request: %v", method, err)
		}
		go func() {
			_, _ = clientW.Write(append(payload, '\n'))
		}()
		if !scanner.Scan() {
			t.Fatalf("no response from production server for %s: %v", method, scanner.Err())
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode %s response: %v", method, err)
		}
		return resp
	}
}

// unwrapToolResult decodes the MCP content envelope the real server wraps tool
// results in: {"content":[{"type":"text","text":"<json>"}],"isError":false}.
func unwrapToolResult(t *testing.T, resp map[string]interface{}) map[string]interface{} {
	t.Helper()
	if errObj, hasErr := resp["error"]; hasErr {
		t.Fatalf("tool call returned an error: %v", errObj)
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("result is not a map: %+v", resp)
	}
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatalf("result has no content envelope: %+v", result)
	}
	first, ok := content[0].(map[string]interface{})
	if !ok {
		t.Fatalf("content[0] is not a map: %+v", content[0])
	}
	text, ok := first["text"].(string)
	if !ok {
		t.Fatalf("content[0].text is not a string: %+v", first)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("failed to decode tool result payload: %v (raw: %s)", err, text)
	}
	return decoded
}

// ===== TESTS =====

func TestResolveRunArtifactsDir_ByExactRunID(t *testing.T) {
	memDir := t.TempDir()
	runDir := filepath.Join(memDir, "runs", "20260807-193103-https---aulavirtualsiste")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}
	manifest := RunManifest{RunID: "20260807-193103-https---aulavirtualsiste", Campaign: "aulavirtualsistemas-2026-08-07", Status: "running"}
	data, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(runDir, "manifest.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	dir, errObj := resolveRunArtifactsDir(memDir, "20260807-193103-https---aulavirtualsiste")
	if errObj != nil {
		t.Fatalf("exact run_id should resolve: %v", errObj)
	}
	if dir != runDir {
		t.Errorf("dir = %q, want %q", dir, runDir)
	}
}

func TestResolveRunArtifactsDir_ByCampaignFallback(t *testing.T) {
	memDir := t.TempDir()
	runDir := filepath.Join(memDir, "runs", "20260807-193103-https---aulavirtualsiste")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatal(err)
	}
	manifest := RunManifest{RunID: "20260807-193103-https---aulavirtualsiste", Campaign: "aulavirtualsistemas-2026-08-07", Status: "running"}
	data, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(runDir, "manifest.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	// El agente pasa el campaign (session ID legible) en vez del run_id generado.
	dir, errObj := resolveRunArtifactsDir(memDir, "aulavirtualsistemas-2026-08-07")
	if errObj != nil {
		t.Fatalf("campaign fallback should resolve: %v", errObj)
	}
	if dir != runDir {
		t.Errorf("dir = %q, want %q", dir, runDir)
	}
}

func TestResolveRunArtifactsDir_PrefersActiveRunForDuplicateCampaign(t *testing.T) {
	memDir := t.TempDir()

	// Run viejo, cerrado (status "completed") de la misma campaña.
	oldDir := filepath.Join(memDir, "runs", "20260801-100000-https---aulavirtualsiste")
	if err := os.MkdirAll(oldDir, 0755); err != nil {
		t.Fatal(err)
	}
	oldManifest := RunManifest{RunID: "20260801-100000-https---aulavirtualsiste", Campaign: "aulavirtualsistemas-2026-08-07", Status: "completed", UpdatedAt: "2026-08-01T10:00:00Z"}
	oldData, _ := json.MarshalIndent(oldManifest, "", "  ")
	if err := os.WriteFile(filepath.Join(oldDir, "manifest.json"), oldData, 0644); err != nil {
		t.Fatal(err)
	}

	// Run activo, reciente (status "running") de la misma campaña.
	newDir := filepath.Join(memDir, "runs", "20260807-193103-https---aulavirtualsiste")
	if err := os.MkdirAll(newDir, 0755); err != nil {
		t.Fatal(err)
	}
	newManifest := RunManifest{RunID: "20260807-193103-https---aulavirtualsiste", Campaign: "aulavirtualsistemas-2026-08-07", Status: "running", UpdatedAt: "2026-08-07T19:31:03Z"}
	newData, _ := json.MarshalIndent(newManifest, "", "  ")
	if err := os.WriteFile(filepath.Join(newDir, "manifest.json"), newData, 0644); err != nil {
		t.Fatal(err)
	}

	dir, errObj := resolveRunArtifactsDir(memDir, "aulavirtualsistemas-2026-08-07")
	if errObj != nil {
		t.Fatalf("campaign fallback should resolve: %v", errObj)
	}
	if dir != newDir {
		t.Errorf("dir = %q, want active run %q", dir, newDir)
	}
}

func TestResolveRunArtifactsDir_NotFound(t *testing.T) {
	memDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(memDir, "runs"), 0755); err != nil {
		t.Fatal(err)
	}

	_, errObj := resolveRunArtifactsDir(memDir, "no-such-run")
	if errObj == nil {
		t.Fatal("expected error for unknown run")
	}
	if errObj.Code != -32602 {
		t.Errorf("code = %d, want -32602", errObj.Code)
	}
}

func TestToolRegistration_All11Registered(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	resp := call("tools/list", nil)
	if errObj, hasErr := resp["error"]; hasErr {
		t.Fatalf("unexpected error: %v", errObj)
	}

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("result is not a map")
	}
	toolsRaw, ok := result["tools"]
	if !ok {
		t.Fatal("result.tools not found")
	}
	toolsList, ok := toolsRaw.([]interface{})
	if !ok {
		t.Fatalf("tools is not an array: %T", toolsRaw)
	}
	if len(toolsList) != 11 {
		t.Errorf("got %d tools, want 11", len(toolsList))
	}

	names := make(map[string]bool)
	for _, tRaw := range toolsList {
		tDef, ok := tRaw.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := tDef["name"].(string)
		names[name] = true
	}

	expected := []string{
		"orchestrator.sync", "orchestrator.info",
		"memory.search", "memory.context", "memory.save",
		"audit.scout", "audit.dispatch",
		"audit.run.start", "audit.run.phase", "audit.run.inspect", "audit.run.correlate",
	}
	for _, n := range expected {
		if !names[n] {
			t.Errorf("missing tool: %s", n)
		}
	}
}

func TestOrchestratorInfo(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	resp := call("tools/call", map[string]interface{}{
		"name":      "orchestrator.info",
		"arguments": map[string]interface{}{},
	})
	result := unwrapToolResult(t, resp)

	if result["name"] != "Argos Orquestador" {
		t.Errorf("name = %v, want Argos Orquestador", result["name"])
	}
	if result["version"] != "1.0.0" {
		t.Errorf("version = %v, want 1.0.0", result["version"])
	}

	profiles, ok := result["profiles"].([]interface{})
	if !ok {
		t.Fatal("profiles is not an array")
	}
	if len(profiles) == 0 {
		t.Error("profiles is empty")
	}

	memoryDir, ok := result["memory_dir"].(string)
	if !ok || memoryDir == "" {
		t.Error("memory_dir should be present and non-empty")
	}
}

func TestMemorySearch_TokenizedMatchesBilingualAuthorization(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	// Autorización guardada en español (como la guarda security-report en el mundo real).
	saveResp := call("tools/call", map[string]interface{}{
		"name": "memory.save",
		"arguments": map[string]interface{}{
			"title":   "Autorización: auditoría autorizada por escrito — portal.example.com (Target Corp)",
			"target":  "https://portal.example.com/",
			"status":  "validated",
			"kind":    "note",
			"tags":    []interface{}{"autorización", "example"},
			"session": "engagement-2026-08-07",
			"agent":   "security-report",
		},
	})
	unwrapToolResult(t, saveResp)

	// El orquestador consulta en inglés ("authorized engagement [target]").
	// Con matching por frase completa esto devolvía vacío (falso negativo);
	// con tokenización debe encontrar la autorización por el target.
	searchResp := call("tools/call", map[string]interface{}{
		"name": "memory.search",
		"arguments": map[string]interface{}{
			"query": "authorized engagement portal.example.com",
			"limit": 10,
		},
	})
	result := unwrapToolResult(t, searchResp)

	total, _ := result["total"].(float64)
	if total == 0 {
		t.Fatal("tokenized search returned 0 results, expected the authorization finding")
	}

	findings, ok := result["findings"].([]interface{})
	if !ok || len(findings) == 0 {
		t.Fatal("findings empty")
	}
	first := findings[0].(map[string]interface{})
	if !strings.Contains(first["title"].(string), "Autorización") {
		t.Errorf("expected authorization finding, got title %q", first["title"])
	}
}

func TestMemorySaveAndSearchRoundTrip(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	saveResp := call("tools/call", map[string]interface{}{
		"name": "memory.save",
		"arguments": map[string]interface{}{
			"title":            "Test Finding for Search",
			"target":           "192.168.1.1",
			"severity":         "HIGH",
			"status":           "validated",
			"cwe":              "CWE-79",
			"evidence":         "XSS vulnerability found in parameter 'q'",
			"agent_assessment": "Confirmed that the reflected value executes in the response context.",
			"impact":           "An attacker can execute script in another user's browser session.",
			"session":          "test-session",
			"argos_session_id": "ses_test_roundtrip_01",
			"agent":            "test-agent",
			"kind":             "finding",
			"source_tool":      "web.probe",
		},
	})
	saveResult := unwrapToolResult(t, saveResp)
	if saveResult["status"] != "saved" {
		t.Errorf("save status = %v, want saved", saveResult["status"])
	}
	savedFinding, ok := saveResult["finding"].(map[string]interface{})
	if !ok {
		t.Fatal("save result finding is not a map")
	}
	if savedFinding["source_tool"] != "web.probe" {
		t.Errorf("saved finding source_tool = %v, want web.probe", savedFinding["source_tool"])
	}

	searchResp := call("tools/call", map[string]interface{}{
		"name": "memory.search",
		"arguments": map[string]interface{}{
			"query": "XSS",
			"limit": 10,
		},
	})
	searchResult := unwrapToolResult(t, searchResp)

	total, _ := searchResult["total"].(float64)
	if total == 0 {
		t.Error("memory.search returned 0 results, expected at least 1")
	}

	findings, ok := searchResult["findings"].([]interface{})
	if !ok || len(findings) == 0 {
		t.Fatal("search result findings is empty")
	}

	first := findings[0].(map[string]interface{})
	if first["title"] != "Test Finding for Search" {
		t.Errorf("finding title = %v, want Test Finding for Search", first["title"])
	}
	if first["severity"] != "HIGH" {
		t.Errorf("finding severity = %v, want HIGH", first["severity"])
	}
	if first["source_tool"] != "web.probe" {
		t.Errorf("finding source_tool = %v, want web.probe", first["source_tool"])
	}

	// Also verify searching by session identifier + "findings" works robustly.
	searchBySession := call("tools/call", map[string]interface{}{
		"name": "memory.search",
		"arguments": map[string]interface{}{
			"query": "test-session findings",
			"limit": 10,
		},
	})
	resSession := unwrapToolResult(t, searchBySession)
	totSession, _ := resSession["total"].(float64)
	if totSession == 0 {
		t.Errorf("memory.search by session query returned 0 results, response: %+v", resSession)
	}
}

// TestMemorySaveProductionPersistsArgosSessionID exercises the field a
// peer agent (security-scout, security-web, …) must set for its finding to be
// reconcilable back into the Argos Desktop — distinct
// from "session", the human-readable campaign label.
func TestMemorySaveProductionPersistsArgosSessionID(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	saveResp := call("tools/call", map[string]interface{}{
		"name": "memory.save",
		"arguments": map[string]interface{}{
			"title":            "Reconcilable finding from a peer agent",
			"kind":             "finding",
			"target":           "https://example.test/account",
			"severity":         "MEDIUM",
			"evidence":         "The agent verified unauthorized account data disclosure.",
			"agent_assessment": "Compared the returned record with the authenticated user's account and confirmed the mismatch.",
			"impact":           "An unauthorized user can read private account data.",
			"session":          "example-target-2026-08-14",
			"argos_session_id": "ses_test_reconcile_01",
			"agent":            "security-scout",
		},
	})
	saveResult := unwrapToolResult(t, saveResp)
	savedFinding, ok := saveResult["finding"].(map[string]interface{})
	if !ok {
		t.Fatalf("save result finding is not a map: %+v", saveResult)
	}
	if savedFinding["argos_session_id"] != "ses_test_reconcile_01" {
		t.Errorf("saved argos_session_id = %v, want ses_test_reconcile_01", savedFinding["argos_session_id"])
	}
	if savedFinding["session"] != "example-target-2026-08-14" {
		t.Errorf("saved session = %v, want example-target-2026-08-14 (unchanged)", savedFinding["session"])
	}

	// Re-read the persisted JSON directly: confirms the field round-trips
	// through disk, not just through the in-memory response.
	findingsDir := filepath.Join(memDir, "findings")
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		t.Fatalf("failed to read findings dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 persisted finding, got %d", len(entries))
	}
	data, err := os.ReadFile(filepath.Join(findingsDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("failed to read persisted finding: %v", err)
	}
	var persisted Finding
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("failed to decode persisted finding: %v", err)
	}
	if persisted.ArgosSessionID != "ses_test_reconcile_01" {
		t.Errorf("persisted ArgosSessionID = %q, want ses_test_reconcile_01", persisted.ArgosSessionID)
	}
}

func TestMemorySaveUsesControllerSessionContext(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	resp := call("tools/call", map[string]interface{}{
		"name": "memory.save",
		"arguments": map[string]interface{}{
			"title":            "Controller-bound finding",
			"kind":             "finding",
			"target":           "https://example.test/account",
			"severity":         "HIGH",
			"evidence":         "The agent verified unauthorized account data disclosure.",
			"agent_assessment": "Compared the returned record with the authenticated user's account and confirmed the mismatch.",
			"impact":           "An unauthorized user can read private account data.",
			"argos_session_id": "ses_model_selected",
		},
		"_meta": map[string]interface{}{
			"argos/session_id": "ses_controller_bound",
		},
	})
	result := unwrapToolResult(t, resp)
	finding, ok := result["finding"].(map[string]interface{})
	if !ok {
		t.Fatalf("saved finding is not a map: %+v", result)
	}
	if finding["argos_session_id"] != "ses_controller_bound" {
		t.Errorf("saved argos_session_id = %v, want controller session", finding["argos_session_id"])
	}

	entries, err := os.ReadDir(filepath.Join(memDir, "findings"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("persisted files = %d, error = %v; want exactly one", len(entries), err)
	}
	data, err := os.ReadFile(filepath.Join(memDir, "findings", entries[0].Name()))
	if err != nil {
		t.Fatalf("failed to read persisted finding: %v", err)
	}
	var persisted Finding
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("failed to decode persisted finding: %v", err)
	}
	if persisted.ArgosSessionID != "ses_controller_bound" {
		t.Errorf("persisted argos_session_id = %q, want controller session", persisted.ArgosSessionID)
	}
}

func TestMemorySaveDoesNotBindNotesToControllerSession(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	resp := call("tools/call", map[string]interface{}{
		"name": "memory.save",
		"arguments": map[string]interface{}{
			"title": "Shared note",
			"kind":  "note",
		},
		"_meta": map[string]interface{}{
			"argos/session_id": "ses_controller_bound",
		},
	})
	result := unwrapToolResult(t, resp)
	record, ok := result["finding"].(map[string]interface{})
	if !ok {
		t.Fatalf("saved record is not a map: %+v", result)
	}
	if _, exists := record["argos_session_id"]; exists {
		t.Errorf("shared note unexpectedly belongs to session %v", record["argos_session_id"])
	}
}

// Este test antes afirmaba lo contrario: que omitir argos_session_id
// seguía siendo válido, "para que las prompts de agente viejas y los
// engagements en vuelo siguieran funcionando".
//
// Esa compatibilidad hacia atrás era precisamente el fallo. El hallazgo se
// guardaba en disco con status "saved", el agente lo daba por bueno, y el panel
// nunca lo veía porque la reconciliación exige coincidencia exacta del campo.
// Una auditoría del store real encontró 0 de 182 hallazgos con el campo: la
// ruta de reconciliación no había funcionado nunca. Un error explícito es
// preferible a perder datos en silencio.
func TestMemorySaveRejectsFindingWithoutArgosSessionID(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	resp := call("tools/call", map[string]interface{}{
		"name": "memory.save",
		"arguments": map[string]interface{}{
			"title":            "Finding without the reconciliation field",
			"target":           "https://example.test/account",
			"severity":         "LOW",
			"evidence":         "The agent verified a security impact.",
			"agent_assessment": "Confirmed the response exposes a private record outside the authorized account.",
			"impact":           "An unauthorized actor can read another user's private data.",
			"session":          "example-target-2026-08-14",
			"kind":             "finding",
		},
	})

	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected an error rejecting the save, got: %+v", resp)
	}
	if !strings.Contains(fmt.Sprint(errObj["message"]), "argos_session_id") {
		t.Errorf("error message should name the missing field, got: %v", errObj["message"])
	}

	// Y no debe quedar ningún archivo a medias en el store.
	entries, err := os.ReadDir(filepath.Join(memDir, "findings"))
	if err == nil && len(entries) != 0 {
		t.Errorf("rejected save wrote %d file(s); want none", len(entries))
	}
}

// La etiqueta de campaña es un campo distinto: pasarla por error en el lugar
// del Session ID real produciría un hallazgo igual de invisible, así que
// también se rechaza.
func TestMemorySaveRejectsCampaignLabelAsSessionID(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	resp := call("tools/call", map[string]interface{}{
		"name": "memory.save",
		"arguments": map[string]interface{}{
			"title":            "Finding with the campaign label in the wrong field",
			"target":           "https://example.test/account",
			"severity":         "LOW",
			"evidence":         "The agent verified a security impact.",
			"agent_assessment": "Confirmed the response exposes a private record outside the authorized account.",
			"impact":           "An unauthorized actor can read another user's private data.",
			"session":          "argoscom-2026-08-19",
			"argos_session_id": "argoscom-2026-08-19",
			"kind":             "finding",
		},
	})

	if _, ok := resp["error"].(map[string]interface{}); !ok {
		t.Fatalf("expected an error for a non-ses_ session id, got: %+v", resp)
	}
}

func TestMemorySaveRejectsUnreviewedOrIncompleteFindings(t *testing.T) {
	tests := []struct {
		name string
		args map[string]interface{}
	}{
		{
			name: "missing explicit finding kind",
			args: map[string]interface{}{"title": "Scanner candidate", "target": "https://example.test", "severity": "HIGH", "evidence": "Scanner matched a template", "argos_session_id": "ses_review_gate_01"},
		},
		{
			name: "missing target",
			args: map[string]interface{}{"kind": "finding", "title": "Scanner candidate", "severity": "HIGH", "evidence": "Verified impact", "argos_session_id": "ses_review_gate_01"},
		},
		{
			name: "missing evidence",
			args: map[string]interface{}{"kind": "finding", "title": "Scanner candidate", "target": "https://example.test", "severity": "HIGH", "argos_session_id": "ses_review_gate_01"},
		},
		{
			name: "missing agent assessment",
			args: map[string]interface{}{"kind": "finding", "title": "Scanner candidate", "target": "https://example.test", "severity": "HIGH", "evidence": "The response contains another user's private record", "impact": "An attacker can read another user's data", "argos_session_id": "ses_review_gate_01"},
		},
		{
			name: "missing impact",
			args: map[string]interface{}{"kind": "finding", "title": "Scanner candidate", "target": "https://example.test", "severity": "HIGH", "evidence": "The response contains another user's private record", "agent_assessment": "Compared the response with the authenticated account and confirmed the mismatch", "argos_session_id": "ses_review_gate_01"},
		},
		{
			name: "trivial agent assessment",
			args: map[string]interface{}{"kind": "finding", "title": "Scanner candidate", "target": "https://example.test", "severity": "HIGH", "evidence": "The response contains another user's private record", "agent_assessment": "Confirmed", "impact": "An attacker can read another user's private account data", "argos_session_id": "ses_review_gate_01"},
		},
		{
			name: "assessment copied from evidence",
			args: map[string]interface{}{"kind": "finding", "title": "Scanner candidate", "target": "https://example.test", "severity": "HIGH", "evidence": "The response contains another user's private record", "agent_assessment": "The response contains another user's private record", "impact": "An attacker can read another user's private account data", "argos_session_id": "ses_review_gate_01"},
		},
		{
			name: "placeholder impact",
			args: map[string]interface{}{"kind": "finding", "title": "Scanner candidate", "target": "https://example.test", "severity": "HIGH", "evidence": "The response contains another user's private record", "agent_assessment": "Compared the response with the authenticated account and confirmed the mismatch", "impact": "N/A", "argos_session_id": "ses_review_gate_01"},
		},
		{
			name: "unknown severity",
			args: map[string]interface{}{"kind": "finding", "title": "Scanner candidate", "target": "https://example.test", "severity": "maybe", "evidence": "Verified impact", "argos_session_id": "ses_review_gate_01"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			memDir := t.TempDir()
			call := newProductionServer(t, memDir)
			resp := call("tools/call", map[string]interface{}{"name": "memory.save", "arguments": test.args})
			if _, ok := resp["error"].(map[string]interface{}); !ok {
				t.Fatalf("expected invalid finding to be rejected, got %+v", resp)
			}
			entries, err := os.ReadDir(filepath.Join(memDir, "findings"))
			if err == nil && len(entries) != 0 {
				t.Fatalf("rejected finding wrote %d file(s)", len(entries))
			}
		})
	}
}

// Las notas de memoria compartida no se reconcilian con ninguna sesión, así que
// no deben quedar bloqueadas por la validación.
func TestMemorySaveAllowsNotesWithoutSessionID(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	resp := call("tools/call", map[string]interface{}{
		"name": "memory.save",
		"arguments": map[string]interface{}{
			"title":   "Cross-campaign note",
			"session": "example-target-2026-08-14",
			"kind":    "note",
		},
	})
	result := unwrapToolResult(t, resp)
	if result["status"] != "saved" {
		t.Errorf("status = %v, want saved", result["status"])
	}
}

func TestAuditRunStartCreatesValidRunID(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	resp := call("tools/call", map[string]interface{}{
		"name": "audit.run.start",
		"arguments": map[string]interface{}{
			"target":     "https://example.com:8443/api",
			"profile":    "web-triage",
			"authorized": true,
		},
	})
	result := unwrapToolResult(t, resp)

	runID, ok := result["run_id"].(string)
	if !ok || runID == "" {
		t.Fatal("run_id is empty or missing")
	}

	// Format: YYYYMMDD-HHMMSS-target-suffix
	parts := strings.SplitN(runID, "-", 2)
	if len(parts) < 2 {
		t.Fatalf("run_id %q does not contain timestamp prefix", runID)
	}
	if len(parts[0]) != 15 { // "20260807-193103"
		t.Logf("run_id timestamp part length = %d (expected 15 for YYYYMMDD-HHMMSS)", len(parts[0]))
	}

	status, ok := result["status"].(string)
	if !ok || status != "running" {
		t.Errorf("status = %v, want running", status)
	}

	targetKind, ok := result["target_kind"].(string)
	if !ok || targetKind == "" {
		t.Error("target_kind is empty")
	}
}

func TestAuditScoutTargetDetection(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	tests := []struct {
		target     string
		wantKind   string
		wantMethod string
	}{
		{"https://example.com", "web", "General web application assessment"},
		// Port 8443 takes precedence over /api path for kind detection
		{"https://example.com:8443/api", "web", "HTTPS web application assessment with TLS validation"},
		// HTTP URLs always enter the web block; repo detection only applies to non-HTTP
		{"https://github.com/org/repo", "web", "General web application assessment"},
		{"192.168.1.1:22", "host", "Host service assessment"},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			resp := call("tools/call", map[string]interface{}{
				"name": "audit.scout",
				"arguments": map[string]interface{}{
					"target": tt.target,
				},
			})
			result := unwrapToolResult(t, resp)

			kind, _ := result["kind"].(string)
			if kind != tt.wantKind {
				t.Errorf("kind = %q, want %q", kind, tt.wantKind)
			}

			method, _ := result["recommended_methodology"].(string)
			if !strings.HasPrefix(method, tt.wantMethod) {
				t.Errorf("method = %q, want prefix %q", method, tt.wantMethod)
			}
		})
	}
}

func TestOrchestratorSync(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	resp := call("tools/call", map[string]interface{}{
		"name": "orchestrator.sync",
		"arguments": map[string]interface{}{
			"profile": "recon",
		},
	})
	result := unwrapToolResult(t, resp)

	if result["status"] != "synced" {
		t.Errorf("status = %v, want synced", result["status"])
	}

	agents, ok := result["agents"].([]interface{})
	if !ok || len(agents) == 0 {
		t.Error("agents should be a non-empty list")
	}
}

func TestOrchestratorSyncInvalidProfile(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	resp := call("tools/call", map[string]interface{}{
		"name": "orchestrator.sync",
		"arguments": map[string]interface{}{
			"profile": "nonexistent",
		},
	})

	if _, hasErr := resp["error"]; !hasErr {
		t.Error("expected error for unknown profile")
	}
}

// La correlación leía el directorio de hallazgos ENTERO sin filtrar por run.
// Como el store de memoria es compartido entre campañas, el resultado mezclaba
// engagements distintos: en un run real aparecieron CWEs de targets que ni
// siquiera estaban en alcance. El manifiesto declara su `campaign`, que es el
// mismo valor que los agentes escriben en `session`.
func TestAuditRunCorrelateIsolatesCampaigns(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	startResp := call("tools/call", map[string]interface{}{
		"name": "audit.run.start",
		"arguments": map[string]interface{}{
			"target":     "https://in-scope.example",
			"profile":    "web-triage",
			"authorized": true,
			"campaign":   "in-scope-campaign",
		},
	})
	runID, _ := unwrapToolResult(t, startResp)["run_id"].(string)
	if runID == "" {
		t.Fatal("audit.run.start returned no run_id")
	}

	save := func(session, title, cwe string) {
		t.Helper()
		call("tools/call", map[string]interface{}{
			"name": "memory.save",
			"arguments": map[string]interface{}{
				"title":            title,
				"cwe":              cwe,
				"severity":         "HIGH",
				"kind":             "finding",
				"evidence":         "The response contains an executable reflected payload.",
				"agent_assessment": "Verified the payload executes in the response context.",
				"impact":           "An attacker can run script in a victim's browser.",
				"session":          session,
				"argos_session_id": "ses_correlate_test_01",
				"target":           "https://in-scope.example",
			},
		})
	}
	save("in-scope-campaign", "In scope issue", "CWE-79")
	save("some-other-engagement", "Unrelated SQLi from another client", "CWE-89")
	save("some-other-engagement", "Unrelated open redirect", "CWE-601")

	result := unwrapToolResult(t, call("tools/call", map[string]interface{}{
		"name":      "audit.run.correlate",
		"arguments": map[string]interface{}{"run_id": runID},
	}))

	if got := result["total_findings"]; got != float64(1) {
		t.Errorf("total_findings = %v, want 1 (only the in-scope finding)", got)
	}
	if got := result["out_of_scope_skipped"]; got != float64(2) {
		t.Errorf("out_of_scope_skipped = %v, want 2", got)
	}
	for _, entry := range result["by_cwe"].([]interface{}) {
		if cwe := entry.(map[string]interface{})["cwe"]; cwe == "CWE-89" || cwe == "CWE-601" {
			t.Errorf("correlation leaked a CWE from another campaign: %v", cwe)
		}
	}
}

// La clave de dedup era una comparación exacta, así que la misma incidencia
// descrita con distinta capitalización o espaciado contaba dos veces.
func TestAuditRunCorrelateDedupesIgnoringCaseAndSpacing(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	startResp := call("tools/call", map[string]interface{}{
		"name": "audit.run.start",
		"arguments": map[string]interface{}{
			"target":     "https://dedup.example",
			"profile":    "web-triage",
			"authorized": true,
			"campaign":   "dedup-campaign",
		},
	})
	runID, _ := unwrapToolResult(t, startResp)["run_id"].(string)

	for _, title := range []string{"Expired TLS certificate", "expired tls   certificate"} {
		call("tools/call", map[string]interface{}{
			"name": "memory.save",
			"arguments": map[string]interface{}{
				"title":            title,
				"cwe":              "CWE-295",
				"severity":         "HIGH",
				"kind":             "finding",
				"evidence":         "A controlled input changed the SQL query result.",
				"agent_assessment": "Repeated the parameter test and confirmed query behavior changes based on injected input.",
				"impact":           "An attacker can read or modify data through SQL injection.",
				"session":          "dedup-campaign",
				"argos_session_id": "ses_dedup_test_01",
				"target":           "https://dedup.example",
			},
		})
	}

	result := unwrapToolResult(t, call("tools/call", map[string]interface{}{
		"name":      "audit.run.correlate",
		"arguments": map[string]interface{}{"run_id": runID},
	}))

	if got := result["deduplicated"]; got != float64(1) {
		t.Errorf("deduplicated = %v, want 1", got)
	}
}

// La identidad de un bug es taxonómica (CWE + target + vector), no la prosa
// del título: dos herramientas que describen el MISMO bug con títulos
// distintos son un solo hallazgo.
func TestNormalizeDedupKeyByTaxonomy(t *testing.T) {
	cases := []struct {
		name    string
		a       [4]string // title, target, cwe, vector
		b       [4]string
		sameKey bool
	}{
		{
			name:    "the same bug with a different title dedupes",
			a:       [4]string{"SQL Injection", "https://x/item", "CWE-89", "id"},
			b:       [4]string{"SQL Injection Confirmada (sqlmap)", "https://x/item", "CWE-89", "id"},
			sameKey: true,
		},
		{
			name:    "a different CWE is a different bug",
			a:       [4]string{"SQL Injection", "https://x/item", "CWE-89", "id"},
			b:       [4]string{"XSS reflejado", "https://x/item", "CWE-79", "id"},
			sameKey: false,
		},
		{
			name:    "the same parameter name in another target is another bug",
			a:       [4]string{"SQL Injection", "https://x/a", "CWE-89", "id"},
			b:       [4]string{"SQL Injection", "https://x/b", "CWE-89", "id"},
			sameKey: false,
		},
		{
			name:    "query values do not discriminate for the same parameter",
			a:       [4]string{"SQL Injection", "https://x/item?id=1", "CWE-89", "https://x/item?id=1"},
			b:       [4]string{"SQL Injection", "https://x/item?id=2", "CWE-89", "https://x/item?id=2"},
			sameKey: true,
		},
		{
			name:    "different vulnerable parameters remain separate",
			a:       [4]string{"SQL Injection", "https://x/item", "CWE-89", "https://x/item?id=1"},
			b:       [4]string{"SQL Injection", "https://x/item", "CWE-89", "https://x/item?search=1"},
			sameKey: false,
		},
		{
			name:    "without an explicit vector do not merge distinct issues by CWE and target",
			a:       [4]string{"SQL Injection in id", "https://x/item", "CWE-89", ""},
			b:       [4]string{"SQL Injection in search", "https://x/item", "CWE-89", ""},
			sameKey: false,
		},
		{
			name:    "a non-default port is another target",
			a:       [4]string{"Open redirect", "https://x:8080/item", "CWE-601", "/go"},
			b:       [4]string{"Open redirect", "https://x/item", "CWE-601", "/go"},
			sameKey: false,
		},
		{
			name:    "the default port does not discriminate",
			a:       [4]string{"Open redirect", "https://x:443/item", "CWE-601", "/go"},
			b:       [4]string{"Open redirect", "https://x/item", "CWE-601", "/go"},
			sameKey: true,
		},
		{
			name:    "without a CWE it falls back to the title identity",
			a:       [4]string{"Open port 22", "10.0.0.1", "", ""},
			b:       [4]string{"Open port 22 (recheck)", "10.0.0.1", "", ""},
			sameKey: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyA := normalizeDedupKey(tc.a[0], tc.a[1], tc.a[2], tc.a[3])
			keyB := normalizeDedupKey(tc.b[0], tc.b[1], tc.b[2], tc.b[3])
			if tc.sameKey && keyA != keyB {
				t.Errorf("keys differ, want the same:\n  %q\n  %q", keyA, keyB)
			}
			if !tc.sameKey && keyA == keyB {
				t.Errorf("keys are the same, want different: %q", keyA)
			}
		})
	}
}

// La normalización de target es la MISMA que la del backend
// (packages/core/src/security/ingest.ts): sin esquema, sin query string, sin
// fragment, sin puerto por defecto y sin barras finales.
func TestNormalizeTargetIdentity(t *testing.T) {
	cases := map[string]string{
		"HTTPS://Example.com:8080/path/?x=1#frag": "example.com:8080/path",
		"https://example.com/path/":               "example.com/path",
		"https://example.com:443/path":            "example.com/path",
		"http://example.com:80/path":              "example.com/path",
		"https://example.com":                     "example.com",
		"https://example.com/":                    "example.com",
		"sub.example.com":                         "sub.example.com",
		"192.168.1.1:22":                          "192.168.1.1:22",
		"  HTTPS://Example.com/  ":                "example.com",
		"":                                        "",
	}
	for input, want := range cases {
		if got := normalizeTargetIdentity(input); got != want {
			t.Errorf("normalizeTargetIdentity(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeVectorIdentity(t *testing.T) {
	cases := map[string]string{
		"https://x/item?id=1":          "https://x/item?id",
		"https://x/item?search=2&id=1": "https://x/item?id&search",
		"id":                           "id",
		"/admin/":                      "/admin",
		"  ID  ":                       "id",
		"":                             "",
	}
	for input, want := range cases {
		if got := normalizeVectorIdentity(input); got != want {
			t.Errorf("normalizeVectorIdentity(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeCWE(t *testing.T) {
	cases := map[string]string{
		"CWE-89": "CWE-89",
		"cwe-89": "CWE-89",
		"cwe 89": "CWE-89",
		"89":     "CWE-89",
		"":       "",
		"nope":   "",
	}
	for input, want := range cases {
		if got := normalizeCWE(input); got != want {
			t.Errorf("normalizeCWE(%q) = %q, want %q", input, got, want)
		}
	}
}

// Dos agentes que reportan el MISMO bug con títulos distintos cuentan como
// un solo hallazgo: la correlación deduplica por taxonomía, no por prosa.
func TestAuditRunCorrelateDedupesByTaxonomyNotTitle(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	startResp := call("tools/call", map[string]interface{}{
		"name": "audit.run.start",
		"arguments": map[string]interface{}{
			"target":     "https://taxonomy.example",
			"profile":    "web-triage",
			"authorized": true,
			"campaign":   "taxonomy-campaign",
		},
	})
	runID, _ := unwrapToolResult(t, startResp)["run_id"].(string)
	if runID == "" {
		t.Fatal("audit.run.start returned no run_id")
	}

	save := func(title, cwe, target, vector string) {
		t.Helper()
		call("tools/call", map[string]interface{}{
			"name": "memory.save",
			"arguments": map[string]interface{}{
				"title":            title,
				"cwe":              cwe,
				"severity":         "HIGH",
				"kind":             "finding",
				"evidence":         "A controlled input changed the SQL query result.",
				"agent_assessment": "Repeated the parameter test and confirmed query behavior changes based on injected input.",
				"impact":           "An attacker can read or modify data through SQL injection.",
				"session":          "taxonomy-campaign",
				"argos_session_id": "ses_taxonomy_test_01",
				"target":           target,
				"vector":           vector,
			},
		})
	}

	// El mismo bug (CWE-89) en el mismo target y vector, descrito por dos
	// herramientas con títulos distintos.
	save("SQL Injection", "CWE-89", "https://taxonomy.example/item", "id")
	save("SQL Injection Confirmada (sqlmap)", "CWE-89", "https://taxonomy.example/item", "id")

	result := unwrapToolResult(t, call("tools/call", map[string]interface{}{
		"name":      "audit.run.correlate",
		"arguments": map[string]interface{}{"run_id": runID},
	}))

	if got := result["deduplicated"]; got != float64(1) {
		t.Errorf("deduplicated = %v, want 1 (same bug, different titles)", got)
	}
	// El grupo por CWE cuenta sobre los hallazgos YA deduplicados: un solo
	// SQLi aunque lo hayan reportado dos herramientas.
	for _, entry := range result["by_cwe"].([]interface{}) {
		group := entry.(map[string]interface{})
		if group["cwe"] == "CWE-89" {
			if count := group["count"]; count != float64(1) {
				t.Errorf("CWE-89 count = %v, want 1", count)
			}
		}
	}
}

// Dos bugs DISTINTOS (CWE distinto) no se deduplican, aunque compartan
// target y vector.
func TestAuditRunCorrelateKeepsDistinctCWESeparate(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	startResp := call("tools/call", map[string]interface{}{
		"name": "audit.run.start",
		"arguments": map[string]interface{}{
			"target":     "https://distinct.example",
			"profile":    "web-triage",
			"authorized": true,
			"campaign":   "distinct-campaign",
		},
	})
	runID, _ := unwrapToolResult(t, startResp)["run_id"].(string)

	save := func(title, cwe, target string) {
		t.Helper()
		call("tools/call", map[string]interface{}{
			"name": "memory.save",
			"arguments": map[string]interface{}{
				"title":            title,
				"cwe":              cwe,
				"severity":         "HIGH",
				"kind":             "finding",
				"evidence":         "A controlled input changed the SQL query result.",
				"agent_assessment": "Repeated the parameter test and confirmed query behavior changes based on injected input.",
				"impact":           "An attacker can read or modify data through SQL injection.",
				"session":          "distinct-campaign",
				"argos_session_id": "ses_distinct_test_01",
				"target":           target,
				"vector":           "id",
			},
		})
	}

	save("SQL Injection", "CWE-89", "https://distinct.example/item")
	save("XSS reflejado", "CWE-79", "https://distinct.example/item")

	result := unwrapToolResult(t, call("tools/call", map[string]interface{}{
		"name":      "audit.run.correlate",
		"arguments": map[string]interface{}{"run_id": runID},
	}))

	if got := result["deduplicated"]; got != float64(0) {
		t.Errorf("deduplicated = %v, want 0 (different CWEs are different bugs)", got)
	}
	if got := result["total_findings"]; got != float64(2) {
		t.Errorf("total_findings = %v, want 2", got)
	}
}

// El mismo nombre de parámetro en endpoints distintos son dos bugs: el
// target discrimina (antes, con la identidad por título, se pisaban).
func TestAuditRunCorrelateKeepsSameParameterInDistinctTargets(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	startResp := call("tools/call", map[string]interface{}{
		"name": "audit.run.start",
		"arguments": map[string]interface{}{
			"target":     "https://params.example",
			"profile":    "web-triage",
			"authorized": true,
			"campaign":   "params-campaign",
		},
	})
	runID, _ := unwrapToolResult(t, startResp)["run_id"].(string)

	save := func(target string) {
		t.Helper()
		call("tools/call", map[string]interface{}{
			"name": "memory.save",
			"arguments": map[string]interface{}{
				"title":            "SQL Injection",
				"cwe":              "CWE-89",
				"severity":         "HIGH",
				"kind":             "finding",
				"evidence":         "A controlled input changed the SQL query result.",
				"agent_assessment": "Repeated the parameter test and confirmed query behavior changes based on injected input.",
				"impact":           "An attacker can read or modify data through SQL injection.",
				"session":          "params-campaign",
				"argos_session_id": "ses_params_test_01",
				"target":           target,
				"vector":           "id",
			},
		})
	}

	save("https://params.example/a")
	save("https://params.example/b")

	result := unwrapToolResult(t, call("tools/call", map[string]interface{}{
		"name":      "audit.run.correlate",
		"arguments": map[string]interface{}{"run_id": runID},
	}))

	if got := result["deduplicated"]; got != float64(0) {
		t.Errorf("deduplicated = %v, want 0 (different targets are different bugs)", got)
	}
	if got := result["total_findings"]; got != float64(2) {
		t.Errorf("total_findings = %v, want 2", got)
	}
}

func TestAuditRunStartPersistsAuthorizationRecord(t *testing.T) {
	memDir := t.TempDir()
	call := newProductionServer(t, memDir)

	startResp := call("tools/call", map[string]interface{}{
		"name": "audit.run.start",
		"arguments": map[string]interface{}{
			"target":     "https://api.audit.example.org",
			"authorized": true,
		},
	})
	startResult := unwrapToolResult(t, startResp)
	runID, ok := startResult["run_id"].(string)
	if !ok || runID == "" {
		t.Fatalf("expected run_id in startResult, got %v", startResult)
	}

	// Check that both target slug and clean host slug files exist on disk
	findingsDir := filepath.Join(memDir, "findings")
	targetAuth := filepath.Join(findingsDir, fmt.Sprintf("auth-%s.json", shortTarget("https://api.audit.example.org")))
	if _, err := os.Stat(targetAuth); err != nil {
		t.Errorf("expected target auth file to exist: %v", err)
	}
	hostAuth := filepath.Join(findingsDir, fmt.Sprintf("auth-%s.json", shortTarget("api.audit.example.org")))
	if _, err := os.Stat(hostAuth); err != nil {
		t.Errorf("expected host auth file to exist: %v", err)
	}

	for _, query := range []string{
		"authorized engagement api.audit.example.org",
		"authorized engagement https://api.audit.example.org",
		"autorizacion api.audit.example.org",
	} {
		searchResp := call("tools/call", map[string]interface{}{
			"name": "memory.search",
			"arguments": map[string]interface{}{
				"query": query,
				"limit": 5,
			},
		})
		result := unwrapToolResult(t, searchResp)
		total, _ := result["total"].(float64)
		if total == 0 {
			t.Fatalf("query %q returned 0 results, expected authorization record", query)
		}
		findings, ok := result["findings"].([]interface{})
		if !ok || len(findings) == 0 {
			t.Fatalf("query %q returned empty findings", query)
		}
		first := findings[0].(map[string]interface{})
		if first["status"] != "authorized" {
			t.Errorf("query %q expected status 'authorized', got %v", query, first["status"])
		}
	}

	// Verify that starting run with target without explicitly passing authorized: true still defaults to authorized
	startResp2 := call("tools/call", map[string]interface{}{
		"name": "audit.run.start",
		"arguments": map[string]interface{}{
			"target": "https://api.example.org",
		},
	})
	startResult2 := unwrapToolResult(t, startResp2)
	runID2, ok := startResult2["run_id"].(string)
	if !ok || runID2 == "" {
		t.Fatalf("expected run_id in startResult2, got %v", startResult2)
	}
	manifestData, err := os.ReadFile(filepath.Join(memDir, "runs", runID2, "manifest.json"))
	if err != nil {
		t.Fatalf("cannot read manifest.json: %v", err)
	}
	var manifest map[string]interface{}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("cannot parse manifest.json: %v", err)
	}
	if manifest["authorized"] != true {
		t.Errorf("expected manifest.authorized to be true, got %v", manifest["authorized"])
	}
}
