package tools

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
)

func TestArtifactToolsMCP(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "argos-web-artifact-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	s := mcp.NewServer(mcp.ServerInfo{Name: "test-server", Version: "1.0"})
	s.SetMemoryDir(tempDir)

	sg, _ := scope.New(scope.ScopeConfig{
		AllowedDomains: []string{"example.com"},
	})
	env := &Env{
		Scope: sg,
	}

	RegisterArtifact(s, env)

	// Test 1: web.artifact with inline JS content
	jsCode := `function test(){const secret="AIzaSyD-abcdef123456789012345678901234";fetch('/api/v2/tokens');return secret;}`
	params, _ := json.Marshal(map[string]interface{}{
		"target":  "https://example.com/assets/app.min.js",
		"content": jsCode,
		"type":    "js",
	})

	toolCtx := mcp.ToolContext{
		MemoryDir:   tempDir,
		Ctx:         context.Background(),
		SessionID:   "ses_artifact_test",
		OperationID: "call_artifact_test",
		Scope:       &mcp.ScopeSnapshot{Domains: []string{"example.com"}},
		Log:         func(string, ...interface{}) {},
	}

	handler := s.GetToolHandler("web.artifact")
	if handler == nil {
		t.Fatalf("tool web.artifact was not registered")
	}

	res, errObj := handler(toolCtx, params)
	if errObj != nil {
		t.Fatalf("web.artifact failed: %s", errObj.Message)
	}

	resMap, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", res)
	}

	artifactID, ok := resMap["artifact_id"].(string)
	if !ok || artifactID == "" {
		t.Fatalf("expected artifact_id in result, got %+v", resMap)
	}

	endpoints, ok := resMap["endpoints"].([]string)
	if !ok || len(endpoints) == 0 {
		t.Errorf("expected endpoints in result, got: %+v", resMap["endpoints"])
	}

	totalLines, ok := resMap["total_lines"].(int)
	if !ok || totalLines < 2 {
		t.Errorf("expected total_lines > 1, got %v", resMap["total_lines"])
	}

	// Test 2: web.artifact.read lines
	readHandler := s.GetToolHandler("web.artifact.read")
	if readHandler == nil {
		t.Fatalf("tool web.artifact.read was not registered")
	}

	readParams, _ := json.Marshal(map[string]interface{}{
		"artifact_id": artifactID,
		"start_line":  1,
		"limit":       50,
	})

	readRes, errObj := readHandler(toolCtx, readParams)
	if errObj != nil {
		t.Fatalf("web.artifact.read failed: %s", errObj.Message)
	}

	readMap := readRes.(map[string]interface{})
	if readMap["lines"] == nil {
		t.Errorf("expected lines in readMap")
	}
	if readMap["total_lines"] != totalLines {
		t.Errorf("expected total_lines %d, got %v", totalLines, readMap["total_lines"])
	}

	// Test 3: web.artifact.read with regex pattern
	searchParams, _ := json.Marshal(map[string]interface{}{
		"artifact_id": artifactID,
		"pattern":     "AIzaSyD",
	})

	searchRes, errObj := readHandler(toolCtx, searchParams)
	if errObj != nil {
		t.Fatalf("web.artifact.read search failed: %s", errObj.Message)
	}

	searchMap := searchRes.(map[string]interface{})
	matchesCount, _ := searchMap["matches_count"].(int)
	if matchesCount < 1 {
		t.Errorf("expected at least 1 match for AIzaSyD, got %d", matchesCount)
	}

	// Test 4: Scope protection: out-of-scope URL should be rejected
	outOfScopeParams, _ := json.Marshal(map[string]interface{}{
		"target": "https://unauthorized-evil-target.com/evil.js",
	})
	_, outOfScopeErr := handler(toolCtx, outOfScopeParams)
	if outOfScopeErr == nil {
		t.Fatalf("expected out-of-scope target to be rejected by ScopeGuard")
	}
	if !strings.Contains(outOfScopeErr.Message, "authorized scope") {
		t.Errorf("expected scope error message, got: %s", outOfScopeErr.Message)
	}
}
