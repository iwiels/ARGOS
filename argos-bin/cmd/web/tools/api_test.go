package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSchemathesisReport(t *testing.T) {
	mockJson := `[
		{
			"check": "not_a_server_error",
			"status": "failure",
			"endpoint": "/api/v1/users/{id}",
			"method": "GET",
			"response": { "status_code": 500, "body": "Internal Server Error: DB connection leak" }
		}
	]`
	findings := parseSchemathesisJSON([]byte(mockJson), "http://127.0.0.1:8080")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "medium" {
		t.Fatalf("expected medium severity, got %s", findings[0].Severity)
	}
}

func TestSchemathesisRunOptionsUseReadOnlySourceAndSeparateReport(t *testing.T) {
	sourceRoot := t.TempDir()
	artifactDir := t.TempDir()
	reportPath := filepath.Join(artifactDir, "report.json")
	timeout := 30 * time.Second
	options := schemathesisRunOptions([]string{"run", "/workspace/openapi.yaml"}, sourceRoot, reportPath, timeout)
	if options.Dir != sourceRoot || options.ArtifactDir != artifactDir || options.Timeout != timeout {
		t.Fatalf("API scan mounts = source %q artifacts %q timeout %s", options.Dir, options.ArtifactDir, options.Timeout)
	}
	joined := strings.Join(options.Args, " ")
	if !strings.Contains(joined, "--report-v2-file "+reportPath) || !strings.Contains(joined, "/workspace/openapi.yaml") {
		t.Fatalf("API report and source paths were not retained: %s", joined)
	}
}

func TestSchemathesisSchemaTargetSeparatesLocalAndRemoteInputs(t *testing.T) {
	sourceRoot := t.TempDir()
	schemaPath := filepath.Join(sourceRoot, "openapi.yaml")
	if err := os.WriteFile(schemaPath, []byte("openapi: 3.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, root, remote, err := schemathesisSchemaTarget(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != schemaPath || root != sourceRoot || remote {
		t.Fatalf("local schema = target %q root %q remote %v", target, root, remote)
	}
	remoteTarget, remoteRoot, remote, err := schemathesisSchemaTarget("https://api.example.test/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	if remoteTarget != "https://api.example.test/openapi.json" || remoteRoot != "" || !remote {
		t.Fatalf("remote schema = target %q root %q remote %v", remoteTarget, remoteRoot, remote)
	}
}

func TestSchemathesisReportRejectsMissingOrMalformedEvidence(t *testing.T) {
	if _, err := parseSchemathesisReport(nil, "https://api.example.test"); err == nil {
		t.Fatal("missing report was treated as a completed scan")
	}
	if _, err := parseSchemathesisReport([]byte("not json"), "https://api.example.test"); err == nil {
		t.Fatal("malformed report was treated as a completed scan")
	}
	findings, err := parseSchemathesisReport([]byte("[]"), "https://api.example.test")
	if err != nil || len(findings) != 0 {
		t.Fatalf("valid clean report = %d findings, %v", len(findings), err)
	}
}
