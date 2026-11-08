package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecuteRejectsInvalidSessionBeforeContactingServer(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := execute([]string{"run", "--server", server.URL, "--session", "invalid", "--prompt", "audit"}, strings.NewReader(""), &stdout, &stderr)

	if code != 1 {
		t.Fatalf("got exit code %d, want 1", code)
	}
	if requests != 0 {
		t.Fatalf("invalid session must be rejected before HTTP request, got %d requests", requests)
	}
	if !strings.Contains(stderr.String(), "session ID") {
		t.Fatalf("expected session validation error, got %q", stderr.String())
	}
}

func TestExecuteRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("got exit code %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "run, status, cancel, export") {
		t.Fatalf("expected command list, got %q", stderr.String())
	}
}

func TestExecutePrintsBuildVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := execute([]string{"--version"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("got exit code %d, want 0; stderr=%q", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "argos-runner ") {
		t.Fatalf("unexpected version output %q", stdout.String())
	}
}
