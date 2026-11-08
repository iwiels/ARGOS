package tools

import (
	"testing"
)

func TestParseTestsslFindings(t *testing.T) {
	mockJSON := `[
		{"id": "SSLv3", "severity": "CRITICAL", "finding": "offered (deprecated)"},
		{"id": "cert_expirationStatus", "severity": "WARN", "finding": "certificate expired in 5 days"}
	]`
	findings := parseTestsslJSON([]byte(mockJSON), "https://example.com")
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Severity != "high" {
		t.Fatalf("expected high severity for SSLv3, got %s", findings[0].Severity)
	}
}
