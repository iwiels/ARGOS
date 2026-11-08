package tools

import (
	"context"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

// oauthHasRule reports whether the findings carry the rule.
func oauthHasRule(findings []Finding, rule string) bool {
	for _, finding := range findings {
		if finding.RuleID == rule {
			return true
		}
	}
	return false
}

func TestOAuthMissingStateIsDetected(t *testing.T) {
	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-oauth-no-state",
		MaxRPS:       50,
	})

	report := auditOAuth(context.Background(), env, "https://app.example/login", "https://idp.example/authorize?client_id=app&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback", nil, 5*time.Second)
	if !oauthHasRule(report.findings, "oauth:missing-state") {
		t.Fatalf("expected the missing state finding, got %+v", report.findings)
	}
	for _, finding := range report.findings {
		if finding.RuleID == "oauth:missing-state" {
			if finding.Confidence != ConfidenceConfirmed {
				t.Errorf("confidence = %q, want confirmed", finding.Confidence)
			}
			if finding.CWE != "CWE-352" {
				t.Errorf("cwe = %q, want CWE-352", finding.CWE)
			}
		}
	}
}

func TestOAuthWithStateAndPKCEProducesNoFindings(t *testing.T) {
	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-oauth-hardened",
		MaxRPS:       50,
	})

	report := auditOAuth(context.Background(), env, "https://app.example/login",
		"https://idp.example/authorize?client_id=app&response_type=code&scope=profile&state=8f2b1c&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback",
		nil, 5*time.Second)
	if len(report.findings) != 0 {
		t.Fatalf("expected no findings for a hardened authorization request, got %d: %+v", len(report.findings), report.findings)
	}
}

func TestOAuthPlainPKCEAndOpenRedirectAreDetected(t *testing.T) {
	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-oauth-plain",
		MaxRPS:       50,
	})

	report := auditOAuth(context.Background(), env, "https://app.example/login",
		"https://idp.example/authorize?client_id=app&response_type=code&state=8f2b1c&code_challenge=verifier&code_challenge_method=plain&redirect_uri=https%3A%2F%2Fapp.example%2F*",
		nil, 5*time.Second)
	if !oauthHasRule(report.findings, "oauth:pkce-plain") {
		t.Errorf("expected the plain PKCE finding, got %+v", report.findings)
	}
	if !oauthHasRule(report.findings, "oauth:open-redirect-uri") {
		t.Errorf("expected the open redirect finding, got %+v", report.findings)
	}
}

func TestOAuthMixedResponseTypeIsDetected(t *testing.T) {
	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-oauth-mixed",
		MaxRPS:       50,
	})

	report := auditOAuth(context.Background(), env, "https://app.example/login",
		"https://idp.example/authorize?client_id=app&response_type=code%20token&state=8f2b1c&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback",
		nil, 5*time.Second)
	if !oauthHasRule(report.findings, "oauth:mixed-response-types") {
		t.Fatalf("expected the mixed response type finding, got %+v", report.findings)
	}
}
