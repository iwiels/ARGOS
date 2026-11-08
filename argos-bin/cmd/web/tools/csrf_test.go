package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
)

// csrfHasRule reports whether the findings carry the rule.
func csrfHasRule(findings []Finding, rule string) bool {
	for _, finding := range findings {
		if finding.RuleID == rule {
			return true
		}
	}
	return false
}

func TestCSRFFormWithoutTokenIsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc123; Path=/; HttpOnly; SameSite=Strict")
		_, _ = w.Write([]byte(`<html><body>
<form method="POST" action="/login">
  <input type="text" name="username" value="root">
  <input type="password" name="password" value="">
  <input type="submit" value="Sign in">
</form>
</body></html>`))
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-csrf-detected",
		MaxRPS:       50,
	})

	report := detectCSRF(context.Background(), env, srv.URL, nil, 5*time.Second)
	if !csrfHasRule(report.findings, "csrf:missing-token") {
		t.Fatalf("expected the missing token finding, got %+v", report.findings)
	}
	for _, finding := range report.findings {
		if finding.RuleID == "csrf:missing-token" {
			if finding.CWE != "CWE-352" {
				t.Errorf("cwe = %q, want CWE-352", finding.CWE)
			}
			if finding.Confidence != ConfidenceProbable {
				t.Errorf("confidence = %q, want probable", finding.Confidence)
			}
		}
	}
}

func TestCSRFProtectedFormProducesNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict")
		token := csrfTestToken()
		_, _ = fmt.Fprintf(w, `<html><body>
<form method="POST" action="/login">
  <input type="hidden" name="csrf_token" value="%s">
  <input type="text" name="username" value="root">
  <input type="submit" value="Sign in">
</form>
</body></html>`, token)
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-csrf-no-fp",
		MaxRPS:       50,
	})

	report := detectCSRF(context.Background(), env, srv.URL, nil, 5*time.Second)
	if len(report.findings) != 0 {
		t.Fatalf("expected no findings for a protected form, got %d: %+v", len(report.findings), report.findings)
	}
}

func TestCSRFStaticTokenIsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>
<form method="POST" action="/login">
  <input type="hidden" name="csrf_token" value="static-token-value">
  <input type="submit" value="Sign in">
</form>
</body></html>`))
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-csrf-static",
		MaxRPS:       50,
	})

	report := detectCSRF(context.Background(), env, srv.URL, nil, 5*time.Second)
	if !csrfHasRule(report.findings, "csrf:predictable-token") {
		t.Fatalf("expected the predictable token finding, got %+v", report.findings)
	}
}

func TestCSRFCredentialedCORSIsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-csrf-cors",
		MaxRPS:       50,
	})

	report := detectCSRF(context.Background(), env, srv.URL, nil, 5*time.Second)
	if !csrfHasRule(report.findings, "csrf:cors-credentialed-origin") {
		t.Fatalf("expected the credentialed CORS finding, got %+v", report.findings)
	}
}

func TestCSRFParseHTMLForms(t *testing.T) {
	body := `<form method="POST" action="/login"><input name="user"><input name='csrf_token' value='abc'></form>`
	forms := parseHTMLForms(body)
	if len(forms) != 1 {
		t.Fatalf("expected one form, got %d", len(forms))
	}
	if forms[0].Method != "POST" || forms[0].Action != "/login" {
		t.Errorf("unexpected form: %+v", forms[0])
	}
	if forms[0].Token != "csrf_token" || forms[0].TokenValue != "abc" {
		t.Errorf("unexpected token: %+v", forms[0])
	}
	if !forms[0].IsStateChanging() {
		t.Error("a POST form has to be state changing")
	}
}

// csrfTestToken returns a random token, so two requests never share it.
func csrfTestToken() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "fallback-token"
	}
	return hex.EncodeToString(buf)
}
