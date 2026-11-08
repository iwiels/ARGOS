package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

// sstiHasRule reports whether the findings carry the rule.
func sstiHasRule(findings []Finding, rule string) bool {
	for _, finding := range findings {
		if finding.RuleID == rule {
			return true
		}
	}
	return false
}

func TestSSTIEvaluatedExpressionIsDetected(t *testing.T) {
	// The endpoint renders the input with a template engine: the arithmetic
	// expression comes back evaluated.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		switch name {
		case "{{7*7}}":
			_, _ = w.Write([]byte("<p>Hello 49</p>"))
		case "${7*7}":
			_, _ = w.Write([]byte("<p>Hello 49</p>"))
		default:
			_, _ = w.Write([]byte("<p>Hello " + name + "</p>"))
		}
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-ssti-detected",
		MaxRPS:       50,
	})
	spec := vectorSpec{URL: srv.URL + "/greet", Param: "name", Surface: vectorSurfaceQuery}

	report := detectSSTI(context.Background(), env, spec, defaultSSTIProbes(), 5*time.Second)
	if !sstiHasRule(report.findings, "ssti:expression-evaluated") {
		t.Fatalf("expected the template injection finding, got %+v", report.findings)
	}
	for _, finding := range report.findings {
		if finding.RuleID == "ssti:expression-evaluated" {
			if finding.CWE != "CWE-1336" {
				t.Errorf("cwe = %q, want CWE-1336", finding.CWE)
			}
			if finding.Confidence != ConfidenceConfirmed {
				t.Errorf("confidence = %q, want confirmed", finding.Confidence)
			}
			if payload, _ := finding.Evidence["payload"].(string); payload == "" {
				t.Error("the evidence has to carry the exact payload")
			}
		}
	}
}

func TestSSTINotEvaluatedProducesNoFindings(t *testing.T) {
	// The endpoint echoes the input: the template never evaluated it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<p>Hello " + r.URL.Query().Get("name") + "</p>"))
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-ssti-no-fp",
		MaxRPS:       50,
	})
	spec := vectorSpec{URL: srv.URL + "/greet", Param: "name", Surface: vectorSurfaceQuery}

	report := detectSSTI(context.Background(), env, spec, defaultSSTIProbes(), 5*time.Second)
	if len(report.findings) != 0 {
		t.Fatalf("expected no findings when the payload is not evaluated, got %d: %+v", len(report.findings), report.findings)
	}
}

func TestSSTIProbeListCarriesTheEngines(t *testing.T) {
	probes := defaultSSTIProbes()
	if len(probes) < 5 {
		t.Fatalf("expected at least five probes, got %d", len(probes))
	}
	found := false
	for _, probe := range probes {
		if probe.Payload == "{{7*7}}" && probe.Result == "49" {
			found = true
		}
	}
	if !found {
		t.Fatal("the Jinja2 probe has to be {{7*7}}")
	}
}
