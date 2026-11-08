package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

// ssrfHasRule reports whether the findings carry the rule.
func ssrfHasRule(findings []Finding, rule string) bool {
	for _, finding := range findings {
		if finding.RuleID == rule {
			return true
		}
	}
	return false
}

func TestSSRFFetcherThatReturnsMetadataIsDetected(t *testing.T) {
	// The endpoint plays the role of a server side fetcher: it answers with
	// the content of the metadata service when it is asked for it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		switch {
		case target == "":
			w.WriteHeader(http.StatusBadRequest)
		case containsAny(target, "169.254.169.254", "2852039166", "0xA9FEA9FE"):
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(`{"accessKeyId":"AKIAEXAMPLE","SecretAccessKey":"wJalrXUtnFEMI","InstanceId":"i-0123456789"}`))
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-ssrf-detected",
		MaxRPS:       50,
	})
	spec := vectorSpec{URL: srv.URL + "/fetch", Param: "url", Surface: vectorSurfaceQuery}
	probes := []ssrfProbe{{
		Category: "cloud-metadata",
		Label:    "AWS instance metadata",
		Value:    "http://169.254.169.254/latest/meta-data/",
	}}

	report := detectSSRF(context.Background(), env, spec, probes, 5*time.Second)
	if !ssrfHasRule(report.findings, "ssrf:cloud-metadata-exposure") {
		t.Fatalf("expected the metadata exposure finding, got %+v", report.findings)
	}
	for _, finding := range report.findings {
		if finding.RuleID == "ssrf:cloud-metadata-exposure" {
			if finding.Confidence != ConfidenceConfirmed {
				t.Errorf("confidence = %q, want confirmed", finding.Confidence)
			}
			if finding.CWE != "CWE-918" {
				t.Errorf("cwe = %q, want CWE-918", finding.CWE)
			}
			if payload, _ := finding.Evidence["payload"].(string); payload != "http://169.254.169.254/latest/meta-data/" {
				t.Errorf("evidence payload = %q, want the exact probe", payload)
			}
		}
	}
}

func TestSSRFEchoingTargetProducesNoFindings(t *testing.T) {
	// The endpoint reflects the URL it receives and never fetches it: it is
	// the classic false positive of a naive SSRF detector.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fetching " + r.URL.Query().Get("url")))
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-ssrf-no-fp",
		MaxRPS:       50,
	})
	spec := vectorSpec{URL: srv.URL + "/fetch", Param: "url", Surface: vectorSurfaceQuery}
	probes := []ssrfProbe{
		{Category: "cloud-metadata", Label: "metadata", Value: "http://169.254.169.254/latest/meta-data/"},
		{Category: "loopback", Label: "loopback", Value: "http://127.0.0.1/"},
		{Category: "private-network", Label: "private", Value: "http://10.0.0.1/"},
	}

	report := detectSSRF(context.Background(), env, spec, probes, 5*time.Second)
	if len(report.findings) != 0 {
		t.Fatalf("expected no findings for an echoing target, got %d: %+v", len(report.findings), report.findings)
	}
}

func TestSSRFBaselineDoesNotReachAThirdParty(t *testing.T) {
	// The baseline value has to be unresolvable: the engagement must not
	// send a request to an unknown host.
	if ssrfBaselineValue != "http://argos-ssrf-baseline.invalid/" {
		t.Fatalf("unexpected baseline value: %q", ssrfBaselineValue)
	}
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if len(needle) > 0 && len(value) >= len(needle) {
			for i := 0; i+len(needle) <= len(value); i++ {
				if value[i:i+len(needle)] == needle {
					return true
				}
			}
		}
	}
	return false
}
