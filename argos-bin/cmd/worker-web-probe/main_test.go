package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/iwiels/argos-auditor/argos-bin/internal/gatewayprotocol"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/workerpreflight"
	"github.com/iwiels/argos-auditor/argos-bin/internal/workerprobe"
)

func TestWorkerVersionUsesPackageVersionAndDevFallback(t *testing.T) {
	t.Setenv("ARGOS_WORKER_VERSION", "1.2.3")
	if got := workerVersion(); got != "1.2.3" {
		t.Fatalf("workerVersion() = %q, want package version", got)
	}
	t.Setenv("ARGOS_WORKER_VERSION", " ")
	if got := workerVersion(); got != "dev" {
		t.Fatalf("workerVersion() = %q, want dev fallback", got)
	}
}

func TestExecuteProbeUsesRelayClientAndKeepsControllerScope(t *testing.T) {
	t.Setenv("ARGOS_AUDIT_LOG_DIR", t.TempDir())
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>page</body></html>")
	}))
	defer target.Close()

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			t.Errorf("probe bypassed the configured proxy: request URI %q", r.RequestURI)
			http.Error(w, "proxy request must use an absolute URL", http.StatusBadRequest)
			return
		}
		response, err := (&http.Transport{}).RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	defer proxy.Close()

	client, monitor, err := workerpreflight.NewClientWithMonitor(proxy.URL)
	if err != nil {
		t.Fatalf("NewClientWithMonitor: %v", err)
	}
	request := workerprobe.Request{
		Protocol:    workerprobe.ProtocolVersion,
		Tool:        "web.csrf",
		Params:      []byte(`{"target":"` + target.URL + `"}`),
		SessionID:   "ses_worker_web_probe",
		RunID:       "run_worker_web_probe",
		OperationID: "call_worker_web_probe",
		Scope:       &mcp.ScopeSnapshot{CIDRs: []string{"127.0.0.0/8"}, MaxRPS: 50},
	}
	response, err := executeProbe(context.Background(), request, client, monitor)
	if err != nil {
		t.Fatalf("executeProbe: %v", err)
	}
	digest, err := workerprobe.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := workerprobe.ValidateResponse(response, digest); err != nil {
		t.Fatalf("worker response: %v", err)
	}
	if targetHits.Load() == 0 {
		t.Fatalf("the probe did not reach the target through its proxy: %+v", response.Error)
	}
	if monitor.FailureCount() != 0 {
		t.Fatalf("gateway failures = %d, want 0", monitor.FailureCount())
	}
}

func TestExecuteProbeDiscardsPartialResultAfterGatewayDenial(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(gatewayprotocol.ScopeBlockedHeader, "true")
		http.Error(w, "target blocked by session scope", http.StatusForbidden)
	}))
	defer proxy.Close()
	client, monitor, err := workerpreflight.NewClientWithMonitor(proxy.URL)
	if err != nil {
		t.Fatalf("NewClientWithMonitor: %v", err)
	}
	request := workerprobe.Request{
		Protocol:    workerprobe.ProtocolVersion,
		Tool:        "web.csrf",
		Params:      []byte(`{"target":"http://target.example.test"}`),
		SessionID:   "ses_worker_web_probe_blocked",
		RunID:       "run_worker_web_probe_blocked",
		OperationID: "call_worker_web_probe_blocked",
		Scope:       &mcp.ScopeSnapshot{Domains: []string{"target.example.test"}, MaxRPS: 50},
	}
	response, err := executeProbe(context.Background(), request, client, monitor)
	if err != nil {
		t.Fatalf("executeProbe: %v", err)
	}
	if response.Complete || response.GatewayFailures == 0 || len(response.Result) != 0 {
		t.Fatalf("response = %+v, error=%+v, want incomplete with no partial result", response, response.Error)
	}
}
