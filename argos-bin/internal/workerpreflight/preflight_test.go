package workerpreflight

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/gatewayprotocol"
)

func TestRunUsesTheGatewayForHealthAndWAFProbes(t *testing.T) {
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "abc123")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			t.Errorf("gateway received non-proxy request URI %q", r.RequestURI)
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

	client, err := NewClient(proxy.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := Run(context.Background(), target.URL, 3, client)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Complete || len(result.Probes) != 3 {
		t.Fatalf("result = %+v, want three complete probes", result)
	}
	for _, probe := range result.Probes {
		if probe.Status != http.StatusOK {
			t.Errorf("probe status = %d, want 200", probe.Status)
		}
	}
	if len(result.WAFVendors) == 0 || result.WAFVendors[0] != "Cloudflare" {
		t.Fatalf("WAF vendors = %v, want Cloudflare", result.WAFVendors)
	}
	if targetHits != 3 {
		t.Fatalf("target hits = %d, want only the three requested health probes with WAF fingerprinting from their responses", targetHits)
	}
}

func TestRunAbortsOnScopeGatewayDenial(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(gatewayprotocol.ScopeBlockedHeader, "true")
		http.Error(w, "target blocked by session scope", http.StatusForbidden)
	}))
	defer proxy.Close()

	client, err := NewClient(proxy.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = Run(context.Background(), "http://target.example.test/", 1, client)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "scope") {
		t.Fatalf("Run error = %v, want an explicit scope denial", err)
	}
}

func TestClientMonitorRecordsGatewayDenials(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(gatewayprotocol.ScopeBlockedHeader, "true")
		http.Error(w, "target blocked by session scope", http.StatusForbidden)
	}))
	defer proxy.Close()

	client, monitor, err := NewClientWithMonitor(proxy.URL)
	if err != nil {
		t.Fatalf("NewClientWithMonitor: %v", err)
	}
	response, err := client.Get("http://target.example.test/")
	if err == nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal("client did not report a gateway denial")
	}
	if monitor.FailureCount() != 1 {
		t.Fatalf("gateway failure count = %d, want 1", monitor.FailureCount())
	}
}

func TestNewClientRejectsNonLoopbackProxy(t *testing.T) {
	if _, err := NewClient("http://192.0.2.10:3128"); err == nil {
		t.Fatal("NewClient accepted a proxy outside the worker loopback")
	}
}

func TestRunHonorsCancellationDuringHealthProbe(t *testing.T) {
	started := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer target.Close()

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := (&http.Transport{}).RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	defer proxy.Close()

	client, err := NewClient(proxy.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := Run(ctx, target.URL, 1, client)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("health probe did not reach the target")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("Run succeeded after its context was canceled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

func TestValidateResultRequiresCompleteExactProbeSet(t *testing.T) {
	valid := Result{
		Protocol: ProtocolVersion,
		Target:   "https://app.example.test/",
		Complete: true,
		Probes:   []Probe{{Status: 200}, {Status: 403}},
	}
	if err := ValidateResult(valid, valid.Target, 2); err != nil {
		t.Fatalf("ValidateResult(valid): %v", err)
	}

	tests := []struct {
		name   string
		result Result
	}{
		{name: "incomplete", result: Result{Protocol: ProtocolVersion, Target: valid.Target, Probes: valid.Probes}},
		{name: "wrong target", result: Result{Protocol: ProtocolVersion, Target: "https://other.example.test/", Complete: true, Probes: valid.Probes}},
		{name: "missing probe", result: Result{Protocol: ProtocolVersion, Target: valid.Target, Complete: true, Probes: valid.Probes[:1]}},
		{name: "invalid status", result: Result{Protocol: ProtocolVersion, Target: valid.Target, Complete: true, Probes: []Probe{{Status: 0}, valid.Probes[1]}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateResult(test.result, valid.Target, 2); err == nil {
				t.Fatal("ValidateResult accepted an invalid result")
			}
		})
	}
}
