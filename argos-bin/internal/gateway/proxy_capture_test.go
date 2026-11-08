package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
	"github.com/iwiels/ARGOS/argos-bin/internal/traffic"
)

func TestHTTPProxyCapturesRedactedExchangeWhenConfigured(t *testing.T) {
	const sessionID = "ses_gateway_capture_test"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/submit" {
			t.Errorf("upstream request = %s %s, want POST /submit", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"result":"captured"}`)
	}))
	defer target.Close()

	guard, err := scope.New(scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		MaxRPS:       100,
		SessionID:    sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	store := traffic.NewStore(t.TempDir())
	proxy := httptest.NewServer(NewHandler(guard, CaptureConfig{
		Store:      store,
		SessionID:  sessionID,
		SourceTool: "nuclei",
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	request, err := http.NewRequest(http.MethodPost, target.URL+"/submit?token=url-secret", strings.NewReader(`{"password":"body-secret","action":"scan"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer header-secret")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(responseBody) != `{"result":"captured"}` {
		t.Fatalf("proxy response = %d %s", response.StatusCode, responseBody)
	}

	exchanges, total := store.List(sessionID, traffic.Filter{})
	if total != 1 || len(exchanges) != 1 {
		t.Fatalf("captured exchanges = %d (total %d), want one", len(exchanges), total)
	}
	exchange := exchanges[0]
	if exchange.SourceTool != "nuclei" || exchange.Method != http.MethodPost || exchange.Status != http.StatusOK {
		t.Fatalf("captured exchange metadata = %#v", exchange)
	}
	if !strings.Contains(exchange.URL, "token=%2A%2A%2A") && !strings.Contains(exchange.URL, "token=***") {
		t.Fatalf("captured URL did not redact its token: %s", exchange.URL)
	}
	if got := exchange.Headers["Authorization"]; len(got) != 1 || got[0] != "Bearer ***" {
		t.Fatalf("captured Authorization header = %q", got)
	}
	if strings.Contains(string(exchange.RequestBody), "body-secret") || !strings.Contains(string(exchange.RequestBody), "[REDACTED]") {
		t.Fatalf("captured request body was not redacted: %s", exchange.RequestBody)
	}
	if string(exchange.ResponseBody) != `{"result":"captured"}` {
		t.Fatalf("captured response body = %s", exchange.ResponseBody)
	}
}

func TestHTTPSProxyCapturesOnlyTunnelMetadata(t *testing.T) {
	const sessionID = "ses_gateway_tunnel_capture_test"
	store := traffic.NewStore(t.TempDir())
	capture := CaptureConfig{
		Store:      store,
		SessionID:  sessionID,
		SourceTool: "httpx",
	}
	started := time.Now().Add(-25 * time.Millisecond)
	capture.recordTunnel("https://example.test:443/", started)
	exchanges, total := store.List(sessionID, traffic.Filter{})
	if total != 1 || len(exchanges) != 1 {
		t.Fatalf("captured exchanges = %d (total %d), want one CONNECT tunnel record", len(exchanges), total)
	}
	exchange := exchanges[0]
	if exchange.Method != http.MethodConnect || exchange.Status != http.StatusOK || exchange.SourceTool != "httpx" {
		t.Fatalf("captured tunnel metadata = %#v", exchange)
	}
	if len(exchange.RequestBody) != 0 || len(exchange.ResponseBody) != 0 {
		t.Fatalf("TLS tunnel capture unexpectedly contains plaintext payloads: %#v", exchange)
	}
}
