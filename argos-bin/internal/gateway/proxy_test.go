package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/gatewayprotocol"
	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

func TestHTTPProxyEnforcesScopeAndRouteExclusions(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "proxied")
	}))
	defer target.Close()

	guard, err := scope.New(scope.ScopeConfig{
		AllowedCIDRs:  []string{"127.0.0.0/8"},
		ExcludedHosts: []string{"/admin/*"},
		MaxRPS:        100,
		SessionID:     "ses_gateway_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	proxy := httptest.NewServer(NewHandler(guard))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	response, err := client.Get(target.URL + "/public")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("allowed request status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	response, err = client.Get(target.URL + "/admin/users")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("excluded request status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	if response.Header.Get(gatewayprotocol.ScopeBlockedHeader) != "true" {
		t.Fatalf("excluded request did not include the scope-block marker: %v", response.Header)
	}
	if hits != 1 {
		t.Fatalf("target received %d requests, want only the in-scope request", hits)
	}
}

func TestHTTPProxyBlocksCanonicalizedExcludedRoutes(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	guard, err := scope.New(scope.ScopeConfig{
		AllowedCIDRs:  []string{"127.0.0.0/8"},
		ExcludedHosts: []string{"/admin/*"},
		MaxRPS:        100,
		SessionID:     "ses_gateway_encoded_exclusion_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	proxy := httptest.NewServer(NewHandler(guard))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	for _, path := range []string{
		"/admin",
		"/%61dmin/users",
		"/safe/../admin/users",
		"/safe/%2e%2e/admin/users",
		"/safe/%252e%252e/admin/users",
		"/%2fadmin/users",
		"/ADMIN/users",
	} {
		t.Run(path, func(t *testing.T) {
			response, err := client.Get(target.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("excluded route %q status = %d, want %d", path, response.StatusCode, http.StatusForbidden)
			}
			if response.Header.Get(gatewayprotocol.ScopeBlockedHeader) != "true" {
				t.Fatalf("excluded route %q did not include the scope-block marker: %v", path, response.Header)
			}
		})
	}

	if got := targetHits.Load(); got != 0 {
		t.Fatalf("target received %d requests for excluded routes, want 0", got)
	}
}

func TestConnectIsBlockedWhenRouteExclusionsCannotBeInspected(t *testing.T) {
	guard, err := scope.New(scope.ScopeConfig{
		AllowedDomains: []string{"app.example.com"},
		ExcludedHosts:  []string{"/admin/*"},
		MaxRPS:         100,
		SessionID:      "ses_gateway_connect_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	request := httptest.NewRequest(http.MethodConnect, "https://app.example.com:443", nil)
	recorder := httptest.NewRecorder()
	NewHandler(guard).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("CONNECT status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if recorder.Header().Get(gatewayprotocol.ScopeBlockedHeader) != "true" {
		t.Fatalf("blocked CONNECT did not include the scope-block marker: %v", recorder.Header())
	}
}

func TestHTTPProxyBlocksTargetsOutsideScope(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("out-of-scope request reached the target")
	}))
	defer target.Close()

	guard, err := scope.New(scope.ScopeConfig{
		AllowedCIDRs: []string{"192.0.2.0/24"},
		MaxRPS:       100,
		SessionID:    "ses_gateway_oos_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	proxy := httptest.NewServer(NewHandler(guard))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-scope status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	if response.Header.Get(gatewayprotocol.ScopeBlockedHeader) != "true" {
		t.Fatalf("out-of-scope response did not include the scope-block marker: %v", response.Header)
	}
}

func TestHTTPProxyMarksUpstreamFailures(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	targetURL := target.URL
	target.Close()

	guard, err := scope.New(scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		MaxRPS:       100,
		SessionID:    "ses_gateway_upstream_failure",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	proxy := httptest.NewServer(NewHandler(guard))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("upstream failure status = %d, want %d", response.StatusCode, http.StatusBadGateway)
	}
	if response.Header.Get(gatewayprotocol.GatewayErrorHeader) != "true" {
		t.Fatalf("upstream failure did not include the gateway-error marker: %v", response.Header)
	}
}
