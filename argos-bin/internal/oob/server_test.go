package oob

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// newTestServer starts a collector on an ephemeral loopback port.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	return srv
}

// sendCallback issues a request against the collector carrying the token as
// the leftmost label of the Host header.
//
// The connection always goes to the loopback address: the "*.localhost" label
// is what the auditor injects into the target, not something the test host
// has to resolve.
func sendCallback(t *testing.T, srv *Server, method, token, path string, body io.Reader) *http.Response {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d%s", srv.Port(), path)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("cannot build the callback request: %v", err)
	}
	req.Host = fmt.Sprintf("%s.%s:%d", token, srv.Domain(), srv.Port())
	if body != nil {
		req.Header.Set("Content-Type", "text/plain")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestCallbackWithKnownTokenIsPolled(t *testing.T) {
	srv := newTestServer(t)
	srv.Register("tok123")

	resp := sendCallback(t, srv, http.MethodPost, "tok123", "/probe?x=1", strings.NewReader("payload"))
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a known token, got %d", resp.StatusCode)
	}

	events := srv.Poll("tok123")
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	event := events[0]
	if event.Method != http.MethodPost {
		t.Errorf("expected method POST, got %s", event.Method)
	}
	if event.Protocol != "http" {
		t.Errorf("expected protocol http, got %s", event.Protocol)
	}
	if !strings.Contains(event.URL, "/probe") {
		t.Errorf("expected the URL to keep the request path, got %s", event.URL)
	}
	if string(event.Body) != "payload" {
		t.Errorf("expected body %q, got %q", "payload", string(event.Body))
	}
	if event.Token != "tok123" {
		t.Errorf("expected token tok123, got %s", event.Token)
	}
	if event.RemoteAddr == "" {
		t.Error("expected the remote address to be recorded")
	}
	if got := http.Header(event.Headers).Get("Content-Type"); got != "text/plain" {
		t.Errorf("expected the headers to be recorded, got %q", got)
	}
	if event.Timestamp.IsZero() {
		t.Error("expected the event to carry a timestamp")
	}
}

func TestCallbackTokenInPathIsCorrelated(t *testing.T) {
	srv := newTestServer(t)
	srv.Register("pathToken")

	resp := sendCallback(t, srv, http.MethodGet, "pathToken", "/pathToken/callback", nil)
	_, _ = io.Copy(io.Discard, resp.Body)

	if events := srv.Poll("pathToken"); len(events) != 1 {
		t.Fatalf("expected 1 event correlated by path token, got %d", len(events))
	}
}

func TestCallbackWithUnknownTokenIsNotRecorded(t *testing.T) {
	srv := newTestServer(t)
	srv.Register("tok123")

	resp := sendCallback(t, srv, http.MethodGet, "wrongtoken", "/probe", nil)
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for an unknown token, got %d", resp.StatusCode)
	}
	if events := srv.Poll("tok123"); len(events) != 0 {
		t.Fatalf("expected no event for a known token, got %d", len(events))
	}
	for _, token := range []string{"wrongtoken", "", "tok"} {
		if events := srv.Poll(token); len(events) != 0 {
			t.Fatalf("expected no event under token %q, got %d", token, len(events))
		}
	}
}

func TestNonCallbackRequestIsIgnored(t *testing.T) {
	srv := newTestServer(t)
	srv.Register("tok123")

	resp := sendCallback(t, srv, http.MethodGet, "favicon", "/favicon.ico", nil)
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for a non-callback request, got %d", resp.StatusCode)
	}
	if events := srv.Poll("tok123"); len(events) != 0 {
		t.Fatalf("expected no event for a non-callback request, got %d", len(events))
	}
}

func TestPollIsDestructive(t *testing.T) {
	srv := newTestServer(t)
	srv.Register("tok123")

	resp := sendCallback(t, srv, http.MethodGet, "tok123", "/probe", nil)
	_, _ = io.Copy(io.Discard, resp.Body)

	first := srv.Poll("tok123")
	if len(first) != 1 {
		t.Fatalf("expected 1 event on the first poll, got %d", len(first))
	}
	second := srv.Poll("tok123")
	if len(second) != 0 {
		t.Fatalf("expected the second poll to return nothing, got %d", len(second))
	}
}

func TestStopReleasesThePort(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot reserve a port: %v", err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	srv, err := NewServer(addr)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Stop is idempotent.
	if err := srv.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}

	again, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the port was not released after Stop: %v", err)
	}
	_ = again.Close()
}

func TestCORSHeadersAreServed(t *testing.T) {
	srv := newTestServer(t)
	srv.Register("tok123")

	resp := sendCallback(t, srv, http.MethodGet, "tok123", "/probe", nil)
	_, _ = io.Copy(io.Discard, resp.Body)

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("expected Access-Control-Allow-Origin *, got %q", got)
	}
}

func TestPreflightIsAnswered(t *testing.T) {
	srv := newTestServer(t)
	srv.Register("tok123")

	resp := sendCallback(t, srv, http.MethodOptions, "tok123", "/probe", nil)
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204 for a preflight request, got %d", resp.StatusCode)
	}
}

func TestDomainIsLocalAndUnique(t *testing.T) {
	srv := newTestServer(t)
	domain := srv.Domain()
	if !strings.HasSuffix(domain, ".localhost") {
		t.Errorf("expected a .localhost domain for a loopback bind, got %s", domain)
	}
	other := newTestServer(t)
	if other.Domain() == domain {
		t.Error("expected two collectors to get different domains")
	}
}

func TestEventIsRecordedBeforeTheResponseCompletes(t *testing.T) {
	srv := newTestServer(t)
	srv.Register("tok123")

	resp := sendCallback(t, srv, http.MethodGet, "tok123", "/probe", nil)
	_, _ = io.Copy(io.Discard, resp.Body)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if events := srv.Poll("tok123"); len(events) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the event was not recorded")
}
