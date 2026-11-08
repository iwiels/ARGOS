package tools

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

// publicOASTDomains are the providers Argos must never use without an
// explicit opt-in: they observe which target is being tested.
var publicOASTDomains = []string{
	"oast.fun",
	"oast.pro",
	"oast.online",
	"oast.site",
	"oast.live",
	"interact.sh",
}

// newOOBEnv builds a tool environment with its own local collector.
func newOOBEnv(t *testing.T) *Env {
	t.Helper()
	env := NewEnv(t.TempDir())
	t.Cleanup(func() {
		StopOOBCollector(env)
		if env.Scope != nil {
			env.Scope.Close()
		}
	})
	return env
}

// stubInteractsh replaces the interactsh-client launcher so the tool tests do
// not need the binary (nor a network round trip) to reach the external mode.
func stubInteractsh(t *testing.T) {
	t.Helper()
	previous := oobInteractshStart
	oobInteractshStart = func(ctx context.Context, env *Env, bin, domain, token string, wait int) (*oobSession, error) {
		return &oobSession{token: token, started: time.Now()}, nil
	}
	t.Cleanup(func() { oobInteractshStart = previous })
}

func oobResult(t *testing.T, res interface{}, errObj *mcp.ErrorObj) map[string]interface{} {
	t.Helper()
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Message)
	}
	result, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("expected a map result, got %T", res)
	}
	return result
}

func startOOB(t *testing.T, env *Env) map[string]interface{} {
	t.Helper()
	res, errObj := oobStart(context.Background(), env, 0)
	return oobResult(t, res, errObj)
}

func pollOOB(t *testing.T, env *Env, token string) map[string]interface{} {
	t.Helper()
	res, errObj := oobPoll(env, token)
	return oobResult(t, res, errObj)
}

// rawCallback sends an HTTP request to the collector over a raw socket: the
// tools package may not build its own http.Client.
func rawCallback(t *testing.T, port int, host, path string) {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("cannot reach the collector: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("cannot write the callback: %v", err)
	}
	_, _ = io.Copy(io.Discard, conn)
}

func TestOOBStartReturnsALocalDomain(t *testing.T) {
	t.Setenv("ARGOS_OAST_DOMAIN", "")
	t.Setenv("ARGOS_OAST_EXTERNAL", "")
	stubInteractsh(t)

	env := newOOBEnv(t)
	result := startOOB(t, env)

	domain, _ := result["oast_domain"].(string)
	if domain == "" {
		t.Fatal("expected an oast_domain in the result")
	}
	for _, public := range publicOASTDomains {
		if strings.Contains(domain, public) {
			t.Fatalf("the collector must not use the public provider %s, got %s", public, domain)
		}
	}
	if !strings.HasSuffix(domain, ".localhost") {
		t.Errorf("expected a local .localhost domain, got %s", domain)
	}
	if external, _ := result["external_oast"].(bool); external {
		t.Error("expected external_oast to be false by default")
	}
	if _, ok := result["dns_oast"].(bool); !ok {
		t.Error("expected the result to declare whether DNS callbacks are available")
	}
	if mode, _ := result["oast_mode"].(string); mode != string(oastModeLocal) {
		t.Errorf("expected the local mode, got %s", mode)
	}
}

func TestOOBStartWithConfiguredDomain(t *testing.T) {
	t.Setenv("ARGOS_OAST_DOMAIN", "oast.acme.com")
	t.Setenv("ARGOS_OAST_EXTERNAL", "")
	stubInteractsh(t)

	env := newOOBEnv(t)
	_, errObj := oobStart(context.Background(), env, 0)
	if errObj == nil || !strings.Contains(errObj.Message, "scoped OAST gateway") {
		t.Fatalf("configured remote OAST was not reported as unavailable: %v", errObj)
	}
}

func TestOOBStartExternalModeIsOptIn(t *testing.T) {
	t.Setenv("ARGOS_OAST_DOMAIN", "oast.acme.com")
	t.Setenv("ARGOS_OAST_EXTERNAL", "1")
	stubInteractsh(t)

	env := newOOBEnv(t)
	_, errObj := oobStart(context.Background(), env, 0)
	if errObj == nil || !strings.Contains(errObj.Message, "scoped OAST gateway") {
		t.Fatalf("external OAST was not reported as unavailable: %v", errObj)
	}
}

func TestOOBStartBlocksRemoteCollectorsUntilScopedGatewayExists(t *testing.T) {
	t.Setenv("ARGOS_OAST_DOMAIN", "oast.acme.com")
	t.Setenv("ARGOS_OAST_EXTERNAL", "1")
	toolsDir := t.TempDir()
	clientDir := filepath.Join(toolsDir, "interactsh-client")
	if err := os.MkdirAll(clientDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clientDir, "interactsh-client"), []byte("cached"), 0o700); err != nil {
		t.Fatal(err)
	}
	env := newOOBEnv(t)
	env.Downloader = NewDownloader(toolsDir)
	started := false
	previous := oobInteractshStart
	oobInteractshStart = func(context.Context, *Env, string, string, string, int) (*oobSession, error) {
		started = true
		return &oobSession{token: "external"}, nil
	}
	t.Cleanup(func() { oobInteractshStart = previous })

	_, errObj := oobStart(context.Background(), env, 0)
	if errObj == nil || !strings.Contains(errObj.Message, "scoped OAST gateway") {
		t.Fatalf("remote OAST was not reported as unavailable: %v", errObj)
	}
	if started {
		t.Fatal("remote OAST process started without a scoped gateway")
	}
}

func TestOOBStartExternalWithoutDomainFails(t *testing.T) {
	t.Setenv("ARGOS_OAST_DOMAIN", "")
	t.Setenv("ARGOS_OAST_EXTERNAL", "1")
	stubInteractsh(t)

	env := newOOBEnv(t)
	_, errObj := oobStart(context.Background(), env, 0)
	if errObj == nil {
		t.Fatal("expected the external mode without a domain to fail")
	}
	if !strings.Contains(errObj.Message, "ARGOS_OAST_DOMAIN") {
		t.Errorf("expected the error to name ARGOS_OAST_DOMAIN, got %q", errObj.Message)
	}
}

func TestOOBPollCorrelatesTheCallbackByToken(t *testing.T) {
	t.Setenv("ARGOS_OAST_DOMAIN", "")
	t.Setenv("ARGOS_OAST_EXTERNAL", "")
	stubInteractsh(t)

	env := newOOBEnv(t)
	start := startOOB(t, env)
	correlation, _ := start["correlation"].(string)
	if correlation == "" {
		t.Fatal("expected a correlation id in the start result")
	}
	port, _ := start["oast_port"].(int)
	if port == 0 {
		t.Fatal("expected the local port in the start result")
	}
	domain, _ := start["oast_domain"].(string)

	rawCallback(t, port, fmt.Sprintf("%s.%s:%d", correlation, domain, port), "/probe")

	// The callback is recorded by the collector before the response ends.
	var interactions []map[string]interface{}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		poll := pollOOB(t, env, correlation)
		raw, _ := poll["interactions"].([]map[string]interface{})
		if len(raw) > 0 {
			interactions = raw
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(interactions) == 0 {
		t.Fatal("expected the callback to be reported by poll")
	}
	if method, _ := interactions[0]["method"].(string); method != "GET" {
		t.Errorf("expected the method GET, got %q", method)
	}
	if url, _ := interactions[0]["url"].(string); !strings.Contains(url, "/probe") {
		t.Errorf("expected the callback URL to be reported, got %q", url)
	}
}

func TestOOBPollWithoutSessionFails(t *testing.T) {
	env := newOOBEnv(t)
	if _, errObj := oobPoll(env, ""); errObj == nil {
		t.Error("expected poll without correlation to fail")
	}
	if _, errObj := oobPoll(env, "unknown-correlation"); errObj == nil {
		t.Error("expected poll of an unknown correlation to fail")
	}
}

func TestOOBStopReleasesTheSession(t *testing.T) {
	t.Setenv("ARGOS_OAST_DOMAIN", "")
	t.Setenv("ARGOS_OAST_EXTERNAL", "")
	stubInteractsh(t)

	env := newOOBEnv(t)
	start := startOOB(t, env)
	correlation, _ := start["correlation"].(string)

	res, errObj := oobStop(env, correlation)
	stop := oobResult(t, res, errObj)
	if status, _ := stop["status"].(string); status != "stopped" {
		t.Errorf("expected the status stopped, got %q", status)
	}
	if _, errObj := oobPoll(env, correlation); errObj == nil {
		t.Error("expected the session to be gone after stop")
	}
}

func TestResolveOASTModes(t *testing.T) {
	t.Setenv("ARGOS_OAST_DOMAIN", "")
	t.Setenv("ARGOS_OAST_EXTERNAL", "")
	cfg, err := resolveOAST(t.TempDir())
	if err != nil {
		t.Fatalf("resolveOAST: %v", err)
	}
	if cfg.Mode != oastModeLocal || cfg.External {
		t.Errorf("expected the local mode without external traffic, got %s (external=%v)", cfg.Mode, cfg.External)
	}
	if cfg.DNSAvailable {
		t.Error("expected the DNS mode to be unavailable without an interactsh server")
	}
	if cfg.DNSReason == "" {
		t.Error("expected the reason why the DNS mode is unavailable")
	}

	t.Setenv("ARGOS_OAST_DOMAIN", "oast.acme.com")
	cfg, err = resolveOAST(t.TempDir())
	if err != nil {
		t.Fatalf("resolveOAST: %v", err)
	}
	if cfg.Mode != oastModeSelfHosted || cfg.Domain != "oast.acme.com" || cfg.External {
		t.Errorf("expected the self-hosted mode, got %s / %s / %v", cfg.Mode, cfg.Domain, cfg.External)
	}

	t.Setenv("ARGOS_OAST_EXTERNAL", "1")
	cfg, err = resolveOAST(t.TempDir())
	if err != nil {
		t.Fatalf("resolveOAST: %v", err)
	}
	if cfg.Mode != oastModeExternal || !cfg.External {
		t.Errorf("expected the external mode, got %s (external=%v)", cfg.Mode, cfg.External)
	}
	if cfg.Notice == "" {
		t.Error("expected an explicit notice about the third party in the external mode")
	}
}
