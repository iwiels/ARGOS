package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/guard"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
)

// envWithScope builds a tool environment whose only HTTP client is bound to
// the given scope, exactly like NewEnv does in production.
func envWithScope(t *testing.T, cfg scope.ScopeConfig) *Env {
	t.Helper()
	t.Setenv("ARGOS_AUDIT_LOG_DIR", t.TempDir())
	sg, err := scope.New(cfg)
	if err != nil {
		t.Fatalf("failed to create ScopeGuard: %v", err)
	}
	t.Cleanup(sg.Close)
	return &Env{Scope: sg, HTTP: sg.Client()}
}

func controllerScopeCall(sessionID, operationID string, cidrs, domains []string) mcp.ToolContext {
	return mcp.ToolContext{
		Ctx:         context.Background(),
		SessionID:   sessionID,
		RunID:       "run_" + operationID,
		OperationID: operationID,
		Scope:       &mcp.ScopeSnapshot{CIDRs: cidrs, Domains: domains, MaxRPS: 50},
	}
}

// countingServer answers with a Cloudflare fingerprint and counts the hits.
func countingServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "abc123")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("blocked"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestValidateWebTargetUsesControllerScopeSnapshot(t *testing.T) {
	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"10.0.0.0/8"},
		SessionID:    "process-scope",
	})
	controller := mcp.ToolContext{
		SessionID:   "ses_controller_scope",
		OperationID: "call_controller_scope",
		Scope: &mcp.ScopeSnapshot{
			CIDRs: []string{"127.0.0.0/8"},
		},
	}

	if _, err := validateWebTargetWithToolContext(env, controller, "http://127.0.0.1:8080"); err != nil {
		t.Fatalf("controller-authorized target was rejected by the process scope: %v", err)
	}

	controller.Scope.CIDRs = []string{"192.0.2.0/24"}
	if _, err := validateWebTargetWithToolContext(env, controller, "http://127.0.0.1:8080"); err == nil {
		t.Fatal("target authorized only by the process scope passed controller-scope validation")
	}
}

func TestScopedToolEnvironmentUsesPerCallScope(t *testing.T) {
	base := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"10.0.0.0/8"},
		SessionID:    "process-scope",
	})
	call := mcp.ToolContext{
		SessionID:   "ses_call_scope",
		OperationID: "call_scope_123",
		Scope:       &mcp.ScopeSnapshot{CIDRs: []string{"127.0.0.0/8"}},
	}

	perCall, release, errObj := scopedToolEnvironment(base, call)
	if errObj != nil {
		t.Fatalf("controller scope could not create a per-call environment: %v", errObj)
	}
	defer release()
	if perCall == base {
		t.Fatal("controller-scoped call reused the process-wide environment")
	}
	if !perCall.Scope.Allowed("127.0.0.1") || perCall.Scope.Allowed("10.0.0.1") {
		t.Fatal("per-call scope did not replace the process-wide allowlist")
	}
	if base.Scope.Allowed("127.0.0.1") || !base.Scope.Allowed("10.0.0.1") {
		t.Fatal("creating a per-call scope mutated the shared process environment")
	}
}

func TestScopedToolEnvironmentRequiresContainerWorkerProxy(t *testing.T) {
	t.Setenv("ARGOS_WORKER_PROXY_URL", "")
	t.Setenv("ARGOS_AUDIT_LOG_DIR", t.TempDir())
	base := &Env{RequireWorkerProxy: true}
	call := mcp.ToolContext{
		Ctx:         context.Background(),
		SessionID:   "ses_worker_proxy_required",
		OperationID: "call_worker_proxy_required",
		Scope:       &mcp.ScopeSnapshot{Domains: []string{"target.example.test"}},
	}

	perCall, release, errObj := scopedToolEnvironment(base, call)
	if errObj != nil {
		t.Fatalf("controller scope was rejected: %v", errObj)
	}
	defer release()
	if _, err := perCall.Client().Get("http://target.example.test/"); !errors.Is(err, scope.ErrWorkerProxyRequired) {
		t.Fatalf("HTTP error = %v, want ErrWorkerProxyRequired", err)
	}
}

func TestWorkerProxyDefersTargetAuthorizationToScopeGateway(t *testing.T) {
	t.Setenv("ARGOS_WORKER_PROXY_URL", "")
	t.Setenv("ARGOS_AUDIT_LOG_DIR", t.TempDir())
	base := &Env{RequireWorkerProxy: true}
	call := controllerScopeCall("ses_gateway_scope", "call_gateway_scope", nil, []string{"target.example.test"})

	target, errObj := validateWebTargetWithToolContext(base, call, "https://target.example.test/audit")
	if errObj != nil || target != "https://target.example.test/audit" {
		t.Fatalf("worker-proxy target = %q, error = %v; want syntactically valid target deferred to gateway", target, errObj)
	}

	guard, err := scope.New(scope.ScopeConfig{AllowedDomains: []string{"target.example.test"}, RequireWorkerProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	domainEnv := &Env{Scope: guard, RequireWorkerProxy: true}
	domain, errObj := validateDomainWithEnv(domainEnv, "target.example.test")
	if errObj != nil || domain != "target.example.test" {
		t.Fatalf("worker-proxy domain = %q, error = %v; want syntactically valid domain deferred to gateway", domain, errObj)
	}
}

func TestRegisterAllBlocksHostOnlyProbesInContainerRequiredProfile(t *testing.T) {
	env := &Env{RequireWorkerProxy: true}
	server := mcp.NewServer(mcp.ServerInfo{Name: "argos-web-test"})
	RegisterAll(server, env)

	wantReasons := map[string]string{
		"web.smuggle": "raw tcp",
		"web.sqli":    "nuclei/sqlmap",
		"web.ssrf":    "oob callback",
	}
	for name, reason := range wantReasons {
		handler := server.GetToolHandler(name)
		if handler == nil {
			t.Fatalf("tool %q was not registered", name)
		}
		_, errObj := handler(mcp.ToolContext{}, json.RawMessage(`{"target":"https://target.example.test"}`))
		if errObj == nil || !strings.Contains(strings.ToLower(errObj.Message), "worker") || !strings.Contains(strings.ToLower(errObj.Message), reason) {
			t.Fatalf("tool %q error = %v, want its explicit worker limitation %q", name, errObj, reason)
		}
	}
}

func TestRegisterAllLeavesWAFAvailableBehindControllerScopeValidation(t *testing.T) {
	server := mcp.NewServer(mcp.ServerInfo{Name: "argos-web-test"})
	RegisterAll(server, &Env{RequireWorkerProxy: true})
	handler := server.GetToolHandler("web.waf")
	if handler == nil {
		t.Fatal("web.waf was not registered")
	}
	_, errObj := handler(mcp.ToolContext{}, json.RawMessage(`{"target":"https://target.example.test"}`))
	if errObj == nil || !strings.Contains(strings.ToLower(errObj.Message), "controller session") {
		t.Fatalf("web.waf error = %v, want controller-scope validation rather than a host-only unavailability error", errObj)
	}
}

func TestRegisterAllRoutesHTTPNativeProbesThroughWorkerScopeValidation(t *testing.T) {
	server := mcp.NewServer(mcp.ServerInfo{Name: "argos-web-test"})
	RegisterAll(server, &Env{RequireWorkerProxy: true})
	for _, name := range []string{"web.csrf", "web.graphql", "web.jwt", "web.oauth", "web.prompt_injection", "web.ssti"} {
		handler := server.GetToolHandler(name)
		if handler == nil {
			t.Fatalf("tool %q was not registered", name)
		}
		_, errObj := handler(mcp.ToolContext{}, json.RawMessage(`{"target":"https://target.example.test"}`))
		if errObj == nil || !strings.Contains(strings.ToLower(errObj.Message), "controller session") {
			t.Fatalf("tool %q error = %v, want controller-scope validation before worker dispatch", name, errObj)
		}
	}
}

func TestScopedToolEnvironmentRejectsMissingControllerScope(t *testing.T) {
	base := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "process-scope",
	})
	tests := []struct {
		name string
		call mcp.ToolContext
	}{
		{name: "missing session", call: mcp.ToolContext{OperationID: "call_scope_123", Scope: &mcp.ScopeSnapshot{CIDRs: []string{"127.0.0.0/8"}}}},
		{name: "missing operation", call: mcp.ToolContext{SessionID: "ses_call_scope", Scope: &mcp.ScopeSnapshot{CIDRs: []string{"127.0.0.0/8"}}}},
		{name: "missing snapshot", call: mcp.ToolContext{SessionID: "ses_call_scope", OperationID: "call_scope_123"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perCall, release, errObj := scopedToolEnvironment(base, tt.call)
			defer release()
			if errObj == nil || perCall != nil {
				t.Fatalf("incomplete controller context was accepted: env=%v error=%v", perCall, errObj)
			}
		})
	}
}

func TestValidateWebTargetRejectsMissingControllerScope(t *testing.T) {
	env := envWithScope(t, scope.ScopeConfig{AllowedCIDRs: []string{"127.0.0.0/8"}})
	if _, errObj := validateWebTargetWithToolContext(env, mcp.ToolContext{}, "http://127.0.0.1"); errObj == nil {
		t.Fatal("web target validation accepted a process-wide scope without controller identity")
	}
}

func TestPortsToolDoesNotReportUnsupportedTCPScanAsClean(t *testing.T) {
	t.Setenv("ARGOS_DISABLE_TOOL_DOWNLOAD", "1")
	env := envWithScope(t, scope.ScopeConfig{AllowedCIDRs: []string{"127.0.0.0/8"}})
	server := mcp.NewServer(mcp.ServerInfo{Name: "argos-web-test", Version: "test"})
	RegisterPorts(server, env)
	handler := server.GetToolHandler("web.ports")
	params, err := json.Marshal(map[string]string{"target": "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	call := mcp.ToolContext{
		Ctx:         context.Background(),
		SessionID:   "ses_ports_scope",
		OperationID: "call_ports_scope",
		Scope:       &mcp.ScopeSnapshot{CIDRs: []string{"127.0.0.0/8"}},
	}
	result, errObj := handler(call, params)
	if errObj == nil || result != nil || !strings.Contains(errObj.Message, "TCP gateway") {
		t.Fatalf("unsupported TCP scan was not reported as unavailable: result=%v error=%v", result, errObj)
	}
}

func TestScopeEnforcement_TargetOutOfScopeEmitsNoRequest(t *testing.T) {
	srv, hits := countingServer(t)

	// The scope authorizes 10.0.0.0/8 only: the loopback server is out of it.
	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"10.0.0.0/8"},
		SessionID:    "tools-scope-blocked",
		MaxRPS:       50,
	})

	detected, evidence, _ := guard.DetectWAFDetailed(env.Client(), srv.URL)
	if len(detected) != 0 || len(evidence) != 0 {
		t.Errorf("expected no WAF detection from a blocked target, got %v", detected)
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("expected 0 requests to reach the target, got %d", n)
	}
}

func TestScopeEnforcement_TargetInScopeEmitsRequest(t *testing.T) {
	srv, hits := countingServer(t)

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-scope-allowed",
		MaxRPS:       50,
	})

	detected, _, _ := guard.DetectWAFDetailed(env.Client(), srv.URL)
	if len(detected) == 0 {
		t.Fatal("expected the WAF fingerprint to be detected for an in-scope target")
	}
	if n := atomic.LoadInt32(hits); n == 0 {
		t.Error("expected the request to reach the in-scope target")
	}
}

func TestScopeEnforcement_SQLiNativeDetectorRespectsScope(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		q := r.URL.Query().Get("id")
		switch q {
		case "1", "1' AND '1'='1":
			_, _ = w.Write([]byte("Item: 1 <b>ok</b>"))
		case "1' AND '1'='2":
			_, _ = w.Write([]byte("Item: 1"))
		default:
			_, _ = w.Write([]byte("error: sql syntax"))
		}
	}))
	defer srv.Close()

	// Out of scope: the native detector must not emit a single probe.
	blocked := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"10.0.0.0/8"},
		SessionID:    "tools-scope-sqli-blocked",
		MaxRPS:       50,
	})
	fs := detectSQLi(blocked.Client(), srv.URL+"?id=1", 10*time.Second)
	if len(fs) != 0 {
		t.Errorf("expected 0 findings from a blocked target, got %d", len(fs))
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("expected 0 requests to reach the target, got %d", n)
	}

	// In scope: the same detector works as before.
	allowed := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-scope-sqli-allowed",
		MaxRPS:       50,
	})
	fs = detectSQLi(allowed.Client(), srv.URL+"?id=1", 10*time.Second)
	if len(fs) == 0 {
		t.Fatal("expected a SQLi candidate for an in-scope target")
	}
	if n := atomic.LoadInt32(&hits); n == 0 {
		t.Error("expected the probes to reach the in-scope target")
	}
}

func TestScopeEnforcement_ArtifactFetchRespectsScope(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("console.log(1)"))
	}))
	defer srv.Close()

	blocked := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"10.0.0.0/8"},
		SessionID:    "tools-scope-artifact-blocked",
		MaxRPS:       50,
	})
	if _, err := fetchRemoteAsset(context.Background(), blocked.Client(), srv.URL); err == nil {
		t.Fatal("expected the asset fetch to be blocked for an out-of-scope target")
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("expected 0 requests to reach the target, got %d", n)
	}

	allowed := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-scope-artifact-allowed",
		MaxRPS:       50,
	})
	body, err := fetchRemoteAsset(context.Background(), allowed.Client(), srv.URL)
	if err != nil {
		t.Fatalf("expected the asset fetch to succeed for an in-scope target: %v", err)
	}
	if body == "" {
		t.Error("expected the asset body to be fetched")
	}
}

func TestWebWAF_RejectsOutOfScopeTargetBeforeRequest(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"10.0.0.0/8"},
		SessionID:    "waf-scope-blocked",
		MaxRPS:       50,
	})
	server := mcp.NewServerWithIO(mcp.ServerInfo{Name: "argos-web"}, bytes.NewReader(nil), io.Discard)
	RegisterWAF(server, env)
	handler := server.GetToolHandler("web.waf")
	params, err := json.Marshal(map[string]any{"target": srv.URL})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	_, errObj := handler(mcp.ToolContext{}, params)
	if errObj == nil {
		t.Fatal("expected web.waf to reject an out-of-scope target")
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("expected 0 requests to reach the out-of-scope target, got %d", n)
	}
}
