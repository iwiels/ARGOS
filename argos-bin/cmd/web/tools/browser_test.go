package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/iwiels/argos-auditor/argos-bin/internal/authvault"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/sandbox"
)

type browserWorkerExecutor struct {
	spec   sandbox.CommandSpec
	calls  int
	output string
}

const browserProfileA = "auth_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const browserProfileB = "auth_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func (e *browserWorkerExecutor) Execute(_ context.Context, spec sandbox.CommandSpec) (*sandbox.CommandResult, error) {
	e.spec = spec
	e.calls++
	return &sandbox.CommandResult{Stdout: e.output, Sandboxed: true}, nil
}

func (*browserWorkerExecutor) IsSandboxed() bool { return true }
func (*browserWorkerExecutor) Name() string      { return "docker" }

func TestBrowserToolRunsOnlyThroughTheControllerScopeGateway(t *testing.T) {
	previous := defaultExecutor
	executor := &browserWorkerExecutor{output: `{"action":"navigate","url":"http://127.0.0.1:8080","success":true,"title":"controlled"}`}
	defaultExecutor = executor
	t.Cleanup(func() { defaultExecutor = previous })

	server := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "test"})
	RegisterBrowser(server, &Env{})
	handler := server.GetToolHandler("web.browse")
	if handler == nil {
		t.Fatal("web.browse was not registered")
	}
	definitions := server.ToolDefinitions()
	for _, definition := range definitions {
		if definition.Name != "web.browse" {
			continue
		}
		if _, ok := definition.InputSchema.Properties["credentials"]; ok {
			t.Fatal("web.browse schema exposes credential fields")
		}
		if _, ok := definition.InputSchema.Properties["storageStateRef"]; ok {
			t.Fatal("web.browse schema exposes raw browser state references")
		}
	}

	safeMode := true
	result, errObj := handler(mcp.ToolContext{
		Ctx:         context.Background(),
		SessionID:   "ses_browser_test",
		OperationID: "call_browser_test",
		Scope: &mcp.ScopeSnapshot{
			CIDRs:    []string{"127.0.0.0/8"},
			MaxRPS:   3,
			SafeMode: &safeMode,
		},
	}, json.RawMessage(`{"action":"navigate","url":"http://127.0.0.1:8080"}`))
	if errObj != nil {
		t.Fatalf("web.browse returned an error: %s", errObj.Message)
	}
	if executor.calls != 1 {
		t.Fatalf("browser worker calls = %d, want 1", executor.calls)
	}
	if executor.spec.Path != "/usr/local/bin/argos-browser-worker" {
		t.Fatalf("worker path = %q", executor.spec.Path)
	}
	if executor.spec.NetworkMode != "scope-gateway" {
		t.Fatalf("worker network mode = %q, want scope-gateway", executor.spec.NetworkMode)
	}
	if executor.spec.SessionID != "ses_browser_test" || executor.spec.OperationID != "call_browser_test" {
		t.Fatalf("controller identity was not bound to the worker: %+v", executor.spec)
	}
	if executor.spec.Scope == nil || executor.spec.Scope.MaxRPS != 3 || !executor.spec.Scope.SafeMode {
		t.Fatalf("scope limits were not propagated to the worker: %+v", executor.spec.Scope)
	}
	var workerRequest map[string]any
	if err := json.Unmarshal([]byte(executor.spec.Stdin), &workerRequest); err != nil {
		t.Fatalf("worker input is not JSON: %v", err)
	}
	if workerRequest["action"] != "navigate" || workerRequest["url"] != "http://127.0.0.1:8080" {
		t.Fatalf("unexpected browser worker request: %#v", workerRequest)
	}
	if !strings.Contains(executor.spec.Stdin, "\"timeoutSeconds\":30") {
		t.Fatalf("default timeout was not bounded in the worker request: %s", executor.spec.Stdin)
	}
	response, ok := result.(map[string]interface{})
	if !ok || response["title"] != "controlled" || response["success"] != true {
		t.Fatalf("browser worker response was not returned: %#v", result)
	}
}

func TestBrowserToolRejectsAnOutOfScopeAuthorizationEndpointBeforeLaunching(t *testing.T) {
	previous := defaultExecutor
	executor := &browserWorkerExecutor{}
	defaultExecutor = executor
	t.Cleanup(func() { defaultExecutor = previous })

	server := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "test"})
	RegisterBrowser(server, &Env{})
	handler := server.GetToolHandler("web.browse")
	if handler == nil {
		t.Fatal("web.browse was not registered")
	}

	_, errObj := handler(mcp.ToolContext{
		Ctx:         context.Background(),
		SessionID:   "ses_browser_test",
		OperationID: "call_browser_test",
		Scope:       &mcp.ScopeSnapshot{CIDRs: []string{"127.0.0.0/8"}},
	}, json.RawMessage(`{"action":"check_authz","url":"http://127.0.0.1:8080","authzCompare":{"roleAAuthProfileID":"role_a","roleBAuthProfileID":"role_b","endpointUrl":"http://192.0.2.20/private"}}`))
	if errObj == nil || !strings.Contains(errObj.Message, "out of authorized scope") {
		t.Fatalf("out-of-scope authorization endpoint was not rejected: %+v", errObj)
	}
	if executor.calls != 0 {
		t.Fatalf("browser worker launched %d times for an out-of-scope endpoint", executor.calls)
	}
}

func TestBrowserLoginUsesProtectedSessionBoundProfile(t *testing.T) {
	previous := defaultExecutor
	state := `{"cookies":[{"name":"session","value":"secret-cookie"}],"origins":[]}`
	workerOutput, err := json.Marshal(map[string]interface{}{
		"action":       "login",
		"success":      true,
		"storageState": state,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor := &browserWorkerExecutor{output: string(workerOutput)}
	defaultExecutor = executor
	t.Cleanup(func() { defaultExecutor = previous })
	profiles := map[string]browserAuthProfile{
		browserProfileA: {ID: browserProfileA, Version: 1, SessionID: "ses_browser_state_test", Name: "Administrator", Username: "alice", Password: "secret"},
		browserProfileB: {ID: browserProfileB, Version: 1, SessionID: "ses_browser_state_test", Name: "Basic user", Username: "bob", Password: "secret"},
	}
	vault, saved := newBrowserAuthVault(t, profiles)
	env := &Env{AuthVault: vault}

	server := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "test"})
	RegisterBrowser(server, env)
	handler := server.GetToolHandler("web.browse")
	scope := &mcp.ScopeSnapshot{CIDRs: []string{"127.0.0.0/8"}}
	call := mcp.ToolContext{Ctx: context.Background(), SessionID: "ses_browser_state_test", OperationID: "login_1", Scope: scope}
	result, errObj := handler(call, json.RawMessage(`{"action":"login","url":"http://127.0.0.1:8080/login","authProfileID":"`+browserProfileA+`"}`))
	if errObj != nil {
		t.Fatalf("browser login returned an error: %s", errObj.Message)
	}
	response, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("browser login response has unexpected type: %#v", result)
	}
	if _, leaksState := response["storageState"]; leaksState {
		t.Fatalf("browser login exposed authentication state: %#v", response)
	}
	if response["authProfileID"] != browserProfileA {
		t.Fatalf("browser login did not return the opaque profile reference: %#v", response)
	}
	if _, oldRef := response["storageStateRef"]; oldRef {
		t.Fatalf("browser login returned a legacy state reference: %#v", response)
	}
	if response["title"] != nil {
		t.Fatalf("authenticated login returned a title that can contain account information: %#v", response)
	}
	if strings.Contains(executor.spec.Stdin, "secret-cookie") {
		t.Fatal("login worker input unexpectedly contained a previous session cookie")
	}
	workerCredentials := mustDecodeMap(t, executor.spec.Stdin)["credentials"].(map[string]interface{})
	if workerCredentials["username"] != "alice" || workerCredentials["password"] != "secret" {
		t.Fatalf("protected profile credentials did not reach the worker: %#v", workerCredentials)
	}
	if !strings.Contains(saved[browserProfileA], "secret-cookie") {
		t.Fatalf("browser state was not persisted through the secure bridge: %s", saved[browserProfileA])
	}

	executor.output = `{"action":"navigate","url":"http://127.0.0.1:8080","success":true}`
	call.OperationID = "navigate_1"
	if _, errObj := handler(call, json.RawMessage(`{"action":"navigate","url":"http://127.0.0.1:8080","authProfileID":"`+browserProfileA+`"}`)); errObj != nil {
		t.Fatalf("same-session authentication profile was rejected: %s", errObj.Message)
	}
	var workerRequest map[string]interface{}
	if err := json.Unmarshal([]byte(executor.spec.Stdin), &workerRequest); err != nil {
		t.Fatalf("worker request is not JSON: %v", err)
	}
	if workerRequest["storageState"] != state {
		t.Fatalf("state reference was not resolved inside the MCP process: %#v", workerRequest)
	}
	if _, exposedRef := workerRequest["authProfileID"]; exposedRef {
		t.Fatalf("browser worker received the opaque profile reference: %#v", workerRequest)
	}

	roleBState := `{"cookies":[{"name":"role","value":"basic"}],"origins":[]}`
	workerOutput, err = json.Marshal(map[string]interface{}{
		"action":       "login",
		"success":      true,
		"storageState": roleBState,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor.output = string(workerOutput)
	call.OperationID = "login_2"
	roleBResult, errObj := handler(call, json.RawMessage(`{"action":"login","url":"http://127.0.0.1:8080/login","authProfileID":"`+browserProfileB+`"}`))
	if errObj != nil {
		t.Fatalf("second role login returned an error: %s", errObj.Message)
	}
	if roleBResult.(map[string]interface{})["authProfileID"] != browserProfileB {
		t.Fatalf("second role profile was not persisted: %#v", roleBResult)
	}
	executor.output = `{"action":"check_authz","success":true}`
	call.OperationID = "authz_1"
	if _, errObj := handler(call, json.RawMessage(`{"action":"check_authz","url":"http://127.0.0.1:8080","authzCompare":{"roleAAuthProfileID":"`+browserProfileA+`","roleBAuthProfileID":"`+browserProfileB+`","endpointUrl":"http://127.0.0.1:8080/api/account"}}`)); errObj != nil {
		t.Fatalf("same-session authorization references were rejected: %s", errObj.Message)
	}
	if err := json.Unmarshal([]byte(executor.spec.Stdin), &workerRequest); err != nil {
		t.Fatalf("authorization worker request is not JSON: %v", err)
	}
	workerAuthz := workerRequest["authzCompare"].(map[string]interface{})
	if workerAuthz["roleAStorageState"] != state || workerAuthz["roleBStorageState"] != roleBState {
		t.Fatalf("authorization roles were not resolved within Argos: %#v", workerAuthz)
	}
	if _, exposedRef := workerAuthz["roleAStorageStateRef"]; exposedRef {
		t.Fatalf("worker received the opaque auth-state reference: %#v", workerAuthz)
	}

	call.SessionID = "ses_other_session"
	call.OperationID = "navigate_2"
	_, errObj = handler(call, json.RawMessage(`{"action":"navigate","url":"http://127.0.0.1:8080","authProfileID":"`+browserProfileA+`"}`))
	if errObj == nil || !strings.Contains(errObj.Message, "another Argos session") {
		t.Fatalf("browser profile was not bound to its issuing session: %+v", errObj)
	}
	if executor.calls != 4 {
		t.Fatalf("worker launched after a cross-session reference attempt; calls=%d", executor.calls)
	}
}

func newBrowserAuthVault(t *testing.T, profiles map[string]browserAuthProfile) (*authvault.Client, map[string]string) {
	t.Helper()
	var mu sync.Mutex
	saved := map[string]string{}
	for id, profile := range profiles {
		encoded, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		saved[id] = string(encoded)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer vault-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			value, ok := saved[id]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"value": value})
		case http.MethodPut:
			var payload struct {
				Value string `json:"value"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "bad payload", http.StatusBadRequest)
				return
			}
			saved[id] = payload.Value
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)
	return authvault.NewClient([]string{server.URL}, "vault-token"), saved
}

func mustDecodeMap(t *testing.T, raw string) map[string]interface{} {
	t.Helper()
	var value map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestBrowserToolRequiresControllerScopeBeforeLaunching(t *testing.T) {
	previous := defaultExecutor
	executor := &browserWorkerExecutor{}
	defaultExecutor = executor
	t.Cleanup(func() { defaultExecutor = previous })

	server := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "test"})
	RegisterBrowser(server, &Env{})
	handler := server.GetToolHandler("web.browse")
	if handler == nil {
		t.Fatal("web.browse was not registered")
	}

	_, errObj := handler(mcp.ToolContext{Ctx: context.Background()}, json.RawMessage(`{"action":"navigate","url":"http://127.0.0.1"}`))
	if errObj == nil || !strings.Contains(errObj.Message, "controller session") {
		t.Fatalf("missing controller scope was not rejected: %+v", errObj)
	}
	if executor.calls != 0 {
		t.Fatalf("browser worker launched %d times without controller scope", executor.calls)
	}
}

func TestRegisterAllExposesBrowserOnlyAfterRuntimePreflight(t *testing.T) {
	withoutPreflight := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "test"})
	RegisterAll(withoutPreflight, &Env{})
	if withoutPreflight.GetToolHandler("web.browse") != nil {
		t.Fatal("web.browse was exposed without a passing browser runtime preflight")
	}

	withPreflight := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "test"})
	RegisterAll(withPreflight, &Env{BrowserWorkerAvailable: true})
	if withPreflight.GetToolHandler("web.browse") == nil {
		t.Fatal("web.browse was not exposed after a passing browser runtime preflight")
	}
}
