package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
	"github.com/iwiels/ARGOS/argos-bin/internal/traffic"
)

// trafficTestServer answers 200 to the original request and 500 to the
// overridden one, and counts the hits it receives.
func trafficTestServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Query().Get("id") == "2" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("original"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// trafficTestEnv builds the tool environment of the traffic tests: the same
// shape as NewEnv, but with a scope guard the test controls.
func trafficTestEnv(t *testing.T, allowedCIDRs []string) *Env {
	t.Helper()
	sg, err := scope.New(scope.ScopeConfig{
		AllowedCIDRs: allowedCIDRs,
		SessionID:    "ses_traffic_tools_test",
		MaxRPS:       50,
	})
	if err != nil {
		t.Fatalf("failed to create the ScopeGuard: %v", err)
	}
	t.Cleanup(sg.Close)
	return &Env{
		Scope:     sg,
		HTTP:      sg.Client(),
		SessionID: "ses_traffic_tools_test",
		Agent:     DefaultAgent,
	}
}

// seedExchange writes an exchange in the traffic store of the session.
func seedExchange(t *testing.T, memoryDir, id, url string) {
	t.Helper()
	store := traffic.NewStore(memoryDir)
	err := store.Record(traffic.Exchange{
		ID:              id,
		SessionID:       "ses_traffic_tools_test",
		Timestamp:       time.Now().UTC(),
		Method:          http.MethodGet,
		URL:             url,
		Headers:         map[string][]string{"Accept": {"*/*"}},
		Status:          http.StatusOK,
		ResponseHeaders: map[string][]string{"Content-Type": {"text/plain"}},
		ResponseBody:    []byte("original"),
		SourceTool:      "web.probe",
		Target:          url,
		ScopeAllowed:    true,
	})
	if err != nil {
		t.Fatalf("cannot seed the exchange: %v", err)
	}
}

func trafficToolContext(memoryDir string, allowedCIDRs ...string) mcp.ToolContext {
	if len(allowedCIDRs) == 0 {
		allowedCIDRs = []string{"127.0.0.0/8"}
	}
	return mcp.ToolContext{
		MemoryDir:   memoryDir,
		SessionID:   "ses_traffic_tools_test",
		OperationID: "call_traffic_tools_test",
		Scope:       &mcp.ScopeSnapshot{CIDRs: allowedCIDRs, MaxRPS: 50},
		Ctx:         context.Background(),
		Log:         func(string, ...interface{}) {},
	}
}

func TestTrafficToolsReplayDetectsTheChange(t *testing.T) {
	srv, hits := trafficTestServer(t)
	memoryDir := t.TempDir()
	env := trafficTestEnv(t, []string{"127.0.0.0/8"})

	s := mcp.NewServer(mcp.ServerInfo{Name: "test-server", Version: "1.0"})
	s.SetMemoryDir(memoryDir)
	RegisterTraffic(s, env)

	seedExchange(t, memoryDir, "ex_original", srv.URL)

	handler := s.GetToolHandler("web.replay")
	if handler == nil {
		t.Fatal("the tool web.replay was not registered")
	}
	params, _ := json.Marshal(map[string]interface{}{
		"exchange_id": "ex_original",
		"url":         srv.URL + "?id=2",
		"headers":     map[string]string{"X-Probe": "argos"},
	})

	res, errObj := handler(trafficToolContext(memoryDir), params)
	if errObj != nil {
		t.Fatalf("web.replay failed: %s", errObj.Message)
	}
	result, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("expected a map result, got %T", res)
	}

	if result["status_code"] != http.StatusInternalServerError {
		t.Errorf("status_code = %v, want 500", result["status_code"])
	}
	if result["changed"] != true {
		t.Errorf("changed = %v, want true", result["changed"])
	}
	if result["exchange_id"] == "ex_original" {
		t.Error("the replay reused the id of the original exchange")
	}
	diff, ok := result["diff"].(traffic.DiffResult)
	if !ok {
		t.Fatalf("expected a diff in the result, got %+v", result)
	}
	if !diff.StatusChanged {
		t.Errorf("the diff did not detect the status change: %+v", diff)
	}
	if !diff.BodyChanged {
		t.Errorf("the diff did not detect the body change: %+v", diff)
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Errorf("hits = %d, want 1", n)
	}

	// The replayed exchange is part of the history: the auditor can compare
	// it against the original.
	history := s.GetToolHandler("web.history")
	if history == nil {
		t.Fatal("the tool web.history was not registered")
	}
	historyRes, errObj := history(trafficToolContext(memoryDir), json.RawMessage(`{}`))
	if errObj != nil {
		t.Fatalf("web.history failed: %s", errObj.Message)
	}
	historyMap := historyRes.(map[string]interface{})
	if historyMap["total"] != 2 {
		t.Errorf("total = %v, want 2 exchanges in the session", historyMap["total"])
	}

	compare := s.GetToolHandler("web.compare")
	if compare == nil {
		t.Fatal("the tool web.compare was not registered")
	}
	compareRes, errObj := compare(trafficToolContext(memoryDir), json.RawMessage(`{"a_id":"ex_original","b_id":"ex_original"}`))
	if errObj != nil {
		t.Fatalf("web.compare failed: %s", errObj.Message)
	}
	compareMap := compareRes.(map[string]interface{})
	compareDiff := compareMap["diff"].(traffic.DiffResult)
	if !compareDiff.Identical {
		t.Errorf("an exchange compared with itself is not identical: %+v", compareDiff)
	}
}

func TestTrafficToolsReplayOutOfScopeEmitsNoRequest(t *testing.T) {
	srv, hits := trafficTestServer(t)
	memoryDir := t.TempDir()
	// The scope authorizes 10.0.0.0/8 only: the loopback server is out of it.
	env := trafficTestEnv(t, []string{"10.0.0.0/8"})

	s := mcp.NewServer(mcp.ServerInfo{Name: "test-server", Version: "1.0"})
	s.SetMemoryDir(memoryDir)
	RegisterTraffic(s, env)

	seedExchange(t, memoryDir, "ex_original", srv.URL)

	handler := s.GetToolHandler("web.replay")
	if handler == nil {
		t.Fatal("the tool web.replay was not registered")
	}
	params, _ := json.Marshal(map[string]interface{}{
		"exchange_id": "ex_original",
		"url":         srv.URL + "?id=2",
	})

	res, errObj := handler(trafficToolContext(memoryDir, "10.0.0.0/8"), params)
	if errObj == nil {
		t.Fatalf("the replay of an out-of-scope target was allowed: %+v", res)
	}
	if !strings.Contains(errObj.Message, "SCOPE ENFORCEMENT") {
		t.Errorf("error = %q, want a SCOPE ENFORCEMENT error", errObj.Message)
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("hits = %d, want 0: an out-of-scope replay must not emit a request", n)
	}
}

func TestTrafficToolsHistoryFilters(t *testing.T) {
	srv, _ := trafficTestServer(t)
	memoryDir := t.TempDir()
	env := trafficTestEnv(t, []string{"127.0.0.0/8"})

	s := mcp.NewServer(mcp.ServerInfo{Name: "test-server", Version: "1.0"})
	s.SetMemoryDir(memoryDir)
	RegisterTraffic(s, env)

	seedExchange(t, memoryDir, "ex_original", srv.URL)

	handler := s.GetToolHandler("web.history")
	if handler == nil {
		t.Fatal("the tool web.history was not registered")
	}
	res, errObj := handler(trafficToolContext(memoryDir), json.RawMessage(`{"method":"POST"}`))
	if errObj != nil {
		t.Fatalf("web.history failed: %s", errObj.Message)
	}
	result := res.(map[string]interface{})
	if result["total"] != 1 {
		t.Errorf("total = %v, want 1", result["total"])
	}
	if result["count"] != 0 {
		t.Errorf("count = %v, want 0 (the method filter does not match)", result["count"])
	}
}

func TestTrafficHistoryCannotSelectAnotherSession(t *testing.T) {
	srv, _ := trafficTestServer(t)
	memoryDir := t.TempDir()
	env := trafficTestEnv(t, []string{"127.0.0.0/8"})
	s := mcp.NewServer(mcp.ServerInfo{Name: "test-server", Version: "1.0"})
	s.SetMemoryDir(memoryDir)
	RegisterTraffic(s, env)
	seedExchange(t, memoryDir, "ex_current", srv.URL)

	handler := s.GetToolHandler("web.history")
	result, errObj := handler(trafficToolContext(memoryDir), json.RawMessage(`{"session_id":"ses_attacker_selected"}`))
	if errObj != nil {
		t.Fatalf("web.history failed: %s", errObj.Message)
	}
	history := result.(map[string]interface{})
	if history["session_id"] != env.SessionID {
		t.Fatalf("model selected session %v; expected controller-bound session %s", history["session_id"], env.SessionID)
	}
	if history["total"] != 1 {
		t.Fatalf("history total = %v, want current-session exchange only", history["total"])
	}
}

func TestTrafficToolsNeedASession(t *testing.T) {
	memoryDir := t.TempDir()
	env := trafficTestEnv(t, []string{"127.0.0.0/8"})

	s := mcp.NewServer(mcp.ServerInfo{Name: "test-server", Version: "1.0"})
	s.SetMemoryDir(memoryDir)
	RegisterTraffic(s, env)

	handler := s.GetToolHandler("web.history")
	if handler == nil {
		t.Fatal("the tool web.history was not registered")
	}
	if _, errObj := handler(mcp.ToolContext{MemoryDir: memoryDir, Ctx: context.Background()}, json.RawMessage(`{}`)); errObj == nil {
		t.Error("web.history worked without a session id")
	}
}

func TestTrafficToolsCaptureIsOptIn(t *testing.T) {
	// La captura está apagada por defecto: la tool no emite requests extra
	// ni escribe a disco.
	t.Setenv(traffic.CaptureEnv, "")
	if traffic.CaptureEnabled() {
		t.Error("the traffic capture is on by default")
	}
	t.Setenv(traffic.CaptureEnv, "1")
	if !traffic.CaptureEnabled() {
		t.Error("ARGOS_TRAFFIC_CAPTURE=1 did not enable the traffic capture")
	}
}

func TestTrafficStoreIsUnderTheMemoryDir(t *testing.T) {
	memoryDir := t.TempDir()
	store := traffic.NewStore(memoryDir)
	if !strings.HasPrefix(store.BaseDir, memoryDir) {
		t.Errorf("the traffic store lives outside the memory dir: %s", store.BaseDir)
	}
	if !strings.Contains(store.BaseDir, "traffic") {
		t.Errorf("the traffic store is not under <memoryDir>/traffic: %s", store.BaseDir)
	}
	if _, err := os.Stat(memoryDir); err != nil {
		t.Errorf("the memory dir disappeared: %v", err)
	}
}
