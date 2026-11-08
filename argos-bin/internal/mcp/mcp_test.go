package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestToolDefinitionJSON(t *testing.T) {
	readOnly := BoolPtr(true)

	def := ToolDefinition{
		Name:        "test.tool",
		Description: "A test tool",
		InputSchema: ToolInputSchema{
			Type: "object",
			Properties: map[string]Property{
				"query": {Type: "string", Description: "Search query"},
			},
			Required: []string{"query"},
		},
		Annotations: &ToolAnnotations{
			ReadOnlyHint: readOnly,
		},
	}

	data, err := json.Marshal(def)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ToolDefinition
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Name != "test.tool" {
		t.Errorf("Name = %q, want %q", decoded.Name, "test.tool")
	}
	if decoded.InputSchema.Type != "object" {
		t.Errorf("InputSchema.Type = %q, want %q", decoded.InputSchema.Type, "object")
	}
	if decoded.Annotations == nil || !*decoded.Annotations.ReadOnlyHint {
		t.Error("ReadOnlyHint should be true")
	}

	prop, ok := decoded.InputSchema.Properties["query"]
	if !ok {
		t.Fatal("missing property 'query'")
	}
	if prop.Type != "string" {
		t.Errorf("property type = %q, want %q", prop.Type, "string")
	}
	if len(decoded.InputSchema.Required) != 1 || decoded.InputSchema.Required[0] != "query" {
		t.Errorf("Required = %v, want [query]", decoded.InputSchema.Required)
	}
}

func TestToolDefinitionJSON_NoAnnotations(t *testing.T) {
	def := ToolDefinition{
		Name:        "bare.tool",
		Description: "No annotations",
		InputSchema: ToolInputSchema{
			Type:       "object",
			Properties: map[string]Property{},
		},
	}

	data, err := json.Marshal(def)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if contains(data, `"annotations"`) {
		t.Error("annotations field should be omitted when nil")
	}

	var decoded ToolDefinition
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.Annotations != nil {
		t.Error("Annotations should be nil")
	}
}

func TestToolInputSchema_WithItems(t *testing.T) {
	schema := ToolInputSchema{
		Type: "object",
		Properties: map[string]Property{
			"tags": {
				Type:        "array",
				Description: "List of tags",
				Items:       &Items{Type: "string"},
			},
		},
	}

	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ToolInputSchema
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	tags := decoded.Properties["tags"]
	if tags.Items == nil {
		t.Fatal("Items should not be nil")
	}
	if tags.Items.Type != "string" {
		t.Errorf("Items.Type = %q, want %q", tags.Items.Type, "string")
	}
}

func TestToolInputSchemaSupportsNestedObjectsAndEnumValues(t *testing.T) {
	schema := ToolInputSchema{
		Type: "object",
		Properties: map[string]Property{
			"action": {Type: "string", Enum: []string{"navigate", "login"}},
			"credentials": {
				Type:     "object",
				Required: []string{"username", "password"},
				Properties: map[string]Property{
					"username": {Type: "string"},
					"password": {Type: "string"},
				},
			},
		},
	}

	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var decoded ToolInputSchema
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if got := decoded.Properties["action"].Enum; len(got) != 2 || got[0] != "navigate" || got[1] != "login" {
		t.Fatalf("action enum = %#v", got)
	}
	credentials := decoded.Properties["credentials"]
	if len(credentials.Required) != 2 || credentials.Properties["password"].Type != "string" {
		t.Fatalf("nested credentials schema was lost: %+v", credentials)
	}
}

func TestErrorObjStandardErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *ErrorObj
		wantCode int
		wantMsg  string
	}{
		{"MethodNotFound", ErrMethodNotFound, -32601, "Method not found"},
		{"InvalidParams", ErrInvalidParams, -32602, "Invalid params"},
		{"Internal", ErrInternal, -32603, "Internal error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.err)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var decoded ErrorObj
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if decoded.Code != tt.wantCode {
				t.Errorf("Code = %d, want %d", decoded.Code, tt.wantCode)
			}
			if decoded.Message != tt.wantMsg {
				t.Errorf("Message = %q, want %q", decoded.Message, tt.wantMsg)
			}
		})
	}
}

func TestErrorObjWithData(t *testing.T) {
	err := &ErrorObj{
		Code:    -32000,
		Message: "Custom error",
		Data:    map[string]string{"detail": "something went wrong"},
	}

	data, errBytes := json.Marshal(err)
	if errBytes != nil {
		t.Fatalf("Marshal failed: %v", errBytes)
	}

	var decoded ErrorObj
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Data == nil {
		t.Fatal("Data should not be nil")
	}
}

func TestRequestSerialization(t *testing.T) {
	req := Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"test"}`),
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Request
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want %q", decoded.JSONRPC, "2.0")
	}
	if decoded.Method != "tools/call" {
		t.Errorf("Method = %q, want %q", decoded.Method, "tools/call")
	}
}

func TestResponseSerialization(t *testing.T) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      1,
		Result:  map[string]string{"status": "ok"},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want %q", decoded.JSONRPC, "2.0")
	}
	if decoded.Error != nil {
		t.Error("Error should be nil for successful response")
	}
}

func TestResponseWithError(t *testing.T) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      1,
		Error:   ErrMethodNotFound,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Error == nil {
		t.Fatal("Error should not be nil")
	}
	if decoded.Error.Code != -32601 {
		t.Errorf("Error.Code = %d, want %d", decoded.Error.Code, -32601)
	}
}

func TestNotificationSerialization(t *testing.T) {
	notif := Notification{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}

	data, err := json.Marshal(notif)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Notification
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Method != "notifications/initialized" {
		t.Errorf("Method = %q, want %q", decoded.Method, "notifications/initialized")
	}
}

func TestBoolPtr(t *testing.T) {
	b := BoolPtr(true)
	if b == nil {
		t.Fatal("BoolPtr should not return nil")
	}
	if *b != true {
		t.Errorf("value = %v, want true", *b)
	}

	b = BoolPtr(false)
	if *b != false {
		t.Errorf("value = %v, want false", *b)
	}
}

func newTestServer(t *testing.T, concurrency int, timeout time.Duration) (*Server, io.WriteCloser, *bufio.Reader) {
	t.Helper()
	pr, pw := io.Pipe()
	or, ow := io.Pipe()
	server := NewServerWithIO(ServerInfo{Name: "test", Version: "1.0.0"}, pr, ow)
	server.SetLimits(concurrency, timeout)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		server.Run(ctx)
		cancel()
	}()
	t.Cleanup(func() {
		cancel()
		pw.Close()
		ow.Close()
	})
	return server, pw, bufio.NewReader(or)
}

func readResponse(t *testing.T, r *bufio.Reader) Response {
	t.Helper()
	type result struct {
		resp Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := r.ReadString('\n')
		if err != nil {
			ch <- result{err: err}
			return
		}
		var resp Response
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{resp: resp}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("read response: %v", res.err)
		}
		return res.resp
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response")
		return Response{}
	}
}

func registerSlowTool(s *Server, delay time.Duration) {
	s.RegisterTool(
		ToolDefinition{Name: "slow.tool", Description: "sleeps", InputSchema: ToolInputSchema{Type: "object"}},
		func(ctx ToolContext, params json.RawMessage) (interface{}, *ErrorObj) {
			select {
			case <-time.After(delay):
			case <-ctx.Ctx.Done():
				return nil, &ErrorObj{Code: -32000, Message: "canceled"}
			}
			return map[string]string{"ok": "done"}, nil
		},
	)
}

// TestServerToolCallsRunConcurrently proves two slow tools finish in parallel:
// with concurrency=2 and 300ms tools, the pair must complete in well under
// 600ms (the sequential baseline).
func TestServerToolCallsRunConcurrently(t *testing.T) {
	server, pw, out := newTestServer(t, 2, 5*time.Second)
	registerSlowTool(server, 400*time.Millisecond)

	start := time.Now()
	fmt.Fprintln(pw, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow.tool","arguments":{}}}`)
	fmt.Fprintln(pw, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"slow.tool","arguments":{}}}`)

	for i := 0; i < 2; i++ {
		resp := readResponse(t, out)
		if resp.Error != nil {
			t.Fatalf("call %d failed: %+v", i, resp.Error)
		}
	}
	elapsed := time.Since(start)
	// Sequential baseline would be ~800ms (2×400ms); parallel must stay well under it.
	if elapsed >= 700*time.Millisecond {
		t.Errorf("tools appear sequential: elapsed=%v, want <700ms for concurrency=2 with 400ms tools", elapsed)
	}
}

func TestServerToolCallCarriesControllerSessionMetadata(t *testing.T) {
	server, pw, out := newTestServer(t, 1, 5*time.Second)
	server.RegisterTool(
		ToolDefinition{Name: "session.tool", Description: "returns trusted context", InputSchema: ToolInputSchema{Type: "object"}},
		func(ctx ToolContext, params json.RawMessage) (interface{}, *ErrorObj) {
			if ctx.Scope == nil {
				return nil, &ErrorObj{Code: -32603, Message: "missing scope metadata"}
			}
			return map[string]interface{}{
				"session_id":   ctx.SessionID,
				"run_id":       ctx.RunID,
				"operation_id": ctx.OperationID,
				"domains":      ctx.Scope.Domains,
			}, nil
		},
	)

	fmt.Fprintln(pw, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"session.tool","arguments":{"session_id":"ses_model_input","scope":{"domains":["attacker.test"]}},"_meta":{"argos/session_id":"ses_controller_bound","argos/run_id":"run_controller_bound","argos/operation_id":"call_controller_bound","argos/scope":{"domains":["example.test"],"maxRPS":5,"safeMode":true}}}}`)
	resp := readResponse(t, out)
	if resp.Error != nil {
		t.Fatalf("tool call failed: %+v", resp.Error)
	}
	encoded, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "ses_controller_bound") ||
		!strings.Contains(string(encoded), "run_controller_bound") ||
		!strings.Contains(string(encoded), "call_controller_bound") ||
		!strings.Contains(string(encoded), "example.test") ||
		strings.Contains(string(encoded), "ses_model_input") ||
		strings.Contains(string(encoded), "attacker.test") {
		t.Fatalf("tool received wrong session context: %s", encoded)
	}
}

// TestServerToolCallTimeout verifies a tool that outlives the per-call timeout
// receives a timeout error instead of hanging the server.
func TestServerToolCallTimeout(t *testing.T) {
	server, pw, out := newTestServer(t, 2, 200*time.Millisecond)
	registerSlowTool(server, 10*time.Second)

	fmt.Fprintln(pw, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow.tool","arguments":{}}}`)
	resp := readResponse(t, out)
	if resp.Error == nil {
		t.Fatal("expected a timeout error")
	}
	if resp.Error.Code != errTimeoutCode {
		t.Errorf("error code = %d, want %d", resp.Error.Code, errTimeoutCode)
	}
}

// TestServerCancelRequest verifies $/cancelRequest cancels an in-flight call
// and suppresses its response while the server keeps serving other requests.
func TestServerCancelRequest(t *testing.T) {
	server, pw, out := newTestServer(t, 2, 5*time.Second)
	registerSlowTool(server, 10*time.Second)
	server.RegisterTool(
		ToolDefinition{Name: "fast.tool", Description: "instant", InputSchema: ToolInputSchema{Type: "object"}},
		func(ctx ToolContext, params json.RawMessage) (interface{}, *ErrorObj) {
			return map[string]string{"ok": "fast"}, nil
		},
	)

	fmt.Fprintln(pw, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"slow.tool","arguments":{}}}`)
	time.Sleep(100 * time.Millisecond) // let the call start and register its cancel handle
	fmt.Fprintln(pw, `{"jsonrpc":"2.0","method":"$/cancelRequest","params":{"requestId":7}}`)
	fmt.Fprintln(pw, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"fast.tool","arguments":{}}}`)

	resp := readResponse(t, out)
	if resp.ID != float64(8) {
		t.Fatalf("first response id = %v, want 8 (canceled id 7 response must be suppressed)", resp.ID)
	}
	if resp.Error != nil {
		t.Fatalf("fast call failed: %+v", resp.Error)
	}

	// No response may arrive for the canceled id 7 within a short window.
	detour := make(chan struct{})
	go func() {
		line, err := out.ReadString('\n')
		if err == nil && strings.Contains(line, `"id":7`) {
			close(detour)
		}
	}()
	select {
	case <-detour:
		t.Fatal("canceled request id 7 still produced a response")
	case <-time.After(300 * time.Millisecond):
	}
}

func contains(data []byte, s string) bool {
	return len(data) >= len(s) && findSubstring(data, s)
}

func findSubstring(data []byte, s string) bool {
	for i := 0; i <= len(data)-len(s); i++ {
		match := true
		for j := 0; j < len(s); j++ {
			if data[i+j] != s[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
