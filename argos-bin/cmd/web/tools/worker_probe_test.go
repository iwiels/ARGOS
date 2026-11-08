package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
	"github.com/iwiels/ARGOS/argos-bin/internal/sandbox"
	"github.com/iwiels/ARGOS/argos-bin/internal/workerprobe"
)

type workerProbeTestExecutor struct {
	spec     sandbox.CommandSpec
	stdout   string
	exitCode int
	err      error
	calls    int
}

func (e *workerProbeTestExecutor) Execute(_ context.Context, spec sandbox.CommandSpec) (*sandbox.CommandResult, error) {
	e.spec = spec
	e.calls++
	if e.err != nil {
		return nil, e.err
	}
	return &sandbox.CommandResult{Stdout: e.stdout, ExitCode: e.exitCode, Sandboxed: true}, nil
}

func (*workerProbeTestExecutor) IsSandboxed() bool { return true }

func (*workerProbeTestExecutor) Name() string { return "docker" }

func setWorkerProbeTestExecutor(t *testing.T, executor *workerProbeTestExecutor) {
	t.Helper()
	previous := defaultExecutor
	defaultExecutor = executor
	t.Cleanup(func() { defaultExecutor = previous })
}

func workerProbeTestRequest(call mcp.ToolContext, name string, params json.RawMessage) workerprobe.Request {
	return workerprobe.Request{
		Protocol:    workerprobe.ProtocolVersion,
		Tool:        name,
		Params:      append(json.RawMessage(nil), params...),
		SessionID:   call.SessionID,
		RunID:       call.RunID,
		OperationID: call.OperationID,
		Scope:       call.Scope,
	}
}

func TestWorkerProbeHandlerPassesExactControllerScopeToContainer(t *testing.T) {
	call := controllerScopeCall("ses_probe_dispatch", "call_probe_dispatch", []string{"203.0.113.0/24"}, []string{"app.example.test"})
	params := json.RawMessage(`{"target":"https://app.example.test"}`)
	requestSHA256, err := workerprobe.RequestDigest(workerProbeTestRequest(call, "web.jwt", params))
	if err != nil {
		t.Fatal(err)
	}
	finding := Finding{
		Source:     "web.jwt",
		SourceTool: "web.jwt",
		RuleID:     "jwt:test",
		Title:      "Weak JWT configuration",
		Severity:   SeverityHigh,
		Confidence: ConfidenceProbable,
		Target:     "https://app.example.test",
		Evidence:   map[string]any{"signal": "test"},
	}
	resultJSON, err := json.Marshal(map[string]any{
		"tool":     "web.jwt",
		"target":   "https://app.example.test",
		"status":   "completed",
		"findings": []Finding{finding},
	})
	if err != nil {
		t.Fatal(err)
	}
	workerResponse, err := json.Marshal(workerprobe.Response{
		Protocol:      workerprobe.ProtocolVersion,
		Complete:      true,
		RequestSHA256: requestSHA256,
		Result:        resultJSON,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor := &workerProbeTestExecutor{stdout: string(workerResponse)}
	setWorkerProbeTestExecutor(t, executor)

	server := mcp.NewServer(mcp.ServerInfo{Name: "argos-web-test"})
	memoryDir := t.TempDir()
	RegisterAll(server, &Env{RequireWorkerProxy: true, MemoryDir: memoryDir})
	result, errObj := server.GetToolHandler("web.jwt")(call, params)
	if errObj != nil {
		t.Fatalf("web.jwt returned an error: %+v", errObj)
	}
	if got, ok := result.(map[string]interface{}); !ok || got["tool"] != "web.jwt" {
		t.Fatalf("result = %v, want worker result", result)
	}
	resultMap := result.(map[string]interface{})
	if _, exists := resultMap["findings_persisted"]; exists {
		t.Fatalf("scanner output must remain a candidate, got findings_persisted=%v", resultMap["findings_persisted"])
	}
	if _, err := os.Stat(memoryDir + string(os.PathSeparator) + "findings"); !os.IsNotExist(err) {
		t.Fatalf("scanner output created the canonical findings store: %v", err)
	}
	if executor.calls != 1 || executor.spec.Path != "/usr/local/bin/argos-worker-probe" {
		t.Fatalf("worker calls=%d spec=%+v", executor.calls, executor.spec)
	}
	if executor.spec.NetworkMode != "scope-gateway" || executor.spec.SessionID != call.SessionID || executor.spec.OperationID != call.OperationID {
		t.Fatalf("worker identity or gateway mode = %+v", executor.spec)
	}
	if executor.spec.Scope == nil || executor.spec.Scope.AllowedDomains[0] != "app.example.test" || executor.spec.Scope.AllowedCIDRs[0] != "203.0.113.0/24" {
		t.Fatalf("worker scope = %+v", executor.spec.Scope)
	}
	var request workerprobe.Request
	if err := json.NewDecoder(bytes.NewBufferString(executor.spec.Stdin)).Decode(&request); err != nil {
		t.Fatalf("decode worker stdin: %v", err)
	}
	if request.Tool != "web.jwt" || request.SessionID != call.SessionID || request.RunID != call.RunID || request.OperationID != call.OperationID || string(request.Params) != string(params) {
		t.Fatalf("worker request = %+v", request)
	}
}

func TestWorkerProbeHandlerRejectsMismatchedToolOrTarget(t *testing.T) {
	call := controllerScopeCall("ses_probe_mismatch", "call_probe_mismatch", nil, []string{"app.example.test"})
	params := json.RawMessage(`{"target":"https://app.example.test"}`)
	requestSHA256, err := workerprobe.RequestDigest(workerProbeTestRequest(call, "web.jwt", params))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		tool   string
		target string
	}{
		{name: "tool", tool: "web.csrf", target: "https://app.example.test"},
		{name: "target", tool: "web.jwt", target: "https://other.example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resultJSON, err := json.Marshal(map[string]any{
				"tool":     test.tool,
				"target":   test.target,
				"status":   "completed",
				"findings": []Finding{},
			})
			if err != nil {
				t.Fatal(err)
			}
			workerResponse, err := json.Marshal(workerprobe.Response{
				Protocol:      workerprobe.ProtocolVersion,
				Complete:      true,
				RequestSHA256: requestSHA256,
				Result:        resultJSON,
			})
			if err != nil {
				t.Fatal(err)
			}
			executor := &workerProbeTestExecutor{stdout: string(workerResponse)}
			setWorkerProbeTestExecutor(t, executor)
			server := mcp.NewServer(mcp.ServerInfo{Name: "argos-web-test"})
			RegisterAll(server, &Env{RequireWorkerProxy: true})
			result, errObj := server.GetToolHandler("web.jwt")(call, params)
			if errObj == nil || result != nil {
				t.Fatalf("result=%v error=%v, want mismatched worker response rejected", result, errObj)
			}
		})
	}
}

func TestWorkerProbeHandlerRejectsIncompleteGatewayResponse(t *testing.T) {
	call := controllerScopeCall("ses_probe_partial", "call_probe_partial", nil, []string{"app.example.test"})
	params := json.RawMessage(`{"target":"https://app.example.test"}`)
	requestSHA256, err := workerprobe.RequestDigest(workerProbeTestRequest(call, "web.jwt", params))
	if err != nil {
		t.Fatal(err)
	}
	workerResponse, err := json.Marshal(workerprobe.Response{
		Protocol:        workerprobe.ProtocolVersion,
		Complete:        false,
		RequestSHA256:   requestSHA256,
		GatewayFailures: 1,
		Error:           &mcp.ErrorObj{Code: -32002, Message: "blocked"},
	})
	if err != nil {
		t.Fatal(err)
	}
	executor := &workerProbeTestExecutor{stdout: string(workerResponse)}
	setWorkerProbeTestExecutor(t, executor)
	server := mcp.NewServer(mcp.ServerInfo{Name: "argos-web-test"})
	RegisterAll(server, &Env{RequireWorkerProxy: true})
	result, errObj := server.GetToolHandler("web.jwt")(call, params)
	if errObj == nil || result != nil || !strings.Contains(strings.ToLower(errObj.Message), "incomplete") {
		t.Fatalf("result=%v error=%v, want an explicit incomplete result without partial data", result, errObj)
	}
}

func TestWorkerProbeHandlerBlocksWhenContainerRuntimeFails(t *testing.T) {
	executor := &workerProbeTestExecutor{err: errors.New("Docker is unavailable")}
	setWorkerProbeTestExecutor(t, executor)
	server := mcp.NewServer(mcp.ServerInfo{Name: "argos-web-test"})
	RegisterAll(server, &Env{RequireWorkerProxy: true})
	call := controllerScopeCall("ses_probe_runtime_error", "call_probe_runtime_error", nil, []string{"app.example.test"})
	result, errObj := server.GetToolHandler("web.jwt")(call, json.RawMessage(`{"target":"https://app.example.test"}`))
	if errObj == nil || result != nil || !strings.Contains(errObj.Message, "Docker is unavailable") {
		t.Fatalf("result=%v error=%v, want explicit worker runtime failure", result, errObj)
	}
}
