package tools

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/sandbox"
)

type failingRunnerExecutor struct {
	err error
}

func (e failingRunnerExecutor) Execute(context.Context, sandbox.CommandSpec) (*sandbox.CommandResult, error) {
	return nil, e.err
}

func (failingRunnerExecutor) IsSandboxed() bool { return false }

func (failingRunnerExecutor) Name() string { return "docker" }

func TestRunPreservesExecutorFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "executor error", err: errors.New("Docker is required but unavailable"), want: "Docker is required but unavailable"},
		{name: "missing result", want: "executor returned no result"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			previous := defaultExecutor
			defaultExecutor = failingRunnerExecutor{err: tt.err}
			t.Cleanup(func() { defaultExecutor = previous })

			result := run(context.Background(), "scanner", runOptions{})
			if result.Stderr != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, result.Stderr)
			}
			if result.ExitCode != -1 {
				t.Fatalf("expected blocked execution exit code -1, got %d", result.ExitCode)
			}
		})
	}
}

type captureRunnerExecutor struct {
	spec sandbox.CommandSpec
}

func (e *captureRunnerExecutor) Execute(_ context.Context, spec sandbox.CommandSpec) (*sandbox.CommandResult, error) {
	e.spec = spec
	return &sandbox.CommandResult{Sandboxed: true}, nil
}

func (*captureRunnerExecutor) IsSandboxed() bool { return true }

func (*captureRunnerExecutor) Name() string { return "docker" }

func TestRunPassesControllerScopeToIsolatedWorker(t *testing.T) {
	previous := defaultExecutor
	executor := &captureRunnerExecutor{}
	defaultExecutor = executor
	t.Cleanup(func() { defaultExecutor = previous })

	safeMode := true
	controllerContext := mcp.ToolContext{
		Ctx:         context.Background(),
		SessionID:   "ses_controller_123",
		OperationID: "call_456",
		Scope: &mcp.ScopeSnapshot{
			Domains:  []string{"app.example.test"},
			Excluded: []string{"/admin/*"},
			MaxRPS:   4,
			SafeMode: &safeMode,
		},
	}

	run(toolContext(controllerContext), "/opt/argos/tools/nuclei", runOptions{Args: []string{"-u", "https://app.example.test"}})

	if executor.spec.NetworkMode != "scope-gateway" {
		t.Fatalf("network mode = %q, want scope-gateway", executor.spec.NetworkMode)
	}
	if executor.spec.SessionID != controllerContext.SessionID || executor.spec.OperationID != controllerContext.OperationID {
		t.Fatalf("controller identity was not propagated: session=%q operation=%q", executor.spec.SessionID, executor.spec.OperationID)
	}
	if executor.spec.Scope == nil || len(executor.spec.Scope.AllowedDomains) != 1 || executor.spec.Scope.AllowedDomains[0] != "app.example.test" {
		t.Fatalf("scope domains were not propagated: %+v", executor.spec.Scope)
	}
	if len(executor.spec.Scope.ExcludedHosts) != 1 || executor.spec.Scope.ExcludedHosts[0] != "/admin/*" || executor.spec.Scope.MaxRPS != 4 || !executor.spec.Scope.SafeMode {
		t.Fatalf("scope limits were not propagated: %+v", executor.spec.Scope)
	}
}

func TestMarkRunIncompleteCannotLeaveAZeroExitCode(t *testing.T) {
	result := &runResult{ExitCode: 0, Stderr: "scanner warning"}
	markRunIncomplete(result, "report was missing")
	if result.ExitCode == 0 || !strings.Contains(result.Stderr, "report was missing") {
		t.Fatalf("incomplete result = exit %d stderr %q", result.ExitCode, result.Stderr)
	}
	failed := &runResult{ExitCode: 2}
	markRunIncomplete(failed, "report was missing")
	if failed.ExitCode != 2 {
		t.Fatalf("existing scanner failure was overwritten: %d", failed.ExitCode)
	}
}

func TestRunKeepsWorkerNetworkDisabledWithoutControllerScope(t *testing.T) {
	previous := defaultExecutor
	executor := &captureRunnerExecutor{}
	defaultExecutor = executor
	t.Cleanup(func() { defaultExecutor = previous })

	run(toolContext(mcp.ToolContext{Ctx: context.Background(), SessionID: "ses_without_scope"}), "/opt/argos/tools/nuclei", runOptions{})

	if executor.spec.NetworkMode != "none" {
		t.Fatalf("network mode = %q, want none when scope metadata is incomplete", executor.spec.NetworkMode)
	}
}
