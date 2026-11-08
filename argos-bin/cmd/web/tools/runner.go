package tools

import (
	"context"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/env"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/sandbox"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
)

const (
	maxCapturedOutput = 1 << 20 // 1MB cap on captured output
	maxFindings       = 100
)

var defaultExecutor = sandbox.DefaultExecutor()

type auditExecutionContextKey struct{}

type auditExecutionContext struct {
	sessionID   string
	operationID string
	scope       *scope.ScopeConfig
}

func scopeConfigFromToolContext(call mcp.ToolContext) (scope.ScopeConfig, bool) {
	if call.Scope == nil || call.SessionID == "" || call.OperationID == "" {
		return scope.ScopeConfig{}, false
	}
	safeMode := false
	if call.Scope.SafeMode != nil {
		safeMode = *call.Scope.SafeMode
	}
	return scope.ScopeConfig{
		AllowedDomains: append([]string(nil), call.Scope.Domains...),
		AllowedCIDRs:   append([]string(nil), call.Scope.CIDRs...),
		ExcludedHosts:  append([]string(nil), call.Scope.Excluded...),
		MaxRPS:         call.Scope.MaxRPS,
		SafeMode:       safeMode,
		SessionID:      call.SessionID,
		OperationID:    call.OperationID,
	}, true
}

func toolContext(call mcp.ToolContext) context.Context {
	ctx := call.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	var config *scope.ScopeConfig
	if scopeConfig, ok := scopeConfigFromToolContext(call); ok {
		config = &scopeConfig
	}
	return context.WithValue(ctx, auditExecutionContextKey{}, auditExecutionContext{
		sessionID:   call.SessionID,
		operationID: call.OperationID,
		scope:       config,
	})
}

func auditExecutionContextFrom(ctx context.Context) (auditExecutionContext, bool) {
	if ctx == nil {
		return auditExecutionContext{}, false
	}
	value, ok := ctx.Value(auditExecutionContextKey{}).(auditExecutionContext)
	return value, ok
}

type runResult struct {
	Output          string // stdout, the parseable stream
	Stderr          string // stderr, truncated (progress/logs must not corrupt stdout)
	ExitCode        int
	TimedOut        bool
	Duration        time.Duration
	Sandboxed       bool
	OutputTruncated bool
	StderrTruncated bool
}

type runOptions struct {
	Args        []string
	Stdin       string
	Timeout     time.Duration
	MaxOut      int
	Env         []string
	Dir         string
	ArtifactDir string
}

func run(ctx context.Context, bin string, opts runOptions) *runResult {
	spec := sandbox.CommandSpec{
		Path:        bin,
		Args:        opts.Args,
		Stdin:       opts.Stdin,
		Timeout:     opts.Timeout,
		MaxOut:      opts.MaxOut,
		Env:         opts.Env,
		NetworkMode: "none",
		Strict:      true,
		Dir:         opts.Dir,
		ArtifactDir: opts.ArtifactDir,
	}
	if audit, ok := auditExecutionContextFrom(ctx); ok && audit.sessionID != "" && audit.operationID != "" && audit.scope != nil {
		spec.NetworkMode = "scope-gateway"
		spec.SessionID = audit.sessionID
		spec.OperationID = audit.operationID
		spec.Scope = audit.scope
	}
	res, err := defaultExecutor.Execute(ctx, spec)
	if err != nil || res == nil {
		message := "executor returned no result"
		if err != nil {
			message = err.Error()
		}
		return &runResult{
			Stderr:   message,
			ExitCode: -1,
		}
	}
	return &runResult{
		Output:          res.Stdout,
		Stderr:          res.Stderr,
		ExitCode:        res.ExitCode,
		TimedOut:        res.TimedOut,
		Duration:        res.Duration,
		Sandboxed:       res.Sandboxed,
		OutputTruncated: res.OutputTruncated,
		StderrTruncated: res.StderrTruncated,
	}
}

func baseResult(tool, target string, r *runResult) map[string]interface{} {
	status := "completed"
	if r.TimedOut {
		status = "timeout"
	} else if tool == "code.secrets" && r.ExitCode == 1 {
		status = "completed"
	} else if r.ExitCode != 0 {
		status = "error"
	}
	res := map[string]interface{}{
		"tool":        tool,
		"target":      target,
		"status":      status,
		"duration_ms": r.Duration.Milliseconds(),
		"exit_code":   r.ExitCode,
		"sandboxed":   r.Sandboxed,
		"executor":    defaultExecutor.Name(),
		// traceability of the template set used, empty when not applicable
		"templates_version": "",
		"templates_sha256":  "",
	}
	if r.OutputTruncated {
		res["output_truncated"] = true
	}
	if r.StderrTruncated {
		res["stderr_truncated"] = true
	}
	if status == "error" && r.Stderr != "" {
		st := r.Stderr
		if len(st) > 500 {
			st = st[len(st)-500:]
		}
		res["stderr_tail"] = st
	}
	return res
}

func markRunIncomplete(r *runResult, reason string) {
	if r == nil {
		return
	}
	if r.ExitCode == 0 {
		r.ExitCode = -1
	}
	r.Stderr = strings.TrimSpace(r.Stderr + "\n" + reason)
}

func capFindings(fs []Finding) ([]Finding, bool) {
	if len(fs) > maxFindings {
		return fs[:maxFindings], true
	}
	return fs, false
}

// debugToolOutput attaches the raw tool streams to the result when
// ARGOS_DEBUG_TOOL_OUTPUT=1 is set (diagnostics only).
func debugToolOutput(res map[string]interface{}, r *runResult) {
	if env.Get("ARGOS_DEBUG_TOOL_OUTPUT") != "1" {
		return
	}
	if r.Output != "" {
		out := r.Output
		if len(out) > 4000 {
			out = out[len(out)-4000:]
		}
		res["raw_output"] = out
	}
	if r.Stderr != "" {
		errOut := r.Stderr
		if len(errOut) > 2000 {
			errOut = errOut[len(errOut)-2000:]
		}
		res["raw_stderr"] = errOut
	}
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}
