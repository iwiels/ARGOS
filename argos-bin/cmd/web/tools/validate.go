package tools

import (
	"context"
	"net/url"
	"strings"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

var defaultScopeGuard *scope.ScopeGuard

func validateWebTargetWithToolContext(env *Env, call mcp.ToolContext, raw string) (string, *mcp.ErrorObj) {
	config, ok := scopeConfigFromToolContext(call)
	if !ok {
		return "", &mcp.ErrorObj{Code: -32602, Message: "SECURITY ENFORCEMENT: controller session, operation, and scope snapshot are required; scan blocked"}
	}
	config.RequireWorkerProxy = env != nil && (env.RequireWorkerProxy || (env.Scope != nil && env.Scope.RequiresWorkerProxy()))
	if env != nil && env.Scope != nil && env.SessionID == call.SessionID && env.OperationID == call.OperationID {
		return validateWebTargetWithGuard(env.Scope, raw)
	}
	guard, err := scope.New(config)
	if err != nil {
		return "", &mcp.ErrorObj{Code: -32602, Message: "SECURITY ENFORCEMENT: invalid controller scope; scan blocked: " + err.Error()}
	}
	defer guard.Close()
	return validateWebTargetWithGuard(guard, raw)
}

func validateWebTargetWithGuard(sg *scope.ScopeGuard, raw string) (string, *mcp.ErrorObj) {
	if raw == "" {
		return "", &mcp.ErrorObj{Code: -32602, Message: "target is required"}
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", &mcp.ErrorObj{Code: -32602, Message: "invalid target URL: " + err.Error()}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", &mcp.ErrorObj{Code: -32602, Message: "target must be an http(s) URL"}
	}
	if u.Host == "" {
		return "", &mcp.ErrorObj{Code: -32602, Message: "target must include a host"}
	}
	target := strings.TrimRight(u.String(), "/")
	if sg == nil {
		return "", &mcp.ErrorObj{Code: -32602, Message: "SECURITY ENFORCEMENT: scope guard is unavailable; scan blocked"}
	}
	if !sg.RequiresWorkerProxy() {
		if _, err := sg.ValidateTarget(context.Background(), u.String()); err != nil {
			return "", &mcp.ErrorObj{Code: -32602, Message: err.Error()}
		}
	}
	return target, nil
}

func validateDomainWithEnv(env *Env, raw string) (string, *mcp.ErrorObj) {
	d := strings.TrimSpace(raw)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.Split(d, "/")[0]
	if d == "" || strings.ContainsAny(d, " /@") {
		return "", &mcp.ErrorObj{Code: -32602, Message: "invalid domain: " + raw}
	}
	var sg *scope.ScopeGuard
	if env != nil && env.Scope != nil {
		sg = env.Scope
	}
	if sg == nil {
		return "", &mcp.ErrorObj{Code: -32602, Message: "SECURITY ENFORCEMENT: scope guard is unavailable; scan blocked"}
	}
	if !sg.RequiresWorkerProxy() {
		if _, err := sg.ValidateTarget(context.Background(), d); err != nil {
			return "", &mcp.ErrorObj{Code: -32602, Message: err.Error()}
		}
	}
	return d, nil
}
