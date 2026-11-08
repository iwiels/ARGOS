package tools

import (
	"encoding/json"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

func RegisterInfo(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "es.info",
			Description: "Get Elasticsearch cluster info: cluster name, UUID and version details. Use first to confirm connectivity and the ES version.",
			InputSchema: mcp.ToolInputSchema{Type: "object", Properties: map[string]mcp.Property{}},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true), IdempotentHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			res, errObj := env.Client.Do(ctx.Ctx, "GET", "/", nil)
			if errObj != nil {
				return nil, errObj
			}
			return res, nil
		},
	)
}

func RegisterClusterHealth(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "es.cluster_health",
			Description: "Get Elasticsearch cluster health: status (green/yellow/red), node counts, active shards and pending tasks.",
			InputSchema: mcp.ToolInputSchema{Type: "object", Properties: map[string]mcp.Property{}},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true), IdempotentHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			res, errObj := env.Client.Do(ctx.Ctx, "GET", "/_cluster/health", nil)
			if errObj != nil {
				return nil, errObj
			}
			return res, nil
		},
	)
}
