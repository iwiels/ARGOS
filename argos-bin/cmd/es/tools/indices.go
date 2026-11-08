package tools

import (
	"encoding/json"
	"net/url"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

func RegisterIndices(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "es.indices",
			Description: "List Elasticsearch indices with health, status, document count and store size. Optionally filter by index name or pattern.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"index": {Type: "string", Description: "Optional index name or pattern to filter, e.g. logs-*"},
				},
			},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true), IdempotentHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Index string `json:"index"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			if referencesSystemIndex(input.Index) {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "access to dot-prefixed system indices is not permitted through this tool"}
			}
			path := "/_cat/indices?format=json&s=index&expand_wildcards=open,closed"
			if input.Index != "" {
				path = "/_cat/indices/" + url.PathEscape(input.Index) + "?format=json&s=index&expand_wildcards=open,closed"
			}
			res, errObj := env.Client.Do(ctx.Ctx, "GET", path, nil)
			if errObj != nil {
				return nil, errObj
			}
			return res, nil
		},
	)
}

func RegisterMapping(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "es.mapping",
			Description: "Get the field mapping of an Elasticsearch index. Useful to know which fields exist before building a query.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"index": {Type: "string", Description: "Index or index pattern, e.g. winlogbeat-*"},
				},
				Required: []string{"index"},
			},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true), IdempotentHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Index string `json:"index"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			if input.Index == "" {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "missing required param: index"}
			}
			if referencesSystemIndex(input.Index) {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "access to dot-prefixed system indices is not permitted through this tool"}
			}
			path := "/" + url.PathEscape(input.Index) + "/_mapping"
			res, errObj := env.Client.Do(ctx.Ctx, "GET", path, nil)
			if errObj != nil {
				return nil, errObj
			}
			return res, nil
		},
	)
}
