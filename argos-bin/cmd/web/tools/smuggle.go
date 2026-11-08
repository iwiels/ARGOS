package tools

import (
	"encoding/json"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// RegisterSmuggle registers the HTTP request smuggling detection tool.
func RegisterSmuggle(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.smuggle",
			Description: "Unavailable until Argos ships an isolated scoped TCP gateway; direct host socket probes are blocked.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":    {Type: "string", Description: "Target URL to probe, e.g. https://example.com/"},
					"authorize": {Type: "boolean", Description: "Send the smuggled request to confirm the desynchronization. It is a read-only GET but it reaches the backend as a separate request, so it needs the explicit authorization of the engagement (default false)"},
					"timeout":   {Type: "integer", Description: "Timeout of the raw probe in seconds (default 5, max 30)"},
				},
				Required: []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Target string `json:"target"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			if _, errObj := validateWebTargetWithToolContext(env, ctx, input.Target); errObj != nil {
				return nil, errObj
			}
			return nil, &mcp.ErrorObj{Code: -32002, Message: "web.smuggle is unavailable: the isolated worker has no scoped TCP gateway yet; no probe was run"}
		},
	)
}
