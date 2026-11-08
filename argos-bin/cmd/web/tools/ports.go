package tools

import (
	"encoding/json"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

func RegisterPorts(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.ports",
			Description: "TCP port discovery is unavailable until Argos ships an isolated scoped TCP gateway; direct host scans are blocked.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":    {Type: "string", Description: "Target host or IP address to scan"},
					"ports":     {Type: "string", Description: "Specific ports or range to scan (e.g. '80,443,8080' or '1-1000')"},
					"top_ports": {Type: "string", Description: "Top ports preset ('100', '1000', default '100')"},
					"nse":       {Type: "boolean", Description: "Run deep nmap NSE enumeration on open ports (banner, http-title, vulners)"},
					"timeout":   {Type: "integer", Description: "Timeout in seconds (default 120, max 300)"},
				},
				Required: []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Target   string `json:"target"`
				Ports    string `json:"ports"`
				TopPorts string `json:"top_ports"`
				NSE      bool   `json:"nse"`
				Timeout  int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			_, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			return nil, &mcp.ErrorObj{Code: -32002, Message: "web.ports is unavailable: the isolated worker has no scoped TCP gateway yet; no port scan was run"}
		},
	)
}
