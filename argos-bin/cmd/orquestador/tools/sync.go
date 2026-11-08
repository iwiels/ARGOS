package tools

import (
	"encoding/json"
	"fmt"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

type SyncInput struct {
	Profile string `json:"profile"`
	Agent   string `json:"agent,omitempty"`
}

type profileMeta struct {
	Description string   `json:"description"`
	Agents      []string `json:"agents"`
}

var profiles = map[string]profileMeta{
	"recon": {
		Description: "Reconnaissance and surface mapping of target infrastructure",
		Agents:      []string{"nmap-agent", "whois-agent", "subdomain-agent", "cert-agent"},
	},
	"web-triage": {
		Description: "Web application security triage including crawling and scanning",
		Agents:      []string{"crawler-agent", "xss-scanner", "sqli-scanner", "headers-agent"},
	},
	"supply-chain": {
		Description: "Dependency and supply chain vulnerability assessment",
		Agents:      []string{"dep-agent", "sbom-agent", "license-agent", "cve-matcher"},
	},
	"reporting": {
		Description: "Findings aggregation, report generation, and evidence packaging",
		Agents:      []string{"report-agent", "evidence-agent", "screenshots-agent"},
	},
	"memory-only": {
		Description: "Memory maintenance operations without active scanning",
		Agents:      []string{"memory-agent", "context-agent"},
	},
}

func RegisterSync(s *mcp.Server) {
	idempotent := mcp.BoolPtr(true)
	readOnly := mcp.BoolPtr(false)

	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "orchestrator.sync",
			Description: "Sync a security profile to the agent team, triggering the appropriate agent orchestration workflow",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"profile": {
						Type:        "string",
						Description: "Security profile to activate. One of: recon, web-triage, supply-chain, reporting, memory-only",
					},
					"agent": {
						Type:        "string",
						Description: "Optional specific agent to target within the profile",
					},
				},
				Required: []string{"profile"},
			},
			Annotations: &mcp.ToolAnnotations{
				IdempotentHint: idempotent,
				ReadOnlyHint:   readOnly,
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input SyncInput
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid params: " + err.Error()}
			}

			meta, ok := profiles[input.Profile]
			if !ok {
				return nil, &mcp.ErrorObj{Code: -32602, Message: fmt.Sprintf("Unknown profile %q. Valid: recon, web-triage, supply-chain, reporting, memory-only", input.Profile)}
			}

			if input.Agent != "" {
				found := false
				for _, a := range meta.Agents {
					if a == input.Agent {
						found = true
						break
					}
				}
				if !found {
					return nil, &mcp.ErrorObj{Code: -32602, Message: fmt.Sprintf("Agent %q not found in profile %q", input.Agent, input.Profile)}
				}
			}

			result := map[string]interface{}{
				"status":       "synced",
				"profile":      input.Profile,
				"description":  meta.Description,
				"agents":       meta.Agents,
				"target_agent": input.Agent,
				"message":      fmt.Sprintf("Profile %q synced with %d agent(s)", input.Profile, len(meta.Agents)),
			}

			ctx.Log("Sync executed for profile=%s agent=%q", input.Profile, input.Agent)
			return result, nil
		},
	)
}
