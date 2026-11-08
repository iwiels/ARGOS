package tools

import (
	"encoding/json"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

type PlatformInfo struct {
	Name        string                  `json:"name"`
	Version     string                  `json:"version"`
	Profiles    []ProfileInfo           `json:"profiles"`
	MemoryDir   string                  `json:"memory_dir"`
}

type ProfileInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Agents      []string `json:"agents"`
}

func RegisterInfo(s *mcp.Server) {
	readOnly := mcp.BoolPtr(true)
	idempotent := mcp.BoolPtr(true)

	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "orchestrator.info",
			Description: "Return platform information including all available security profiles, their descriptions, and assigned agents",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]mcp.Property{},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   readOnly,
				IdempotentHint: idempotent,
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			profileList := make([]ProfileInfo, 0, len(profiles))
			for name, meta := range profiles {
				profileList = append(profileList, ProfileInfo{
					Name:        name,
					Description: meta.Description,
					Agents:      meta.Agents,
				})
			}

			result := PlatformInfo{
				Name:      "Argos Orquestador",
				Version:   "1.0.0",
				Profiles:  profileList,
				MemoryDir: ctx.MemoryDir,
			}

			return result, nil
		},
	)
}
