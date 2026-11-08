package tools

import (
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

func TestRegisterVectorsRegistersTheEightBusinessLogicTools(t *testing.T) {
	s := mcp.NewServer(mcp.ServerInfo{Name: "test", Version: "1.0.0"})
	RegisterVectors(s, NewEnv(t.TempDir()))

	want := []string{
		"web.jwt",
		"web.ssrf",
		"web.csrf",
		"web.graphql",
		"web.smuggle",
		"web.oauth",
		"web.ssti",
		"web.prompt_injection",
	}
	registered := map[string]bool{}
	for _, definition := range s.ToolDefinitions() {
		registered[definition.Name] = true
	}
	if len(registered) != len(want) {
		t.Fatalf("registered %d tools, want %d: %+v", len(registered), len(want), registered)
	}
	for _, name := range want {
		if !registered[name] {
			t.Errorf("missing tool: %s", name)
		}
		if s.GetToolHandler(name) == nil {
			t.Errorf("tool %s has no handler", name)
		}
	}
}
