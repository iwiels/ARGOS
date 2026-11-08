package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

func TestPortsToolBlocksRawHostConnectionsUntilGatewayExists(t *testing.T) {
	env := envWithScope(t, scope.ScopeConfig{AllowedCIDRs: []string{"127.0.0.0/8"}})
	server := mcp.NewServer(mcp.ServerInfo{Name: "argos-web-test", Version: "test"})
	RegisterPorts(server, env)
	params, err := json.Marshal(map[string]string{"target": "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	result, errObj := server.GetToolHandler("web.ports")(
		controllerScopeCall("ses_ports_test", "call_ports_test", []string{"127.0.0.0/8"}, nil),
		params,
	)
	if errObj == nil || result != nil || !strings.Contains(errObj.Message, "scoped TCP gateway") {
		t.Fatalf("raw TCP port scan was not blocked: result=%v error=%v", result, errObj)
	}
}
