package tools

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

func TestSmuggleToolBlocksRawHostConnectionsUntilGatewayExists(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{AllowedCIDRs: []string{"127.0.0.0/8"}})
	server := mcp.NewServer(mcp.ServerInfo{Name: "argos-web-test", Version: "test"})
	RegisterSmuggle(server, env)
	params, err := json.Marshal(map[string]string{"target": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, errObj := server.GetToolHandler("web.smuggle")(
		controllerScopeCall("ses_smuggle_test", "call_smuggle_test", []string{"127.0.0.0/8"}, nil),
		params,
	)
	if errObj == nil || result != nil || !strings.Contains(errObj.Message, "scoped TCP gateway") {
		t.Fatalf("raw TCP scan was not blocked: result=%v error=%v", result, errObj)
	}
	if hits != 0 {
		t.Fatalf("blocked smuggle scan sent %d HTTP requests", hits)
	}
}
