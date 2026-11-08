package tools

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/practicetarget"
	"github.com/iwiels/argos-auditor/argos-bin/internal/sandbox"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
)

func TestDockerScopeGatewayBrowserWorkerIntegration(t *testing.T) {
	if os.Getenv("ARGOS_RUN_DOCKER_INTEGRATION") != "1" {
		t.Skip("set ARGOS_RUN_DOCKER_INTEGRATION=1 to run against a prepared Docker worker image and local fixture")
	}
	image := strings.TrimSpace(os.Getenv("ARGOS_SANDBOX_IMAGE"))
	if image == "" {
		t.Fatal("ARGOS_SANDBOX_IMAGE must identify the digest-pinned worker image")
	}
	t.Setenv("ARGOS_SANDBOX_IMAGE", image)
	executor := sandbox.NewDockerExecutor()
	if !executor.IsAvailable() {
		t.Fatal("digest-pinned Docker worker image is not available")
	}
	fixture := httptest.NewServer(practicetarget.Handler())
	defer fixture.Close()

	for _, test := range []struct {
		name          string
		url           string
		excludedHosts []string
		wantBlocked   bool
	}{
		{name: "authorized page", url: fixture.URL + "/"},
		{name: "excluded route", url: fixture.URL + "/admin/secret", excludedHosts: []string{"/admin/*"}, wantBlocked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sessionID := "ses_browser_docker_smoke"
			operationID := "call_browser_docker_smoke"
			if test.wantBlocked {
				operationID = "call_browser_docker_blocked"
			}
			payload, err := json.Marshal(browserWorkerRequest{
				Action:         "navigate",
				URL:            test.url,
				TimeoutSeconds: 15,
			})
			if err != nil {
				t.Fatal(err)
			}
			scopeConfig := &scope.ScopeConfig{
				AllowedCIDRs:  []string{"127.0.0.1/32"},
				ExcludedHosts: test.excludedHosts,
				MaxRPS:        50,
			}
			result, err := executor.Execute(context.Background(), sandbox.CommandSpec{
				Path:        browserWorkerPath,
				Stdin:       string(payload),
				Timeout:     60 * time.Second,
				MaxOut:      4 << 20,
				NetworkMode: "scope-gateway",
				SessionID:   sessionID,
				OperationID: operationID,
				Scope:       scopeConfig,
			})
			if err != nil {
				t.Fatalf("execute isolated browser worker: %v", err)
			}
			if result.TimedOut || result.OutputTruncated {
				t.Fatalf("browser worker timed out or truncated output: timeout=%v truncated=%v stderr=%q", result.TimedOut, result.OutputTruncated, result.Stderr)
			}
			if test.wantBlocked {
				if result.ExitCode == 0 || !strings.Contains(result.Stderr, "blocked by Argos scope gateway") {
					t.Fatalf("excluded route result = exit %d, stderr=%q; want an explicit gateway block", result.ExitCode, result.Stderr)
				}
				return
			}
			if result.ExitCode != 0 {
				t.Fatalf("authorized browser worker failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
			}
			var response map[string]any
			if err := json.Unmarshal([]byte(result.Stdout), &response); err != nil {
				t.Fatalf("decode browser response: %v; stdout=%q", err, result.Stdout)
			}
			if response["success"] != true || response["title"] != "Argos Practice Target" {
				t.Fatalf("authorized browser response = %+v", response)
			}
			if links, ok := response["links"].([]any); !ok || len(links) == 0 {
				t.Fatalf("browser did not return links from the controlled target: %+v", response)
			}
		})
	}
}
