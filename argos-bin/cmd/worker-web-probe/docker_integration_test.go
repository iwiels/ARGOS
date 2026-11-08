package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
	"github.com/iwiels/ARGOS/argos-bin/internal/practicetarget"
	"github.com/iwiels/ARGOS/argos-bin/internal/sandbox"
	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
	"github.com/iwiels/ARGOS/argos-bin/internal/workerprobe"
)

func TestDockerScopeGatewayWorkerProbeIntegration(t *testing.T) {
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
		cidr          string
		wantComplete  bool
		wantGateBlock bool
	}{
		{name: "authorized local fixture", cidr: "127.0.0.0/8", wantComplete: true},
		{name: "out of scope fixture", cidr: "192.0.2.0/24", wantGateBlock: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sessionID := "ses_worker_docker_smoke"
			operationID := "call_worker_docker_smoke"
			if test.wantGateBlock {
				operationID = "call_worker_docker_blocked"
			}
			params, err := json.Marshal(map[string]string{"target": fixture.URL})
			if err != nil {
				t.Fatal(err)
			}
			request := workerprobe.Request{
				Protocol:    workerprobe.ProtocolVersion,
				Tool:        "web.csrf",
				Params:      params,
				SessionID:   sessionID,
				RunID:       "run_worker_docker_smoke",
				OperationID: operationID,
				Scope:       &mcp.ScopeSnapshot{CIDRs: []string{test.cidr}, MaxRPS: 50},
			}
			requestSHA256, err := workerprobe.RequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			result, err := executor.Execute(context.Background(), sandbox.CommandSpec{
				Path:        "/usr/local/bin/argos-worker-probe",
				Stdin:       string(payload),
				Timeout:     30 * time.Second,
				MaxOut:      1 << 20,
				NetworkMode: "scope-gateway",
				SessionID:   sessionID,
				OperationID: operationID,
				Scope: &scope.ScopeConfig{
					AllowedCIDRs: []string{test.cidr},
					MaxRPS:       50,
					SessionID:    sessionID,
					OperationID:  operationID,
				},
			})
			if err != nil {
				t.Fatalf("execute isolated worker: %v", err)
			}
			if result.ExitCode != 0 || result.TimedOut || result.OutputTruncated {
				t.Fatalf("worker failed: exit=%d timeout=%v truncated=%v stderr=%q", result.ExitCode, result.TimedOut, result.OutputTruncated, result.Stderr)
			}
			var response workerprobe.Response
			if err := json.Unmarshal([]byte(result.Stdout), &response); err != nil {
				t.Fatalf("decode worker response: %v; stdout=%q", err, result.Stdout)
			}
			if test.wantComplete {
				if err := workerprobe.ValidateResponse(response, requestSHA256); err != nil {
					t.Fatalf("authorized worker result was rejected: %v", err)
				}
				var toolResult map[string]any
				if err := json.Unmarshal(response.Result, &toolResult); err != nil {
					t.Fatalf("decode authorized tool result: %v", err)
				}
				if toolResult["tool"] != "web.csrf" || toolResult["target"] != fixture.URL {
					t.Fatalf("authorized tool result = %+v", toolResult)
				}
				return
			}
			if !test.wantGateBlock || response.Complete || response.GatewayFailures == 0 || len(response.Result) != 0 {
				t.Fatalf("out-of-scope worker response = %+v, want an incomplete result without partial findings", response)
			}
		})
	}
}
