package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/iwiels/argos-auditor/argos-bin/cmd/web/tools"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
	"github.com/iwiels/argos-auditor/argos-bin/internal/workerpreflight"
	"github.com/iwiels/argos-auditor/argos-bin/internal/workerprobe"
)

func main() {
	showVersion := flag.Bool("version", false, "print the packaged worker version")
	flag.Parse()
	if *showVersion {
		fmt.Printf("argos-worker-probe %s\n", workerVersion())
		return
	}
	if flag.NArg() != 0 {
		fail("unexpected positional arguments")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, workerprobe.MaxRequestBytes+1))
	if err != nil {
		fail("cannot read worker request")
	}
	if len(data) > workerprobe.MaxRequestBytes {
		fail("worker request exceeds the configured size limit")
	}
	var request workerprobe.Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		fail("worker request is invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		fail("worker request contains trailing data")
	}
	if err := workerprobe.ValidateRequest(request); err != nil {
		fail(err.Error())
	}
	client, monitor, err := workerpreflight.NewClientWithMonitor(os.Getenv("ARGOS_WORKER_PROXY_URL"))
	if err != nil {
		fail(err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	response, err := executeProbe(ctx, request, client, monitor)
	if err != nil {
		fail(err.Error())
	}
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		fail("cannot encode worker response")
	}
}

func workerVersion() string {
	version := strings.TrimSpace(os.Getenv("ARGOS_WORKER_VERSION"))
	if version == "" {
		return "dev"
	}
	return version
}

func executeProbe(ctx context.Context, request workerprobe.Request, client *http.Client, monitor *workerpreflight.Monitor) (workerprobe.Response, error) {
	if err := workerprobe.ValidateRequest(request); err != nil {
		return workerprobe.Response{}, err
	}
	requestSHA256, err := workerprobe.RequestDigest(request)
	if err != nil {
		return workerprobe.Response{}, err
	}
	if client == nil {
		return workerprobe.Response{}, fmt.Errorf("worker scope gateway client is unavailable")
	}

	safeMode := false
	if request.Scope.SafeMode != nil {
		safeMode = *request.Scope.SafeMode
	}
	workerScope, err := scope.New(scope.ScopeConfig{
		AllowedDomains:     append([]string(nil), request.Scope.Domains...),
		AllowedCIDRs:       append([]string(nil), request.Scope.CIDRs...),
		ExcludedHosts:      append([]string(nil), request.Scope.Excluded...),
		MaxRPS:             request.Scope.MaxRPS,
		SafeMode:           safeMode,
		SessionID:          request.SessionID,
		OperationID:        request.OperationID,
		RequireWorkerProxy: true,
	})
	if err != nil {
		return workerprobe.Response{}, fmt.Errorf("controller scope is invalid in worker: %w", err)
	}
	defer workerScope.Close()

	workerEnv := &tools.Env{
		Scope:              workerScope,
		HTTP:               client,
		RequireWorkerProxy: true,
		WorkerScopeGateway: true,
	}
	server := mcp.NewServerWithIO(mcp.ServerInfo{Name: "argos-web-probe-worker"}, bytes.NewReader(nil), io.Discard)
	registerProbe(server, workerEnv, request.Tool)
	handler := server.GetToolHandler(request.Tool)
	if handler == nil {
		return workerprobe.Response{}, fmt.Errorf("worker probe %q is not registered", request.Tool)
	}
	call := mcp.ToolContext{
		SessionID:   request.SessionID,
		OperationID: request.OperationID,
		Scope:       request.Scope,
		Ctx:         ctx,
	}
	result, toolError := handler(call, request.Params)
	if failures := monitor.FailureCount(); failures > 0 {
		return workerprobe.Response{
			Protocol:        workerprobe.ProtocolVersion,
			Complete:        false,
			RequestSHA256:   requestSHA256,
			GatewayFailures: failures,
			Error:           &mcp.ErrorObj{Code: -32002, Message: "one or more target requests failed or were blocked by the scope gateway; partial findings were discarded"},
		}, nil
	}
	if toolError != nil {
		return workerprobe.Response{Protocol: workerprobe.ProtocolVersion, Complete: true, RequestSHA256: requestSHA256, Error: toolError}, nil
	}
	encodedResult, err := json.Marshal(result)
	if err != nil {
		return workerprobe.Response{}, fmt.Errorf("worker probe result is not JSON serializable: %w", err)
	}
	return workerprobe.Response{Protocol: workerprobe.ProtocolVersion, Complete: true, RequestSHA256: requestSHA256, Result: encodedResult}, nil
}

func registerProbe(server *mcp.Server, env *tools.Env, name string) {
	switch name {
	case "web.csrf":
		tools.RegisterCSRF(server, env)
	case "web.graphql":
		tools.RegisterGraphQL(server, env)
	case "web.jwt":
		tools.RegisterJWT(server, env)
	case "web.oauth":
		tools.RegisterOAuth(server, env)
	case "web.prompt_injection":
		tools.RegisterPromptInjection(server, env)
	case "web.ssti":
		tools.RegisterSSTI(server, env)
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "argos-worker-probe:", message)
	os.Exit(1)
}
