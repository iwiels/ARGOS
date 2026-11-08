package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/workerprobe"
)

func workerProbeToolHandler(name string) mcp.ToolHandler {
	return func(call mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
		if _, ok := scopeConfigFromToolContext(call); !ok {
			return nil, &mcp.ErrorObj{Code: -32602, Message: "SECURITY ENFORCEMENT: controller session, operation, and scope snapshot are required; probe blocked"}
		}
		request := workerprobe.Request{
			Protocol:    workerprobe.ProtocolVersion,
			Tool:        name,
			Params:      append(json.RawMessage(nil), params...),
			SessionID:   call.SessionID,
			RunID:       call.RunID,
			OperationID: call.OperationID,
			Scope:       call.Scope,
		}
		if err := workerprobe.ValidateRequest(request); err != nil {
			return nil, &mcp.ErrorObj{Code: -32602, Message: err.Error()}
		}
		requestSHA256, err := workerprobe.RequestDigest(request)
		if err != nil {
			return nil, &mcp.ErrorObj{Code: -32603, Message: "cannot identify the controller-bound worker request"}
		}
		payload, err := json.Marshal(request)
		if err != nil {
			return nil, &mcp.ErrorObj{Code: -32603, Message: "cannot encode the controller-bound worker request"}
		}
		runResult := run(toolContext(call), "/usr/local/bin/argos-worker-probe", runOptions{
			Stdin:   string(payload),
			Timeout: 300 * time.Second,
			MaxOut:  maxCapturedOutput,
		})
		if runResult.TimedOut {
			return nil, &mcp.ErrorObj{Code: -32002, Message: "isolated web probe worker timed out; the probe is incomplete"}
		}
		if runResult.ExitCode != 0 {
			return nil, &mcp.ErrorObj{Code: -32002, Message: safeWorkerProbeFailure(runResult)}
		}
		if runResult.OutputTruncated {
			return nil, &mcp.ErrorObj{Code: -32002, Message: "isolated web probe worker output was truncated; the probe is incomplete"}
		}

		var response workerprobe.Response
		decoder := json.NewDecoder(strings.NewReader(runResult.Output))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&response); err != nil {
			return nil, &mcp.ErrorObj{Code: -32002, Message: fmt.Sprintf("isolated web probe returned invalid output: %v", err)}
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return nil, &mcp.ErrorObj{Code: -32002, Message: "isolated web probe returned trailing or invalid output; the probe is incomplete"}
		}
		if err := workerprobe.ValidateResponse(response, requestSHA256); err != nil {
			return nil, &mcp.ErrorObj{Code: -32002, Message: err.Error()}
		}
		if response.Error != nil {
			return nil, response.Error
		}
		expectedTarget, err := normalizeWorkerProbeTarget(params)
		if err != nil {
			return nil, &mcp.ErrorObj{Code: -32002, Message: "isolated web probe request did not contain a valid target"}
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(response.Result, &fields); err != nil || fields == nil {
			return nil, &mcp.ErrorObj{Code: -32002, Message: "isolated web probe result is not an object"}
		}
		var responseTool string
		if err := json.Unmarshal(fields["tool"], &responseTool); err != nil || responseTool != name {
			return nil, &mcp.ErrorObj{Code: -32002, Message: "isolated web probe result names a different tool than requested"}
		}
		var responseTarget string
		if err := json.Unmarshal(fields["target"], &responseTarget); err != nil || responseTarget != expectedTarget {
			return nil, &mcp.ErrorObj{Code: -32002, Message: "isolated web probe result names a different target than requested"}
		}
		findingsJSON, ok := fields["findings"]
		if !ok {
			return nil, &mcp.ErrorObj{Code: -32002, Message: "isolated web probe result omitted its findings field"}
		}
		var findings []map[string]any
		if err := json.Unmarshal(findingsJSON, &findings); err != nil {
			return nil, &mcp.ErrorObj{Code: -32002, Message: "isolated web probe findings are malformed"}
		}
		var result map[string]interface{}
		if err := json.Unmarshal(response.Result, &result); err != nil {
			return nil, &mcp.ErrorObj{Code: -32002, Message: "isolated web probe result could not be decoded"}
		}
		result["findings"] = findings
		return result, nil
	}
}

func normalizeWorkerProbeTarget(params json.RawMessage) (string, error) {
	var input struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(params, &input); err != nil || strings.TrimSpace(input.Target) == "" {
		return "", fmt.Errorf("worker probe target is missing")
	}
	raw := strings.TrimSpace(input.Target)
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	target, err := url.Parse(raw)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil {
		return "", fmt.Errorf("worker probe target must be an absolute HTTP or HTTPS URL without credentials")
	}
	return strings.TrimRight(target.String(), "/"), nil
}

func safeWorkerProbeFailure(result *runResult) string {
	diagnostic := strings.ToLower(result.Stderr)
	for _, message := range []string{
		"docker is unavailable",
		"docker is required for audit execution but is unavailable",
		"docker scanner worker image",
		"args_sandbox_image must name a scanner image pinned by sha256 digest",
		"docker could not create the isolated audit worker",
	} {
		if strings.Contains(diagnostic, message) {
			return strings.TrimSpace(result.Stderr)
		}
	}
	return fmt.Sprintf("isolated web probe worker failed with exit code %d; the probe is incomplete", result.ExitCode)
}
