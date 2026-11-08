package workerprobe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

const (
	ProtocolVersion = 1
	MaxParamsBytes  = 1 << 20
	MaxRequestBytes = 2 << 20
)

var supportedTools = map[string]struct{}{
	"web.csrf":             {},
	"web.graphql":          {},
	"web.jwt":              {},
	"web.oauth":            {},
	"web.prompt_injection": {},
	"web.ssti":             {},
}

type Request struct {
	Protocol    int                `json:"protocol"`
	Tool        string             `json:"tool"`
	Params      json.RawMessage    `json:"params"`
	SessionID   string             `json:"session_id"`
	RunID       string             `json:"run_id"`
	OperationID string             `json:"operation_id"`
	Scope       *mcp.ScopeSnapshot `json:"scope"`
}

type Response struct {
	Protocol        int             `json:"protocol"`
	Complete        bool            `json:"complete"`
	RequestSHA256   string          `json:"request_sha256"`
	Result          json.RawMessage `json:"result,omitempty"`
	Error           *mcp.ErrorObj   `json:"error,omitempty"`
	GatewayFailures int64           `json:"gateway_failures,omitempty"`
}

func SupportsTool(name string) bool {
	_, ok := supportedTools[name]
	return ok
}

func ValidateRequest(request Request) error {
	if request.Protocol != ProtocolVersion {
		return fmt.Errorf("worker probe request protocol %d is unsupported", request.Protocol)
	}
	if !SupportsTool(request.Tool) {
		return fmt.Errorf("worker probe tool %q is unavailable in this runtime", request.Tool)
	}
	if strings.TrimSpace(request.SessionID) == "" || strings.TrimSpace(request.RunID) == "" || strings.TrimSpace(request.OperationID) == "" || request.Scope == nil {
		return fmt.Errorf("worker probe request requires controller session, run, operation, and scope")
	}
	if len(request.Params) == 0 || len(request.Params) > MaxParamsBytes || !json.Valid(request.Params) {
		return fmt.Errorf("worker probe parameters are empty, oversized, or invalid JSON")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("worker probe request cannot be encoded: %w", err)
	}
	if len(encoded) > MaxRequestBytes {
		return fmt.Errorf("worker probe request exceeds the configured size limit")
	}
	return nil
}

func RequestDigest(request Request) (string, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("worker probe request cannot be encoded: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func ValidateResponse(response Response, expectedRequestSHA256 string) error {
	if response.Protocol != ProtocolVersion {
		return fmt.Errorf("worker probe response protocol %d is unsupported", response.Protocol)
	}
	if !response.Complete {
		return fmt.Errorf("worker probe reported an incomplete result")
	}
	if expectedRequestSHA256 == "" || response.RequestSHA256 != expectedRequestSHA256 {
		return fmt.Errorf("worker probe response does not match the requested session, run, operation, scope, and parameters")
	}
	if response.GatewayFailures > 0 {
		return fmt.Errorf("worker probe recorded %d failed or blocked gateway requests", response.GatewayFailures)
	}
	if response.Error != nil {
		if len(response.Result) > 0 && string(response.Result) != "null" {
			return fmt.Errorf("worker probe response contains both a result and an error")
		}
		return nil
	}
	if len(response.Result) == 0 || !json.Valid(response.Result) {
		return fmt.Errorf("worker probe response result is missing or invalid JSON")
	}
	return nil
}
