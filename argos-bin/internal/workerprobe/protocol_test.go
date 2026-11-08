package workerprobe

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

func TestValidateRequestAllowsOnlyControllerBoundHTTPProbes(t *testing.T) {
	request := Request{
		Protocol:    ProtocolVersion,
		Tool:        "web.jwt",
		Params:      json.RawMessage(`{"target":"https://app.example.test"}`),
		SessionID:   "ses_worker_probe",
		RunID:       "run_worker_probe",
		OperationID: "call_worker_probe",
		Scope:       &mcp.ScopeSnapshot{Domains: []string{"app.example.test"}},
	}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("ValidateRequest(valid): %v", err)
	}

	for _, tool := range []string{"web.csrf", "web.graphql", "web.oauth", "web.prompt_injection", "web.ssti"} {
		request.Tool = tool
		if err := ValidateRequest(request); err != nil {
			t.Errorf("ValidateRequest(%s): %v", tool, err)
		}
	}
}

func TestValidateRequestRejectsUnsupportedOrUnboundCalls(t *testing.T) {
	valid := Request{
		Protocol:    ProtocolVersion,
		Tool:        "web.jwt",
		Params:      json.RawMessage(`{"target":"https://app.example.test"}`),
		SessionID:   "ses_worker_probe",
		RunID:       "run_worker_probe",
		OperationID: "call_worker_probe",
		Scope:       &mcp.ScopeSnapshot{Domains: []string{"app.example.test"}},
	}
	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "unsupported raw socket tool", mutate: func(r *Request) { r.Tool = "web.smuggle" }},
		{name: "unsupported out of band tool", mutate: func(r *Request) { r.Tool = "web.ssrf" }},
		{name: "unsupported binary tool", mutate: func(r *Request) { r.Tool = "web.sqli" }},
		{name: "missing session", mutate: func(r *Request) { r.SessionID = "" }},
		{name: "missing run", mutate: func(r *Request) { r.RunID = "" }},
		{name: "missing operation", mutate: func(r *Request) { r.OperationID = "" }},
		{name: "missing scope", mutate: func(r *Request) { r.Scope = nil }},
		{name: "invalid params", mutate: func(r *Request) { r.Params = json.RawMessage(`{`) }},
		{name: "wrong protocol", mutate: func(r *Request) { r.Protocol++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if err := ValidateRequest(request); err == nil {
				t.Fatal("ValidateRequest accepted an invalid request")
			}
		})
	}
}

func TestValidateRequestEnforcesParameterAndEnvelopeSizeLimits(t *testing.T) {
	valid := Request{
		Protocol:    ProtocolVersion,
		Tool:        "web.csrf",
		Params:      json.RawMessage(`{"target":"https://app.example.test"}`),
		SessionID:   "ses_worker_probe",
		RunID:       "run_worker_probe",
		OperationID: "call_worker_probe",
		Scope:       &mcp.ScopeSnapshot{Domains: []string{"app.example.test"}},
	}

	oversizedParams := valid
	oversizedParams.Params = json.RawMessage(`{"padding":"` + strings.Repeat("x", MaxParamsBytes) + `"}`)
	if err := ValidateRequest(oversizedParams); err == nil {
		t.Fatal("ValidateRequest accepted oversized parameters")
	}

	oversizedEnvelope := valid
	oversizedEnvelope.Scope = &mcp.ScopeSnapshot{Domains: []string{strings.Repeat("x", MaxRequestBytes)}}
	if err := ValidateRequest(oversizedEnvelope); err == nil {
		t.Fatal("ValidateRequest accepted an oversized complete request")
	}
}

func TestResponseValidationRejectsIncompleteOrUntrustedResults(t *testing.T) {
	request := Request{
		Protocol:    ProtocolVersion,
		Tool:        "web.csrf",
		Params:      json.RawMessage(`{"target":"https://app.example.test"}`),
		SessionID:   "ses_worker_probe",
		RunID:       "run_worker_probe",
		OperationID: "call_worker_probe",
		Scope:       &mcp.ScopeSnapshot{Domains: []string{"app.example.test"}},
	}
	digest, err := RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	valid := Response{Protocol: ProtocolVersion, Complete: true, RequestSHA256: digest, Result: json.RawMessage(`{"status":"completed"}`)}
	if err := ValidateResponse(valid, digest); err != nil {
		t.Fatalf("ValidateResponse(valid): %v", err)
	}
	for _, response := range []Response{
		{Protocol: ProtocolVersion, Complete: false},
		{Protocol: ProtocolVersion + 1, Complete: true, Result: json.RawMessage(`{}`)},
		{Protocol: ProtocolVersion, Complete: true, RequestSHA256: strings.Repeat("0", 64), Result: json.RawMessage(`{}`)},
		{Protocol: ProtocolVersion, Complete: true, Result: json.RawMessage(`{`)},
		{Protocol: ProtocolVersion, Complete: true, GatewayFailures: 1, Result: json.RawMessage(`{"status":"completed"}`)},
	} {
		if err := ValidateResponse(response, digest); err == nil {
			t.Errorf("ValidateResponse accepted %+v", response)
		}
	}
}
