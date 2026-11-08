package tools

import (
	"encoding/json"
	"fmt"

	"github.com/iwiels/ARGOS/argos-bin/internal/guard"
	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)


func wafAssessment(vendors []string) string {
	if len(vendors) > 0 {
		return "fingerprint_observed"
	}
	return "inconclusive"
}

func RegisterWAF(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.waf",
			Description: "Passively fingerprint known WAF/provider response markers from one normal request. No match is inconclusive and does not prove that a WAF is absent; a provider fingerprint does not prove that blocking rules are enabled.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target": {Type: "string", Description: "Target URL, e.g. https://example.com"},
				},
				Required: []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			scopedEnv, releaseScope, scopeError := scopedToolEnvironment(env, ctx)
			if scopeError != nil {
				return nil, scopeError
			}
			defer releaseScope()
			env := scopedEnv
			var input struct {
				Target string `json:"target"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			var detected []string
			var evidence map[string]string
			var probeErr error
			workerRequired := env != nil && (env.RequireWorkerProxy || (env.Scope != nil && env.Scope.RequiresWorkerProxy()))
			if workerRequired {
				preflight, decision, preflightErr := runWorkerScanPreflight(toolContext(ctx), SessionBreaker(env), target, 1)
				if preflightErr != nil {
					return nil, &mcp.ErrorObj{Code: -32002, Message: "web.waf worker preflight failed: " + preflightErr.Error()}
				}
				if !decision.Continue {
					return map[string]interface{}{
						"tool":           "web.waf",
						"target":         target,
						"status":         "aborted",
						"waf_detected":   false,
						"waf_assessment": "not_run",
						"wafs":           []string{},
						"evidence":       map[string]string{},
						"abort_reason":   decision.Reason,
						"summary":        "WAF probe aborted by the session circuit breaker",
					}, nil
				}
				detected = preflight.WAFVendors
				evidence = preflight.WAFEvidence
			} else {
				detected, evidence, probeErr = guard.DetectWAFDetailed(env.Client(), target)
				if len(detected) > 0 {
					SessionBreaker(env).ObserveWAFVendor(detected[0])
				}
			}
			status := "completed"
			summary := wafSummary(detected)
			assessment := wafAssessment(detected)
			if detected == nil {
				detected = []string{}
			}
			var wafDetected interface{} = len(detected) > 0
			if probeErr != nil {
				status = "incomplete"
				assessment = "not_run"
				summary = "No se pudo completar la detección de WAF"
				wafDetected = nil
			}
			res := map[string]interface{}{
				"tool":           "web.waf",
				"target":         target,
				"status":         status,
				"waf_detected":   wafDetected,
				"waf_assessment": assessment,
				"wafs":           detected,
				"evidence":       evidence,
				"summary":        summary,
			}
			if probeErr != nil {
				res["waf_probe_error"] = probeErr.Error()
			}
			return res, nil
		},
	)
}

func wafSummary(vendors []string) string {
	if len(vendors) == 0 {
		return "No se observó una huella conocida en la petición pasiva; esto no confirma la ausencia de un WAF"
	}
	return fmt.Sprintf("Se observaron %d huella(s) de proveedor WAF/CDN; esto no confirma que haya reglas de bloqueo activas", len(vendors))
}
