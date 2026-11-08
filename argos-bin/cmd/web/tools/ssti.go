package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// RegisterSSTI registers the server side template injection detector.
func RegisterSSTI(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.ssti",
			Description: "Server side template injection detection: one arithmetic probe per engine (Jinja2, Twig, " +
				"Freemarker, Velocity, EL, ERB). The finding is only reported when the template evaluated the expression.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":       {Type: "string", Description: "Endpoint that renders the input, e.g. https://example.com/greet?name=x"},
					"parameter":    {Type: "string", Description: "Name of the parameter that receives the payload"},
					"surface":      {Type: "string", Description: "Where the parameter lives: query (default) or body"},
					"method":       {Type: "string", Description: "HTTP method of the request under test (default GET, POST when a body is given)"},
					"body":         {Type: "string", Description: "Request body when the parameter lives in the body"},
					"content_type": {Type: "string", Description: "Content type of the body (default application/x-www-form-urlencoded)"},
					"payloads":     {Type: "array", Items: &mcp.Items{Type: "string"}, Description: "Override the built-in probe list with these payloads"},
					"timeout":      {Type: "integer", Description: "Per-request timeout in seconds (default 15, max 60)"},
				},
				Required: []string{"target", "parameter"},
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
				Target      string   `json:"target"`
				Parameter   string   `json:"parameter"`
				Surface     string   `json:"surface"`
				Method      string   `json:"method"`
				Body        string   `json:"body"`
				ContentType string   `json:"content_type"`
				Payloads    []string `json:"payloads"`
				Timeout     int      `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			if strings.TrimSpace(input.Parameter) == "" {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "parameter is required"}
			}
			started := time.Now()
			callCtx := toolContext(ctx)

			spec := vectorSpec{
				URL:         target,
				Method:      input.Method,
				Body:        input.Body,
				ContentType: input.ContentType,
				Param:       input.Parameter,
				Surface:     input.Surface,
			}
			spec.Surface = vectorResolveSurface(spec)
			probes := sstiProbeList(input.Payloads)

			report := detectSSTI(callCtx, env, spec, probes, vectorTimeout(input.Timeout))
			fs, truncated := capFindings(report.findings)
			res := vectorResult("web.ssti", target, started)
			res["parameter"] = input.Parameter
			res["probes"] = report.probes
			res["baseline_status"] = report.baselineStatus
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d template injection indicators", len(fs))
			return res, nil
		},
	)
}

// sstiProbe is one template payload.
type sstiProbe struct {
	Engine  string `json:"engine"`
	Payload string `json:"payload"`
	Result  string `json:"result"`
}

// sstiProbeList returns the probe battery, or the caller supplied one.
//
// A custom payload is compared against the digits it would produce: without
// the expected result the tool cannot tell an evaluation from an echo.
func sstiProbeList(custom []string) []sstiProbe {
	if len(custom) == 0 {
		return defaultSSTIProbes()
	}
	out := make([]sstiProbe, 0, len(custom))
	for _, payload := range custom {
		payload = strings.TrimSpace(payload)
		if payload == "" {
			continue
		}
		out = append(out, sstiProbe{Engine: "custom", Payload: payload, Result: ""})
	}
	return out
}

// defaultSSTIProbes is the built-in battery: one arithmetic expression per
// template engine.
func defaultSSTIProbes() []sstiProbe {
	return []sstiProbe{
		{Engine: "jinja2/twig/python", Payload: "{{7*7}}", Result: "49"},
		{Engine: "python/jinja2", Payload: "{{7*'7'}}", Result: "777777777"},
		{Engine: "freemarker/el/velocity", Payload: "${7*7}", Result: "49"},
		{Engine: "erb", Payload: "<%= 7*7 %>", Result: "49"},
		{Engine: "jsp-el/ruby", Payload: "#{7*7}", Result: "49"},
	}
}

// sstiBaselineValue is the benign value injected to learn the shape of the
// answer of the endpoint.
const sstiBaselineValue = "argos-ssti-baseline"

// sstiReport is the outcome of the template injection probes.
type sstiReport struct {
	findings       []Finding
	probes         []map[string]any
	baselineStatus int
}

// detectSSTI runs the template probes against the vector.
//
// The differential is what makes the finding trustworthy: the result of the
// expression has to appear where the payload was, and the payload itself
// must be gone. A page that echoes the payload did not evaluate it.
func detectSSTI(ctx context.Context, env *Env, spec vectorSpec, probes []sstiProbe, timeout time.Duration) *sstiReport {
	report := &sstiReport{}
	client := env.Client()

	baseline, err := sstiRequest(ctx, client, spec, sstiBaselineValue, timeout)
	if err == nil && baseline != nil {
		report.baselineStatus = baseline.Status
	}

	for _, probe := range probes {
		resp, err := sstiRequest(ctx, client, spec, probe.Payload, timeout)
		entry := map[string]any{
			"engine":   probe.Engine,
			"payload":  probe.Payload,
			"expected": probe.Result,
		}
		if err != nil || resp == nil {
			entry["error"] = errString(err)
			report.probes = append(report.probes, entry)
			continue
		}
		entry["status"] = resp.Status
		entry["payload_present"] = strings.Contains(resp.Body, probe.Payload)
		entry["result_occurrences"] = vectorCount(resp.Body, probe.Result)
		if baseline != nil {
			entry["baseline_result_occurrences"] = vectorCount(baseline.Body, probe.Result)
		}
		entry["body_excerpt"] = vectorTruncate(resp.Body, 400)

		if probe.Result == "" {
			// Without the expected result the tool cannot tell an
			// evaluation from an echo.
			entry["verdict"] = "no-expected-result"
			report.probes = append(report.probes, entry)
			continue
		}
		if strings.Contains(resp.Body, probe.Payload) {
			// The payload is still there: the template did not evaluate it.
			entry["verdict"] = "not-evaluated"
			report.probes = append(report.probes, entry)
			continue
		}
		resultCount := vectorCount(resp.Body, probe.Result)
		baselineCount := 0
		if baseline != nil {
			baselineCount = vectorCount(baseline.Body, probe.Result)
		}
		if resultCount <= baselineCount {
			entry["verdict"] = "no-differential"
			report.probes = append(report.probes, entry)
			continue
		}
		entry["verdict"] = "evaluated"
		report.findings = append(report.findings, sstiFinding(spec, probe, resp, resultCount, baselineCount))
		report.probes = append(report.probes, entry)
	}

	return report
}

// sstiRequest performs one probe request with the injected payload.
func sstiRequest(ctx context.Context, client *http.Client, spec vectorSpec, value string, timeout time.Duration) (*vectorResponse, error) {
	req, err := vectorBuildRequest(ctx, spec, value)
	if err != nil {
		return nil, err
	}
	return vectorFetch(ctx, client, req.Method, req.URL.String(), req.Header, "", timeout)
}

// sstiFinding builds the canonical finding of an evaluated template.
func sstiFinding(spec vectorSpec, probe sstiProbe, resp *vectorResponse, resultCount, baselineCount int) Finding {
	evidence := map[string]any{
		"engine":               probe.Engine,
		"payload":              probe.Payload,
		"expected_result":      probe.Result,
		"result_occurrences":   resultCount,
		"baseline_occurrences": baselineCount,
		"parameter":            spec.Param,
		"surface":              spec.Surface,
		"status":               resp.Status,
		"body_excerpt":         vectorTruncate(resp.Body, 800),
		"url":                  spec.URL,
	}
	// El PoC del hallazgo: la petición con el payload y el matcher que decide
	// si la plantilla sigue evaluando la expresión.
	attachPoc(evidence, sstiPoc(spec, probe, resp))
	return Finding{
		Source: "web.ssti", SourceTool: "web.ssti", RuleID: "ssti:expression-evaluated",
		Title:      "Server side template injection: the template evaluated the injected expression (" + probe.Engine + ")",
		Severity:   SeverityHigh,
		Confidence: ConfidenceConfirmed,
		CWE:        "CWE-1336",
		OWASP:      []string{"A03:2021"},
		Target:     spec.URL,
		Vector:     spec.Surface + ":" + spec.Param,
		Evidence:   evidence,
		Remediation: "Do not render the user input as a template: use a context aware autoescaping engine and keep the " +
			"templates free of the logic that evaluates the request data.",
		Tags: []string{"code-injection"},
	}
}

// sstiPoc builds the proof of concept of a template injection finding.
//
// The needle is the RESULT of the evaluation ("49"), not the payload: while
// the template evaluates the expression the result is in the response, and
// once the injection is fixed the payload is echoed literally and the result
// disappears.
func sstiPoc(spec vectorSpec, probe sstiProbe, resp *vectorResponse) *pocRecord {
	if strings.TrimSpace(probe.Result) == "" {
		return nil
	}
	req, err := vectorBuildRequest(context.Background(), spec, probe.Payload)
	if err != nil {
		return nil
	}
	described, ok := httpRequestToPoc(req)
	if !ok {
		return nil
	}
	return &pocRecord{
		Kind:     "ssti",
		Method:   described.Method,
		URL:      described.URL,
		Body:     described.Body,
		Headers:  described.Headers,
		Payload:  probe.Payload,
		Matcher:  pocMatcherValueAbsent(probe.Result),
		Baseline: pocBaselineOf(resp.Status, resp.Body),
	}
}
