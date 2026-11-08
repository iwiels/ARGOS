package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/oob"
)

// RegisterSSRF registers the SSRF detection tool.
func RegisterSSRF(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.ssrf",
			Description: "Blind SSRF detection on a URL fetching parameter: cloud metadata (169.254.169.254), loopback, " +
				"private ranges, decimal/octal/hex IP notations, DNS rebinding and redirects to internal addresses. " +
				"The probes are read-only and leave through the scope-bound client.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":       {Type: "string", Description: "Endpoint that fetches the URL, e.g. https://example.com/fetch"},
					"parameter":    {Type: "string", Description: "Name of the parameter that receives the URL"},
					"surface":      {Type: "string", Description: "Where the parameter lives: query (default) or body"},
					"method":       {Type: "string", Description: "HTTP method of the request under test (default GET, POST when a body is given)"},
					"body":         {Type: "string", Description: "Request body when the parameter lives in the body"},
					"content_type": {Type: "string", Description: "Content type of the body (default application/x-www-form-urlencoded)"},
					"payloads":     {Type: "array", Items: &mcp.Items{Type: "string"}, Description: "Override the built-in probe list with these URLs"},
					"timeout":      {Type: "integer", Description: "Per-request timeout in seconds (default 10, max 60)"},
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
			probes := ssrfProbeList(input.Payloads)

			report := detectSSRF(callCtx, env, spec, probes, vectorTimeout(input.Timeout))
			fs, truncated := capFindings(report.findings)
			res := vectorResult("web.ssrf", target, started)
			res["parameter"] = input.Parameter
			res["probes"] = report.probes
			res["baseline_status"] = report.baselineStatus
			res["oob_callback"] = report.oobCallback
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d SSRF indicators", len(fs))
			return res, nil
		},
	)
}

// ssrfProbe is one URL injected into the vector.
type ssrfProbe struct {
	Category string `json:"category"`
	Label    string `json:"label"`
	Value    string `json:"value"`
}

// ssrfProbeList returns the probe battery, or the caller supplied one.
func ssrfProbeList(custom []string) []ssrfProbe {
	if len(custom) > 0 {
		out := make([]ssrfProbe, 0, len(custom))
		for _, value := range custom {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			out = append(out, ssrfProbe{Category: "custom", Label: value, Value: value})
		}
		return out
	}
	return defaultSSRFProbes()
}

// defaultSSRFProbes is the built-in battery: every entry is an address that
// only a server side fetch can reach.
func defaultSSRFProbes() []ssrfProbe {
	return []ssrfProbe{
		{Category: "cloud-metadata", Label: "AWS/GCP/Azure instance metadata", Value: "http://169.254.169.254/latest/meta-data/"},
		{Category: "cloud-metadata", Label: "GCP metadata service", Value: "http://metadata.google.internal/computeMetadata/v1/"},
		{Category: "cloud-metadata", Label: "Azure instance metadata", Value: "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
		{Category: "loopback", Label: "IPv4 loopback", Value: "http://127.0.0.1/"},
		{Category: "loopback", Label: "IPv4 loopback with an explicit port", Value: "http://127.0.0.1:80/"},
		{Category: "loopback", Label: "IPv6 loopback", Value: "http://[::1]/"},
		{Category: "loopback", Label: "loopback by name", Value: "http://localhost/"},
		{Category: "private-network", Label: "RFC1918 10.0.0.0/8", Value: "http://10.0.0.1/"},
		{Category: "private-network", Label: "RFC1918 172.16.0.0/12", Value: "http://172.16.0.1/"},
		{Category: "private-network", Label: "RFC1918 192.168.0.0/16", Value: "http://192.168.0.1/"},
		{Category: "ip-obfuscation", Label: "decimal notation of the metadata address", Value: "http://2852039166/"},
		{Category: "ip-obfuscation", Label: "hexadecimal notation of the metadata address", Value: "http://0xA9FEA9FE/"},
		{Category: "ip-obfuscation", Label: "octal notation of the metadata address", Value: "http://0251.0376.0251.0376/"},
		{Category: "ip-obfuscation", Label: "decimal notation of the loopback address", Value: "http://2130706433/"},
		{Category: "ip-obfuscation", Label: "short loopback notation", Value: "http://127.1/"},
	}
}

// ssrfBaselineValue is the benign value injected to learn how the endpoint
// reacts to a URL it cannot resolve. The .invalid TLD never resolves (RFC
// 2606), so no request of the engagement leaves towards a third party.
const ssrfBaselineValue = "http://argos-ssrf-baseline.invalid/"

// ssrfBudget is the total time the probe round may take.
//
// It is a multiple of the per-request timeout because an unreachable
// internal address costs the whole timeout.
func ssrfBudget(timeout time.Duration) time.Duration {
	budget := timeout * 4
	if budget < 30*time.Second {
		budget = 30 * time.Second
	}
	if budget > 120*time.Second {
		budget = 120 * time.Second
	}
	return budget
}

// ssrfMetadataMarkers are the fingerprints of a cloud metadata document.
var ssrfMetadataMarkers = []string{
	"accesskeyid",
	"secretaccesskey",
	"sessiontoken",
	"security-credentials",
	"instance-identity",
	"instance-identity/document",
	"computecredentials",
	"computeRole",
	"identitydocument",
	"computemetadata",
	"ami-id",
	"instance-id",
	"x-aws-ec2-metadata-token",
	"metadata/instance",
}

// ssrfFetchErrorMarkers are the fingerprints of a failed server side fetch.
var ssrfFetchErrorMarkers = []string{
	"connection refused",
	"no such host",
	"dial tcp",
	"no route to host",
	"network is unreachable",
	"client.timeout",
	"context deadline exceeded",
	"failed to fetch",
	"fetch failed",
	"invalid url",
	"unsupported protocol scheme",
	"eof",
	"read: connection reset",
	"i/o timeout",
}

// ssrfReport is the outcome of the SSRF probe round.
type ssrfReport struct {
	findings       []Finding
	probes         []map[string]any
	baselineStatus int
	oobCallback    bool
}

// detectSSRF runs the probe battery against the vector.
//
// The baseline request establishes what the endpoint answers when it is
// asked for a URL it cannot resolve: without it every error page of the
// application would look like a proof of SSRF.
func detectSSRF(ctx context.Context, env *Env, spec vectorSpec, probes []ssrfProbe, timeout time.Duration) *ssrfReport {
	report := &ssrfReport{}
	client := env.Client()

	// The battery is bounded: an unreachable internal address can cost the
	// whole per-request timeout, and the probe has to finish inside the
	// budget of the MCP call.
	deadline := time.Now().Add(ssrfBudget(timeout))

	baseline, err := ssrfRequest(ctx, client, spec, ssrfBaselineValue, timeout)
	if err == nil {
		report.baselineStatus = baseline.Status
	}

	baselineFingerprints := map[string]bool{}
	if baseline != nil {
		for _, marker := range ssrfFetchErrorMarkers {
			if strings.Contains(strings.ToLower(baseline.Body), marker) {
				baselineFingerprints[marker] = true
			}
		}
	}

	// The redirect check is read-only: the endpoint is asked for the URL and
	// its own Location header is inspected. The redirect is not followed.
	redirectFinding := ssrfRedirectFinding(ctx, client, spec, timeout)

	oobSeen, oobDetail := ssrfOOBProbe(ctx, env, spec, timeout)

	for _, probe := range probes {
		if time.Now().After(deadline) {
			report.probes = append(report.probes, map[string]any{
				"category": probe.Category,
				"label":    probe.Label,
				"payload":  probe.Value,
				"skipped":  "the budget of the probe round was exhausted",
			})
			continue
		}
		resp, err := ssrfRequest(ctx, client, spec, probe.Value, timeout)
		if err != nil || resp == nil {
			report.probes = append(report.probes, map[string]any{
				"category": probe.Category,
				"label":    probe.Label,
				"payload":  probe.Value,
				"error":    errString(err),
			})
			continue
		}
		entry := map[string]any{
			"category": probe.Category,
			"label":    probe.Label,
			"payload":  probe.Value,
			"status":   resp.Status,
		}

		metadataMarkers := ssrfFindMarkers(resp.Body, ssrfMetadataMarkers)
		if len(metadataMarkers) > 0 {
			entry["metadata_markers"] = metadataMarkers
			entry["verdict"] = "metadata-exposed"
			report.findings = append(report.findings, ssrfFinding(
				"ssrf:cloud-metadata-exposure",
				"SSRF confirmed: the server fetched the cloud metadata service and returned its content",
				SeverityCritical, ConfidenceConfirmed, spec, probe, resp, map[string]any{
					"metadata_markers": metadataMarkers,
					"payload":          probe.Value,
				}))
			report.probes = append(report.probes, entry)
			continue
		}

		newErrors := ssrfNewErrorMarkers(resp.Body, baselineFingerprints)
		mentionsHost := ssrfMentionsHost(resp.Body, probe.Value)
		if len(newErrors) > 0 && mentionsHost {
			entry["error_markers"] = newErrors
			entry["verdict"] = "server-side-fetch-error"
			report.findings = append(report.findings, ssrfFinding(
				"ssrf:internal-fetch",
				"SSRF probable: the server attempted to fetch an internal address and reported the failure",
				SeverityHigh, ConfidenceProbable, spec, probe, resp, map[string]any{
					"error_markers": newErrors,
					"payload":       probe.Value,
				}))
			report.probes = append(report.probes, entry)
			continue
		}

		if ssrfReflectedDifferentially(resp.Body, probe.Value, baseline) {
			entry["verdict"] = "internal-value-reflected"
			report.findings = append(report.findings, ssrfFinding(
				"ssrf:internal-url-reflected",
				"SSRF possible: the endpoint reflects internal addresses that it does not reflect for benign URLs",
				SeverityMedium, ConfidencePossible, spec, probe, resp, map[string]any{
					"payload": probe.Value,
				}))
			report.probes = append(report.probes, entry)
			continue
		}

		entry["verdict"] = "no-signal"
		report.probes = append(report.probes, entry)
	}

	if oobSeen {
		report.oobCallback = true
		payload, _ := oobDetail["payload"].(string)
		report.findings = append(report.findings, ssrfFinding(
			"ssrf:blind-callback",
			"SSRF confirmed: the server fetched the out-of-band collector, the vector is blind SSRF",
			SeverityCritical, ConfidenceConfirmed, spec,
			ssrfProbe{Category: "dns-rebinding", Label: "out-of-band collector", Value: payload},
			nil, oobDetail))
	}

	if redirectFinding != nil {
		report.findings = append(report.findings, *redirectFinding)
	}

	return report
}

// ssrfRequest performs one probe request with the injected URL.
func ssrfRequest(ctx context.Context, client *http.Client, spec vectorSpec, value string, timeout time.Duration) (*vectorResponse, error) {
	req, err := vectorBuildRequest(ctx, spec, value)
	if err != nil {
		return nil, err
	}
	return vectorFetch(ctx, client, req.Method, req.URL.String(), req.Header, "", timeout)
}

// ssrfFinding builds the canonical finding of one SSRF signal.
func ssrfFinding(ruleID, title, severity, confidence string, spec vectorSpec, probe ssrfProbe, resp *vectorResponse, extra map[string]any) Finding {
	evidence := map[string]any{
		"parameter": spec.Param,
		"surface":   spec.Surface,
		"category":  probe.Category,
		"probe":     probe.Label,
		"payload":   probe.Value,
		"url":       spec.URL,
	}
	for key, value := range extra {
		evidence[key] = value
	}
	if resp != nil {
		evidence["status"] = resp.Status
		evidence["body_excerpt"] = vectorTruncate(resp.Body, 800)
	}
	return Finding{
		Source:     "web.ssrf",
		SourceTool: "web.ssrf",
		RuleID:     ruleID,
		Title:      title,
		Severity:   severity,
		Confidence: confidence,
		CWE:        "CWE-918",
		OWASP:      []string{"A10:2021"},
		Target:     spec.URL,
		Vector:     spec.Surface + ":" + spec.Param,
		Evidence:   evidence,
		Remediation: "Resolve the URL against an allow-list of destinations and block the loopback, the private ranges, the " +
			"link-local metadata address and the numeric notations of them before the request leaves the application.",
		Tags: []string{"ssrf"},
	}
}

// ssrfFindMarkers returns the markers present in the body.
func ssrfFindMarkers(body string, markers []string) []string {
	lower := strings.ToLower(body)
	var out []string
	for _, marker := range markers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			out = append(out, marker)
		}
	}
	sort.Strings(out)
	return out
}

// ssrfNewErrorMarkers returns the fetch error markers the probe produced and
// the baseline did not.
func ssrfNewErrorMarkers(body string, baseline map[string]bool) []string {
	var out []string
	for _, marker := range ssrfFetchErrorMarkers {
		if baseline[marker] {
			continue
		}
		if strings.Contains(strings.ToLower(body), marker) {
			out = append(out, marker)
		}
	}
	sort.Strings(out)
	return out
}

// ssrfMentionsHost reports whether the body mentions the injected host.
func ssrfMentionsHost(body, payload string) bool {
	host := payloadHost(payload)
	if host == "" {
		return false
	}
	return strings.Contains(strings.ToLower(body), strings.ToLower(host))
}

// payloadHost returns the host of a URL payload.
func payloadHost(payload string) string {
	parsed, err := url.Parse(payload)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// ssrfReflectedDifferentially reports whether the endpoint reflects the
// internal URL but not the benign one.
//
// A page that echoes whatever URL it receives reflects both, so it is not a
// signal; only a differential is.
func ssrfReflectedDifferentially(probeBody, probeValue string, baseline *vectorResponse) bool {
	if baseline == nil {
		return false
	}
	if strings.Contains(baseline.Body, ssrfBaselineValue) {
		// The endpoint reflects the URLs it receives: the reflection of the
		// probe proves nothing.
		return false
	}
	return strings.Contains(probeBody, probeValue)
}

// ssrfRedirectFinding inspects the Location header of the endpoint.
//
// The redirect is not followed: the tool must not reach the internal address
// itself, it only reports that the endpoint points at it.
func ssrfRedirectFinding(ctx context.Context, client *http.Client, spec vectorSpec, timeout time.Duration) *Finding {
	req, err := vectorBuildRequest(ctx, spec, ssrfBaselineValue)
	if err != nil {
		return nil
	}
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctxTimeout, req.Method, req.URL.String(), nil)
	if err != nil {
		return nil
	}
	request.Header = req.Header.Clone()
	resp, err := noRedirect.Do(request)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	location := resp.Header.Get("Location")
	if location == "" {
		return nil
	}
	absolute := location
	if parsed, err := url.Parse(location); err == nil && !parsed.IsAbs() {
		if base, err := url.Parse(spec.URL); err == nil {
			absolute = base.ResolveReference(parsed).String()
		}
	}
	host := payloadHost(absolute)
	if host == "" || !isInternalHost(host) {
		return nil
	}
	return &Finding{
		Source:     "web.ssrf",
		SourceTool: "web.ssrf",
		RuleID:     "ssrf:redirect-internal",
		Title:      "SSRF probable: the endpoint redirects to an internal address",
		Severity:   SeverityHigh,
		Confidence: ConfidenceProbable,
		CWE:        "CWE-918",
		OWASP:      []string{"A10:2021"},
		Target:     spec.URL,
		Vector:     spec.Surface + ":" + spec.Param,
		Evidence: map[string]any{
			"parameter":     spec.Param,
			"location":      location,
			"resolved_host": host,
			"status":        resp.StatusCode,
			"url":           spec.URL,
		},
		Remediation: "Validate the redirect target against the same allow-list of destinations used for the URL parameter, " +
			"and refuse to redirect to loopback, private or link-local addresses.",
		Tags: []string{"ssrf", "open-redirect"},
	}
}

// ssrfOOBProbe injects the local collector URL to confirm a blind SSRF.
//
// The collector belongs to the audit host: the callback never leaves the
// machine of the auditor. Two spellings are injected: the numeric one, which
// always resolves, and the hostname one, which is the shape a DNS rebinding
// attack uses.
func ssrfOOBProbe(ctx context.Context, env *Env, spec vectorSpec, timeout time.Duration) (bool, map[string]any) {
	collector := env.OOBServer
	if collector == nil {
		return false, nil
	}
	token := randomToken()
	collector.Register(token)
	defer collector.Unregister(token)

	payloads := []string{
		fmt.Sprintf("http://127.0.0.1:%d/%s", collector.Port(), token),
		fmt.Sprintf("http://%s:%d/%s", collector.Domain(), collector.Port(), token),
	}
	for _, payload := range payloads {
		if _, err := ssrfRequest(ctx, env.Client(), spec, payload, timeout); err != nil {
			continue
		}
		if events := ssrfWaitForCallback(collector, token); len(events) > 0 {
			return true, map[string]any{
				"payload":         payload,
				"collector":       collector.Addr(),
				"callbacks":       len(events),
				"callback_url":    events[0].URL,
				"callback_remote": events[0].RemoteAddr,
			}
		}
	}
	return false, nil
}

// ssrfWaitForCallback polls the collector for a short window: the fetch of
// the target is asynchronous, so the callback can arrive after the response
// of the target.
func ssrfWaitForCallback(collector *oob.Server, token string) []oob.Event {
	deadline := time.Now().Add(3 * time.Second)
	for {
		events := collector.Poll(token)
		if len(events) > 0 {
			return events
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// isInternalHost reports whether the host points to an address that only a
// server side fetch can reach.
func isInternalHost(host string) bool {
	lower := strings.ToLower(strings.TrimSpace(host))
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || lower == "metadata.google.internal" {
		return true
	}
	if ip := net.ParseIP(strings.Trim(lower, "[]")); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	return false
}

// errString renders an error for the evidence without failing on nil.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
