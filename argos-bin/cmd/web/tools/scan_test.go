package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/guard"
	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
	"github.com/iwiels/ARGOS/argos-bin/internal/sandbox"
	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
	"github.com/iwiels/ARGOS/argos-bin/internal/workerpreflight"
)

// scopeConfigForLoopback authorizes the loopback interface, which is where
// the test servers listen.
func scopeConfigForLoopback(sessionID string) scope.ScopeConfig {
	return scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    sessionID,
		MaxRPS:       50,
	}
}

// argValue returns the value that follows the given flag.
func argValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func hasArg(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func TestNucleiScanArgs_IncludesTemplatesAndLimits(t *testing.T) {
	args := nucleiScanArgs("https://example.com", nucleiScanOptions{
		Tags:         "cve",
		Severities:   []string{"high"},
		RateLimit:    10,
		Concurrency:  25,
		TemplatesDir: "/tools/nuclei-templates/v10.4.0",
	})

	if v, ok := argValue(args, "-templates"); !ok || v != "/tools/nuclei-templates/v10.4.0" {
		t.Errorf("-templates = %q (found=%v), want the templates dir", v, ok)
	}
	if v, ok := argValue(args, "-rl"); !ok || v != "10" {
		t.Errorf("-rl = %q (found=%v), want 10", v, ok)
	}
	if v, ok := argValue(args, "-c"); !ok || v != "25" {
		t.Errorf("-c = %q (found=%v), want 25", v, ok)
	}
	if v, ok := argValue(args, "-tags"); !ok || v != "cve" {
		t.Errorf("-tags = %q (found=%v), want cve", v, ok)
	}
	if v, ok := argValue(args, "-severity"); !ok || v != "high" {
		t.Errorf("-severity = %q (found=%v), want high", v, ok)
	}
	if v, ok := argValue(args, "-u"); !ok || v != "https://example.com" {
		t.Errorf("-u = %q (found=%v), want the target", v, ok)
	}
	if hasArg(args, "-headless") {
		t.Error("-headless must not be set when it was not requested")
	}
	for _, required := range []string{"-restrict-local-network-access", "-no-interactsh", "-disable-update-check"} {
		if !hasArg(args, required) {
			t.Errorf("Nuclei must set %s by default", required)
		}
	}
}

func TestNucleiScanArgs_DegradesWithoutTemplates(t *testing.T) {
	args := nucleiScanArgs("https://example.com", nucleiScanOptions{
		RateLimit:   10,
		Concurrency: 25,
	})

	if hasArg(args, "-templates") {
		t.Errorf("no templates available must not pass -templates: %v", args)
	}
	if v, ok := argValue(args, "-u"); !ok || v != "https://example.com" {
		t.Errorf("-u = %q (found=%v), want the target", v, ok)
	}
	if v, ok := argValue(args, "-rl"); !ok || v != "10" {
		t.Errorf("-rl = %q (found=%v), want 10", v, ok)
	}
	for _, required := range []string{"-jsonl", "-silent", "-no-color"} {
		if !hasArg(args, required) {
			t.Errorf("missing %s in %v", required, args)
		}
	}
	if strings.Contains(strings.Join(args, " "), "-templates") {
		t.Errorf("args must stay valid without templates: %v", args)
	}
}

func TestNucleiScanArgs_Headless(t *testing.T) {
	args := nucleiScanArgs("https://example.com", nucleiScanOptions{Headless: true})
	if !hasArg(args, "-headless") {
		t.Errorf("-headless missing in %v", args)
	}
}

func TestNucleiScanArgs_OmitsUnsetLimits(t *testing.T) {
	args := nucleiScanArgs("https://example.com", nucleiScanOptions{})
	if hasArg(args, "-rl") || hasArg(args, "-c") {
		t.Errorf("unset limits must not be passed: %v", args)
	}
}

func TestNucleiScanArgs_SeveritiesAreJoined(t *testing.T) {
	args := nucleiScanArgs("https://example.com", nucleiScanOptions{
		Severities: []string{"high", "critical"},
	})
	if v, ok := argValue(args, "-severity"); !ok || v != "high,critical" {
		t.Errorf("-severity = %q (found=%v), want high,critical", v, ok)
	}
}

func TestNucleiScanArgs_PassivePhaseRestrictsTheProtocolFamily(t *testing.T) {
	args := nucleiScanArgs("https://example.com", nucleiScanOptions{
		Passive:     true,
		Tags:        passivePhaseTags,
		ExcludeTags: splitTags(passivePhaseExcludedTags),
	})
	if v, ok := argValue(args, "-pt"); !ok || v != "http" {
		t.Errorf("-pt = %q (found=%v), want http", v, ok)
	}
	if v, ok := argValue(args, "-tags"); !ok || v != passivePhaseTags {
		t.Errorf("-tags = %q (found=%v), want the recon-grade classes", v, ok)
	}
	if v, ok := argValue(args, "-etags"); !ok || !strings.Contains(v, "intrusive") {
		t.Errorf("-etags = %q (found=%v), want the intrusive classes excluded", v, ok)
	}
	if hasArg(args, "-headless") {
		t.Errorf("the passive phase must not run headless templates: %v", args)
	}
}

func TestNucleiScanArgs_ExcludeTemplatesAreRouted(t *testing.T) {
	args := nucleiScanArgs("https://example.com", nucleiScanOptions{
		ExcludeTemplateIDs: []string{"http/cves/2021/CVE-2021-44228.yaml"},
		ExcludeTags:        []string{"sqli"},
	})
	if v, ok := argValue(args, "-eid"); !ok || v != "http/cves/2021/CVE-2021-44228.yaml" {
		t.Errorf("-eid = %q (found=%v), want the template id", v, ok)
	}
	if v, ok := argValue(args, "-etags"); !ok || v != "sqli" {
		t.Errorf("-etags = %q (found=%v), want sqli", v, ok)
	}
}

func TestNucleiScanArgs_ExtraTemplateDirsAreAddedToTheSet(t *testing.T) {
	args := nucleiScanArgs("https://example.com", nucleiScanOptions{
		TemplatesDir:      "/tools/nuclei-templates/v10.4.0",
		ExtraTemplateDirs: []string{"/opt/argos/templates", "/config/templates/nuclei/idor"},
	})
	if v, ok := argValue(args, "-templates"); !ok || v != "/tools/nuclei-templates/v10.4.0,/opt/argos/templates,/config/templates/nuclei/idor" {
		t.Errorf("-templates = %q (found=%v), want the community set, the operator dir and the pack", v, ok)
	}
}

func TestNucleiScanArgs_ResumeAndFollowRedirects(t *testing.T) {
	args := nucleiScanArgs("https://example.com", nucleiScanOptions{
		FollowRedirects: true,
		ResumeFile:      "/tmp/argos-resume.cfg",
	})
	if !hasArg(args, "-follow-redirects") {
		t.Errorf("-follow-redirects missing in %v", args)
	}
	if v, ok := argValue(args, "-resume"); !ok || v != "/tmp/argos-resume.cfg" {
		t.Errorf("-resume = %q (found=%v), want the resume file", v, ok)
	}
}

func TestScanPhases_PassiveFirstByDefault(t *testing.T) {
	runPassive, runActive, passiveBudget, activeBudget := scanPhases(false, "", 180*time.Second)
	if !runPassive || !runActive {
		t.Fatalf("a scan without tags runs both phases: %v/%v", runPassive, runActive)
	}
	if passiveBudget != 60*time.Second {
		t.Errorf("passive budget = %s, want 60s", passiveBudget)
	}
	if activeBudget != 120*time.Second {
		t.Errorf("active budget = %s, want 120s", activeBudget)
	}
	if passiveBudget+activeBudget > 180*time.Second {
		t.Errorf("the phases must share the timeout of the scan: %s + %s", passiveBudget, activeBudget)
	}
}

func TestScanPhases_PassiveOnly(t *testing.T) {
	runPassive, runActive, passiveBudget, _ := scanPhases(true, "", 180*time.Second)
	if !runPassive || runActive {
		t.Fatalf("passive=true runs only the passive phase: %v/%v", runPassive, runActive)
	}
	if passiveBudget != 180*time.Second {
		t.Errorf("passive budget = %s, want the whole timeout", passiveBudget)
	}
}

func TestScanPhases_ScopedScanRunsTheRequestedSetOnly(t *testing.T) {
	runPassive, runActive, _, activeBudget := scanPhases(false, "sqli", 180*time.Second)
	if runPassive {
		t.Error("a scan that declares its template set must not run the passive sweep")
	}
	if !runActive {
		t.Error("a scan that declares its template set must run the active phase")
	}
	if activeBudget != 180*time.Second {
		t.Errorf("active budget = %s, want the whole timeout", activeBudget)
	}
}

func TestDedupeFindings(t *testing.T) {
	fs := dedupeFindings([]Finding{
		{RuleID: "nuclei:a", Vector: "https://x/1"},
		{RuleID: "nuclei:a", Vector: "https://x/1"},
		{RuleID: "nuclei:a", Vector: "https://x/2"},
	})
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2", len(fs))
	}
}

func TestSplitExclusions_RoutesIDsAndTags(t *testing.T) {
	ids, tags := splitExclusions([]string{"sqli", "http/cves/2021/CVE-2021-44228.yaml", "exposure.yaml", "", "  xss  "})
	if len(ids) != 2 {
		t.Fatalf("ids = %v, want the two path-like entries", ids)
	}
	if len(tags) != 2 || tags[0] != "sqli" || tags[1] != "xss" {
		t.Fatalf("tags = %v, want [sqli xss]", tags)
	}
}

func TestDegradeScanOptions_SoftensTheScan(t *testing.T) {
	opts := degradeScanOptions(nucleiScanOptions{
		RateLimit:   20,
		Concurrency: 40,
		Headless:    true,
	})
	if opts.RateLimit != 10 {
		t.Errorf("rate limit = %d, want 10", opts.RateLimit)
	}
	if opts.Concurrency != 20 {
		t.Errorf("concurrency = %d, want 20", opts.Concurrency)
	}
	if opts.Headless {
		t.Error("a degraded scan must not run headless templates")
	}
	if len(opts.ExcludeTags) == 0 {
		t.Error("a degraded scan must exclude the intrusive payload classes")
	}
}

func TestNucleiTemplateStats(t *testing.T) {
	stderr := strings.Join([]string{
		`{"startedAt":"2026-01-01T00:00:00Z","duration":"0:00:12","templates":"11456","hosts":"1","matched":"3","requests":"120","total":"120","rps":"10","errors":"0","percent":"100"}`,
	}, "\n")
	templates, matched := nucleiTemplateStats(stderr)
	if templates != 11456 {
		t.Errorf("templates = %d, want 11456", templates)
	}
	if matched != 3 {
		t.Errorf("matched = %d, want 3", matched)
	}
	if templates, _ := nucleiTemplateStats("no stats here"); templates != 0 {
		t.Errorf("templates = %d, want 0 without stats", templates)
	}
}

func TestScanResult_ReportsPassiveAndActiveSeparately(t *testing.T) {
	passive := []Finding{{RuleID: "nuclei:exposed-env-file", Title: "passive finding", Severity: SeverityHigh}}
	active := []Finding{{RuleID: "nuclei:CVE-2021-44228", Title: "active finding", Severity: SeverityCritical}}

	res := scanResult(scanOutcome{
		target:  "https://example.com",
		agg:     &runResult{},
		passive: passive,
		active:  active,
		opts:    nucleiScanOptions{RateLimit: 10, Concurrency: 25},
		breaker: guard.New(guard.Options{}),
	})

	passiveFindings, _ := res["passive_findings"].([]map[string]any)
	activeFindings, _ := res["active_findings"].([]map[string]any)
	all, _ := res["findings"].([]map[string]any)
	if len(passiveFindings) != 1 || passiveFindings[0]["title"] != "passive finding" {
		t.Errorf("passive_findings = %v, want the passive finding", passiveFindings)
	}
	if len(activeFindings) != 1 || activeFindings[0]["title"] != "active finding" {
		t.Errorf("active_findings = %v, want the active finding", activeFindings)
	}
	if len(all) != 2 {
		t.Errorf("findings = %d, want the union of both phases", len(all))
	}
	if res["passive_count"] != 1 || res["active_count"] != 1 {
		t.Errorf("counts = %v/%v, want 1/1", res["passive_count"], res["active_count"])
	}
	if res["rate_limit"] != 10 || res["concurrency"] != 25 {
		t.Errorf("the limits must be reported: %v", res)
	}
	if res["degraded"] != false {
		t.Errorf("degraded = %v, want false", res["degraded"])
	}
}

type scanPreflightExecutor struct {
	spec     sandbox.CommandSpec
	output   string
	exitCode int
	err      error
	calls    int
}

func (e *scanPreflightExecutor) Execute(_ context.Context, spec sandbox.CommandSpec) (*sandbox.CommandResult, error) {
	e.spec = spec
	e.calls++
	if e.err != nil {
		return nil, e.err
	}
	return &sandbox.CommandResult{Stdout: e.output, ExitCode: e.exitCode, Sandboxed: true}, nil
}

func (*scanPreflightExecutor) IsSandboxed() bool { return true }

func (*scanPreflightExecutor) Name() string { return "docker" }

func setScanPreflightExecutor(t *testing.T, output string, exitCode int) *scanPreflightExecutor {
	t.Helper()
	previous := defaultExecutor
	executor := &scanPreflightExecutor{output: output, exitCode: exitCode}
	defaultExecutor = executor
	t.Cleanup(func() { defaultExecutor = previous })
	return executor
}

func TestWebScan_AbortsWhenWorkerHealthProbesShowTargetDegradation(t *testing.T) {
	target := "http://127.0.0.1:8080"
	preflight, err := json.Marshal(workerpreflight.Result{
		Protocol: workerpreflight.ProtocolVersion,
		Target:   target,
		Complete: true,
		Probes: []workerpreflight.Probe{
			{Status: http.StatusOK, LatencyMS: 1},
			{Status: http.StatusServiceUnavailable, LatencyMS: 1},
			{Status: http.StatusOK, LatencyMS: 1},
			{Status: http.StatusServiceUnavailable, LatencyMS: 1},
			{Status: http.StatusOK, LatencyMS: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	executor := setScanPreflightExecutor(t, string(preflight), 0)
	env := envWithScope(t, scopeConfigForLoopback("scan-abort"))

	server := mcp.NewServerWithIO(mcp.ServerInfo{Name: "argos-web"}, bytes.NewReader(nil), io.Discard)
	RegisterScan(server, env)
	handler := server.GetToolHandler("web.scan")
	if handler == nil {
		t.Fatal("web.scan was not registered")
	}

	params, err := json.Marshal(map[string]any{"target": target})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	result, errObj := handler(controllerScopeCall("ses_scan_abort", "call_scan_abort", []string{"127.0.0.0/8"}, nil), params)
	if errObj != nil {
		t.Fatalf("web.scan returned an error: %+v", errObj)
	}
	res, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	if res["status"] != "aborted" {
		t.Fatalf("status = %v, want aborted", res["status"])
	}
	if res["aborted"] != true {
		t.Errorf("aborted = %v, want true", res["aborted"])
	}
	reason, _ := res["abort_reason"].(string)
	if !strings.Contains(reason, "server error rate") {
		t.Errorf("abort_reason = %q, want the server error rate rule", reason)
	}
	if findings, _ := res["findings"].([]map[string]any); len(findings) != 0 {
		t.Errorf("an aborted scan must not report findings: %v", findings)
	}

	// The whole point of the tripwire: the target received a handful of
	// requests, not the thousands a template engine would have sent.
	if executor.calls != 1 || executor.spec.Path != "/usr/local/bin/argos-worker-preflight" {
		t.Fatalf("preflight executor calls=%d spec=%+v; scanner must not start after breaker abort", executor.calls, executor.spec)
	}
	if executor.spec.NetworkMode != "scope-gateway" || executor.spec.SessionID != "ses_scan_abort" || executor.spec.OperationID != "call_scan_abort" {
		t.Fatalf("preflight worker did not receive the controller scope: %+v", executor.spec)
	}
}

func TestWorkerScanPreflight_DegradesOnWAFAndUsesTheScopeGateway(t *testing.T) {
	target := "https://app.example.test/"
	output, err := json.Marshal(workerpreflight.Result{
		Protocol:    workerpreflight.ProtocolVersion,
		Target:      target,
		Complete:    true,
		Probes:      []workerpreflight.Probe{{Status: 200}, {Status: 200}, {Status: 200}, {Status: 200}, {Status: 200}},
		WAFVendors:  []string{"Cloudflare"},
		WAFEvidence: map[string]string{"Cloudflare": "cf-ray: abc123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	executor := setScanPreflightExecutor(t, string(output), 0)
	breaker := guard.New(guard.Options{})
	call := controllerScopeCall("ses_preflight_waf", "call_preflight_waf", nil, []string{"app.example.test"})
	result, decision, err := runWorkerScanPreflight(toolContext(call), breaker, target, preflightProbes)
	if err != nil {
		t.Fatalf("runWorkerScanPreflight: %v", err)
	}
	if !decision.Continue || decision.Action != guard.ActionDegrade {
		t.Fatalf("decision = %+v, want continued degraded scan", decision)
	}
	if len(result.WAFVendors) != 1 || result.WAFVendors[0] != "Cloudflare" {
		t.Fatalf("WAF vendors = %v", result.WAFVendors)
	}
	if executor.spec.NetworkMode != "scope-gateway" || executor.spec.SessionID != call.SessionID || executor.spec.OperationID != call.OperationID {
		t.Fatalf("preflight worker did not receive the controller scope: %+v", executor.spec)
	}
}

func TestWorkerScanPreflight_RejectsIncompleteOrMalformedOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{name: "incomplete", output: `{"protocol":1,"target":"http://target.example.test/","complete":false,"probes":[]}`},
		{name: "malformed", output: `{"protocol":1`},
		{name: "trailing json", output: `{"protocol":1,"target":"http://target.example.test/","complete":true,"probes":[{"status":200,"latency_ms":1},{"status":200,"latency_ms":1},{"status":200,"latency_ms":1},{"status":200,"latency_ms":1},{"status":200,"latency_ms":1}]} {}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setScanPreflightExecutor(t, test.output, 0)
			call := controllerScopeCall("ses_preflight_invalid", "call_preflight_invalid", nil, []string{"target.example.test"})
			_, _, err := runWorkerScanPreflight(toolContext(call), guard.New(guard.Options{}), "http://target.example.test/", preflightProbes)
			if err == nil {
				t.Fatal("runWorkerScanPreflight accepted invalid worker output")
			}
		})
	}
}

func TestWebScan_ReportsTheWAFDegradation(t *testing.T) {
	// A WAF in front of the target softens the scan: the result must say so.
	breaker := guard.New(guard.Options{})
	breaker.ObserveWAFVendor("Cloudflare")
	decision := breaker.Decision()

	res := scanResult(scanOutcome{
		target:         "https://example.com",
		agg:            &runResult{},
		opts:           nucleiScanOptions{RateLimit: 5, Concurrency: 12},
		degraded:       true,
		degradedReason: decision.Reason,
		decision:       decision,
		breaker:        breaker,
		wafDetected:    true,
		wafVendor:      "Cloudflare",
	})
	if res["degraded"] != true {
		t.Errorf("degraded = %v, want true", res["degraded"])
	}
	if reason, _ := res["degraded_reason"].(string); !strings.Contains(reason, "WAF") {
		t.Errorf("degraded_reason = %q, want the WAF reason", reason)
	}
	if res["waf_detected"] != true || res["waf_vendor"] != "Cloudflare" {
		t.Errorf("the WAF must be reported: %v", res)
	}
	breakerInfo, _ := res["breaker"].(map[string]interface{})
	if breakerInfo["action"] != guard.ActionDegrade {
		t.Errorf("the breaker verdict must be observable: %v", breakerInfo)
	}
}

func TestWebScan_BlocksWhenContainerPreflightIsUnavailable(t *testing.T) {
	previous := defaultExecutor
	executor := &scanPreflightExecutor{err: errors.New("Docker is unavailable")}
	defaultExecutor = executor
	t.Cleanup(func() { defaultExecutor = previous })

	env := envWithScope(t, scopeConfigForLoopback("scan-worker-unavailable"))
	server := mcp.NewServerWithIO(mcp.ServerInfo{Name: "argos-web"}, bytes.NewReader(nil), io.Discard)
	RegisterScan(server, env)
	handler := server.GetToolHandler("web.scan")
	params, err := json.Marshal(map[string]any{"target": "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	result, errObj := handler(controllerScopeCall("ses_worker_unavailable", "call_worker_unavailable", []string{"127.0.0.0/8"}, nil), params)
	if errObj != nil {
		t.Fatalf("web.scan returned a tool error instead of a blocked audit result: %+v", errObj)
	}
	res, ok := result.(map[string]interface{})
	if !ok || res["status"] != "aborted" {
		t.Fatalf("result = %v, want an aborted result", result)
	}
	if reason, _ := res["abort_reason"].(string); !strings.Contains(reason, "Docker is unavailable") {
		t.Fatalf("abort_reason = %q, want the worker dependency failure", reason)
	}
	if executor.calls != 1 {
		t.Fatalf("worker executor calls = %d, want one and no scanner fallback", executor.calls)
	}
}

func TestWebWAF_UsesTheWorkerWhenContainerRuntimeIsRequired(t *testing.T) {
	target := "https://app.example.test"
	output, err := json.Marshal(workerpreflight.Result{
		Protocol:    workerpreflight.ProtocolVersion,
		Target:      target,
		Complete:    true,
		Probes:      []workerpreflight.Probe{{Status: http.StatusOK, LatencyMS: 1}},
		WAFVendors:  []string{"Cloudflare"},
		WAFEvidence: map[string]string{"Cloudflare": "cf-ray: abc123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	executor := setScanPreflightExecutor(t, string(output), 0)
	env := envWithScope(t, scope.ScopeConfig{AllowedDomains: []string{"app.example.test"}, RequireWorkerProxy: true})
	env.RequireWorkerProxy = true
	server := mcp.NewServerWithIO(mcp.ServerInfo{Name: "argos-web"}, bytes.NewReader(nil), io.Discard)
	RegisterWAF(server, env)
	handler := server.GetToolHandler("web.waf")
	params, err := json.Marshal(map[string]any{"target": target})
	if err != nil {
		t.Fatal(err)
	}
	call := controllerScopeCall("ses_waf_worker", "call_waf_worker", nil, []string{"app.example.test"})
	result, errObj := handler(call, params)
	if errObj != nil {
		t.Fatalf("web.waf returned an error: %+v", errObj)
	}
	res, ok := result.(map[string]interface{})
	if !ok || res["waf_detected"] != true || res["status"] != "completed" {
		t.Fatalf("result = %v, want a completed WAF detection", result)
	}
	if executor.calls != 1 || executor.spec.Path != "/usr/local/bin/argos-worker-preflight" || executor.spec.NetworkMode != "scope-gateway" {
		t.Fatalf("web.waf did not execute inside the scope-gateway worker: calls=%d spec=%+v", executor.calls, executor.spec)
	}
	if decision := SessionBreaker(&Env{SessionID: call.SessionID}).Decision(); decision.Action != guard.ActionDegrade {
		t.Fatalf("session breaker decision = %+v, want WAF degradation", decision)
	}
}

func TestWebWAF_FeedsTheSessionBreaker(t *testing.T) {
	env := envWithScope(t, scopeConfigForLoopback("waf-breaker"))
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "abc123")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("blocked"))
	}))
	defer srv.Close()
	server := mcp.NewServerWithIO(mcp.ServerInfo{Name: "argos-web"}, bytes.NewReader(nil), io.Discard)
	RegisterWAF(server, env)
	handler := server.GetToolHandler("web.waf")
	if handler == nil {
		t.Fatal("web.waf was not registered")
	}
	params, err := json.Marshal(map[string]any{"target": srv.URL})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	result, errObj := handler(controllerScopeCall("ses_waf_breaker", "call_waf_breaker", []string{"127.0.0.0/8"}, nil), params)
	if errObj != nil {
		t.Fatalf("web.waf returned an error: %+v", errObj)
	}
	res, _ := result.(map[string]interface{})
	if res["waf_detected"] != true {
		t.Fatalf("web.waf result = %#v; waf_detected = %v, want true", res, res["waf_detected"])
	}
	if atomic.LoadInt32(&requests) != 1 {
		t.Fatalf("expected exactly one request, got %d", atomic.LoadInt32(&requests))
	}
	if res["waf_assessment"] != "fingerprint_observed" {
		t.Fatalf("waf_assessment = %v, want fingerprint_observed", res["waf_assessment"])
	}

	// The verdict travels to the breaker of the session: the scans that
	// follow are softened.
	decision := SessionBreaker(&Env{SessionID: "ses_waf_breaker"}).Decision()
	if decision.Action != guard.ActionDegrade {
		t.Fatalf("the breaker action = %q, want %q after a WAF detection", decision.Action, guard.ActionDegrade)
	}
}

func TestWebWAF_ReportsIncompleteWhenProbeFails(t *testing.T) {
	env := envWithScope(t, scopeConfigForLoopback("waf-probe-error"))
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	server := mcp.NewServerWithIO(mcp.ServerInfo{Name: "argos-web"}, bytes.NewReader(nil), io.Discard)
	RegisterWAF(server, env)
	handler := server.GetToolHandler("web.waf")
	params, err := json.Marshal(map[string]any{"target": srv.URL})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	result, errObj := handler(controllerScopeCall("ses_waf_error", "call_waf_error", []string{"127.0.0.0/8"}, nil), params)
	if errObj != nil {
		t.Fatalf("web.waf returned an error: %+v", errObj)
	}
	res, _ := result.(map[string]interface{})
	if res["status"] != "incomplete" || res["waf_detected"] != nil || res["waf_probe_error"] == nil {
		t.Fatalf("failed probe must not look like a negative WAF verdict: %#v", res)
	}
}

func TestWebWAF_NoFingerprintIsReportedAsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("application response without WAF fingerprint"))
	}))
	defer srv.Close()

	env := envWithScope(t, scopeConfigForLoopback("waf-inconclusive"))
	server := mcp.NewServerWithIO(mcp.ServerInfo{Name: "argos-web"}, bytes.NewReader(nil), io.Discard)
	RegisterWAF(server, env)
	handler := server.GetToolHandler("web.waf")
	params, err := json.Marshal(map[string]any{"target": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, errObj := handler(controllerScopeCall("ses_waf_inconclusive", "call_waf_inconclusive", []string{"127.0.0.0/8"}, nil), params)
	if errObj != nil {
		t.Fatalf("web.waf returned an error: %+v", errObj)
	}
	res, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result = %T, want object", result)
	}
	if res["waf_detected"] != false {
		t.Fatalf("waf_detected = %v, want false when no signature matches", res["waf_detected"])
	}
	if res["waf_assessment"] != "inconclusive" {
		t.Fatalf("waf_assessment = %v, want inconclusive because passive fingerprints cannot prove absence", res["waf_assessment"])
	}
	wafs, ok := res["wafs"].([]string)
	if !ok || wafs == nil || len(wafs) != 0 {
		t.Fatalf("wafs = %#v, want a non-nil empty list so coverage can attest the result", res["wafs"])
	}
}

func TestResumeFileFor_IsStablePerTarget(t *testing.T) {
	first := resumeFileFor("https://example.com")
	second := resumeFileFor("https://example.com")
	if first != second {
		t.Errorf("the resume file must be stable per target: %q vs %q", first, second)
	}
	if other := resumeFileFor("https://other.example.com"); other == first {
		t.Error("different targets must not share a resume file")
	}
	if !strings.HasPrefix(filepath.Base(first), "argos-web-resume-") {
		t.Errorf("unexpected resume file name: %q", filepath.Base(first))
	}
}
