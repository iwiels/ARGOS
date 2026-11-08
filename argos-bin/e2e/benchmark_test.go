package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/env"
	"github.com/iwiels/ARGOS/argos-bin/internal/practicetarget"
)

// ---------------------------------------------------------------------------
// The benchmark measures three runners against the same ground truth:
//
//	argos_full       — the Argos tools with the canonical contract (tags, CWE,
//	                    severity, evidence) and the taxonomy dedup.
//	argos_no_agents  — the same tools without the canonical contract: only the
//	                    title and the URL of every finding survive.
//	raw_tools        — the third party binaries (nuclei, dalfox, ...) run
//	                    directly, without Argos in the path.
//
// The comparison answers one question: how much of the coverage comes from
// Argos and how much from the scanners it drives.
// ---------------------------------------------------------------------------

const (
	runnerArgosFull      = "argos_full"
	runnerArgosNoAgents  = "argos_no_agents"
	runnerRawTools       = "raw_tools"
	modeLight            = "light"
	modeFull             = "full"
	modeNone             = "none"
	toolUnsupported      = "unsupported"
	reportFileName       = "benchmark-report.json"
	reportMarkdownName   = "benchmark-report.md"
	baselineFileName     = "baseline.json"
	knownToolNamespaces  = "web."
	groundTruthProbeWait = 2 * time.Second
)

// MatchRule is one condition a finding has to meet to be counted as the
// detection of a ground truth item.
//
// The rule is evaluated against the haystack of the finding: the canonical
// haystack (title, taxonomy and evidence) for the runners that speak the
// Argos contract, the raw haystack (title and URL) for the ones that do not.
type MatchRule struct {
	// Tool restricts the rule to the findings of one tool ("web.ssrf").
	Tool string `json:"tool,omitempty"`
	// Path is a fragment the target of the finding must contain.
	Path string `json:"path,omitempty"`
	// Any is a list of alternatives: at least one has to be in the haystack.
	Any []string `json:"any,omitempty"`
	// All is a list of conditions: every one of them has to be in the
	// haystack.
	All []string `json:"all,omitempty"`
}

// GroundTruthItem is one vulnerability the practice target really has.
type GroundTruthItem struct {
	ID           string      `json:"id"`
	Category     string      `json:"category"`
	Path         string      `json:"path"`
	Description  string      `json:"description"`
	Severity     string      `json:"severity"`
	ExpectedTool string      `json:"expected_tool"`
	// Mode is the mode in which the vector is measurable: "light" (the
	// native tools, no binary download), "full" (the third party scanners)
	// or "none" (no tool of Argos detects it today).
	Mode string `json:"mode"`
	// Probe is the URL the smoke test uses to check that the target really
	// exposes the vector.
	Probe       string `json:"probe,omitempty"`
	ProbeStatus int    `json:"probe_status,omitempty"`
	// Detected and MatchedBy are filled by the benchmark.
	Detected  bool   `json:"detected"`
	MatchedBy string `json:"matched_by,omitempty"`
	Matchers  []MatchRule `json:"matchers"`
}

// Supported reports whether a tool of Argos can detect the vector.
func (g GroundTruthItem) Supported() bool {
	return g.ExpectedTool != toolUnsupported
}

// Baseline is the versioned reference the CI gate compares the benchmark
// against. It is only updated with an explicit justification in the PR.
type Baseline struct {
	Version            int     `json:"version"`
	UpdatedAt          string  `json:"updated_at"`
	Commit             string  `json:"commit"`
	Mode               string  `json:"mode"`
	Runner             string  `json:"runner"`
	GroundTruthTotal   int     `json:"ground_truth_total"`
	LightGroundTruth   int     `json:"light_ground_truth_total"`
	RecallPercent      float64 `json:"recall_percent"`
	OverallRecall      float64 `json:"overall_recall_percent"`
	PrecisionPercent   float64 `json:"precision_percent"`
	RecallTolerance    float64 `json:"recall_tolerance_percent"`
	PrecisionTolerance float64 `json:"precision_tolerance_percent"`
	Notes              string  `json:"notes"`
}

// RunnerResult is the outcome of one runner.
type RunnerResult struct {
	Runner              string  `json:"runner"`
	Description         string  `json:"description"`
	Measured            bool    `json:"measured"`
	Reason              string  `json:"reason,omitempty"`
	DurationSec         float64 `json:"duration_seconds"`
	TotalReported       int     `json:"total_reported_findings"`
	TruePositives       int     `json:"true_positives"`
	FalsePositives      int     `json:"false_positives"`
	DetectedGT          int     `json:"detected_ground_truth"`
	RecallPercent       float64 `json:"recall_percent"`
	LightRecallPercent  float64 `json:"light_recall_percent"`
	PrecisionPercent    float64 `json:"precision_percent"`
	FPRPercent          float64 `json:"false_positive_rate_percent"`
}

// BenchmarkReport is the artifact the benchmark writes.
type BenchmarkReport struct {
	Timestamp   string            `json:"timestamp"`
	Target      string            `json:"target"`
	Mode        string            `json:"mode"`
	DurationSec float64           `json:"duration_seconds"`
	TotalGT     int               `json:"total_ground_truth"`
	LightGT     int               `json:"light_ground_truth"`
	Unsupported int               `json:"unsupported_ground_truth"`
	Runners     []RunnerResult    `json:"runners"`
	Items       []GroundTruthItem `json:"ground_truth_items"`
	Gate        GateResult        `json:"gate"`
}

// GateResult is the outcome of the comparison against the baseline.
type GateResult struct {
	Checked        bool    `json:"checked"`
	Passed         bool    `json:"passed"`
	Reason         string  `json:"reason,omitempty"`
	BaselineRecall float64 `json:"baseline_recall_percent"`
	BaselinePrec   float64 `json:"baseline_precision_percent"`
}

// defaultGroundTruth is the catalogue of the vulnerabilities the practice
// target really exposes.
//
// Every entry names the tool of Argos that has to detect it. The vectors that
// no tool detects today are marked as "unsupported": they are the gap list of
// the product, not a failure of the benchmark.
func defaultGroundTruth() []GroundTruthItem {
	return []GroundTruthItem{
		{ID: "GT-SQLI-01", Category: "sqli", Path: "/search?q=1", Description: "SQLi in query parameter q (blind / syntax error)", Severity: "critical", ExpectedTool: "web.sqli", Mode: modeFull,
			Probe: "/search?q=1", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.sqli", Path: "/search", Any: []string{"sqli"}}}},
		{ID: "GT-SQLI-02", Category: "sqli", Path: "/item?id=1", Description: "SQLi in query parameter id (numeric boolean differential)", Severity: "critical", ExpectedTool: "web.sqli", Mode: modeFull,
			Probe: "/item?id=1", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.sqli", Path: "/item", Any: []string{"sqli"}}}},
		{ID: "GT-XSS-01", Category: "xss", Path: "/profile?user=admin", Description: "Reflected XSS in parameter user", Severity: "medium", ExpectedTool: "web.xss", Mode: modeFull,
			Probe: "/profile?user=admin", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.xss", Path: "/profile", Any: []string{"xss"}}}},
		{ID: "GT-LEAK-ENV", Category: "exposure", Path: "/.env", Description: "Exposed environment configuration file", Severity: "high", ExpectedTool: "web.fuzz", Mode: modeFull,
			Probe: "/.env", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.fuzz", Any: []string{".env"}}}},
		{ID: "GT-LEAK-BACKUP", Category: "exposure", Path: "/backup.zip", Description: "Exposed backup archive", Severity: "high", ExpectedTool: "web.fuzz", Mode: modeFull,
			Probe: "/backup.zip", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.fuzz", Any: []string{"backup"}}}},
		{ID: "GT-ROBOTS", Category: "recon", Path: "/robots.txt", Description: "Exposed robots.txt disclosing sensitive routes", Severity: "low", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/robots.txt", ProbeStatus: 200,
			Matchers: []MatchRule{}},
		{ID: "GT-HEADER-CSP", Category: "misconfig", Path: "/", Description: "Missing Content-Security-Policy header", Severity: "low", ExpectedTool: "web.scan", Mode: modeFull,
			Probe: "/", ProbeStatus: 200,
			Matchers: []MatchRule{{Any: []string{"content-security-policy"}}}},
		{ID: "GT-HEADER-HSTS", Category: "misconfig", Path: "/", Description: "Missing Strict-Transport-Security header", Severity: "low", ExpectedTool: "web.scan", Mode: modeFull,
			Probe: "/", ProbeStatus: 200,
			Matchers: []MatchRule{{Any: []string{"strict-transport-security"}}}},
		{ID: "GT-HEADER-XFO", Category: "misconfig", Path: "/", Description: "Missing X-Frame-Options header (clickjacking)", Severity: "low", ExpectedTool: "web.scan", Mode: modeFull,
			Probe: "/", ProbeStatus: 200,
			Matchers: []MatchRule{{Any: []string{"x-frame-options", "frame-ancestors"}}}},

		{ID: "GT-IDOR-01", Category: "idor", Path: "/api/item/{id}", Description: "IDOR/BOLA: the record of any user is returned without checking the session", Severity: "critical", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/api/item/2", ProbeStatus: 200,
			Matchers: []MatchRule{}},
		{ID: "GT-CSRF-01", Category: "csrf", Path: "/login", Description: "CSRF: the login form has no anti-CSRF token", Severity: "high", ExpectedTool: "web.csrf", Mode: modeLight,
			Probe: "/login", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.csrf", Path: "/login", All: []string{"csrf", "anti-csrf token"}}}},
		{ID: "GT-CSRF-02", Category: "csrf", Path: "/api/transfer", Description: "CSRF: a state changing endpoint with no token and no Origin validation", Severity: "high", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/api/transfer", ProbeStatus: 405,
			Matchers: []MatchRule{}},
		{ID: "GT-JWT-01", Category: "jwt", Path: "/api/token", Description: "JWT signed with alg:none (the signature is never verified)", Severity: "critical", ExpectedTool: "web.jwt", Mode: modeLight,
			Probe: "/api/token", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.jwt", Any: []string{"alg=none"}}}},
		{ID: "GT-JWT-02", Category: "jwt", Path: "/api/token", Description: "JWT without exp claim: the token never expires", Severity: "medium", ExpectedTool: "web.jwt", Mode: modeLight,
			Probe: "/api/token", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.jwt", Any: []string{"without exp claim"}}}},
		{ID: "GT-JWT-03", Category: "jwt", Path: "/api/token", Description: "JWT without aud claim: the audience cannot be validated", Severity: "medium", ExpectedTool: "web.jwt", Mode: modeLight,
			Probe: "/api/token", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.jwt", Any: []string{"without aud claim"}}}},
		{ID: "GT-JWT-04", Category: "jwt", Path: "/api/token", Description: "JWT carries a mutable privilege claim: the role of the token is client controlled", Severity: "high", ExpectedTool: "web.jwt", Mode: modeLight,
			Probe: "/api/token", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.jwt", Any: []string{"mutable privilege claim"}}}},
		{ID: "GT-JWT-05", Category: "jwt", Path: "/api/token", Description: "JWT without iss claim: the issuer cannot be validated", Severity: "low", ExpectedTool: "web.jwt", Mode: modeLight,
			Probe: "/api/token", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.jwt", Any: []string{"without iss claim"}}}},
		{ID: "GT-SSRF-01", Category: "ssrf", Path: "/fetch?url=", Description: "Blind SSRF: the server fetches the URL it receives and leaks the internal failure", Severity: "high", ExpectedTool: "web.ssrf", Mode: modeLight,
			Probe: "/fetch?url=http://127.0.0.1:1/", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.ssrf", Path: "/fetch", Any: []string{"ssrf"}}}},
		{ID: "GT-XXE-01", Category: "xxe", Path: "/api/xml", Description: "XXE: the XML parser resolves external entities and reads local files", Severity: "high", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/api/xml", ProbeStatus: 200,
			Matchers: []MatchRule{}},
		{ID: "GT-SSTI-01", Category: "ssti", Path: "/render?tpl=", Description: "SSTI: the template evaluates the expression of the request", Severity: "critical", ExpectedTool: "web.ssti", Mode: modeLight,
			Probe: "/render?tpl=%7B%7B7*7%7D%7D", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.ssti", Path: "/render", Any: []string{"template injection", "ssti"}}}},
		{ID: "GT-OPENREDIR-01", Category: "redirect", Path: "/redirect?u=", Description: "Open redirect: any destination is accepted", Severity: "medium", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/redirect?u=https://evil.example/", ProbeStatus: 302,
			Matchers: []MatchRule{}},
		{ID: "GT-PATHTRAV-01", Category: "traversal", Path: "/download?file=", Description: "Path traversal: the file name escapes the base directory", Severity: "high", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/download?file=../../../../etc/passwd", ProbeStatus: 200,
			Matchers: []MatchRule{}},
		{ID: "GT-CMDI-01", Category: "cmd-injection", Path: "/ping?host=", Description: "Command injection: the host is concatenated into a shell command", Severity: "critical", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/ping?host=127.0.0.1", ProbeStatus: 200,
			Matchers: []MatchRule{}},
		{ID: "GT-DESER-01", Category: "deserialization", Path: "/api/deserialize", Description: "Unsafe deserialization: the gadget of the payload reaches the shell", Severity: "critical", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/api/deserialize", ProbeStatus: 400,
			Matchers: []MatchRule{}},
		{ID: "GT-GQL-01", Category: "graphql", Path: "/graphql", Description: "GraphQL introspection is enabled: the whole schema is readable", Severity: "medium", ExpectedTool: "web.graphql", Mode: modeLight,
			Probe: "/graphql", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.graphql", Path: "/graphql", All: []string{"graphql introspection"}}}},
		{ID: "GT-GQL-02", Category: "graphql", Path: "/graphql", Description: "The GraphQL schema exposes sensitive fields (the password of the user)", Severity: "medium", ExpectedTool: "web.graphql", Mode: modeLight,
			Probe: "/graphql", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.graphql", Path: "/graphql", Any: []string{"sensitive fields"}}}},
		{ID: "GT-GQL-03", Category: "graphql", Path: "/graphql", Description: "GraphQL exposes state changing mutations without an authorization rule", Severity: "medium", ExpectedTool: "web.graphql", Mode: modeLight,
			Probe: "/graphql", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.graphql", Path: "/graphql", Any: []string{"state changing"}}}},
		{ID: "GT-GQL-04", Category: "graphql", Path: "/graphql", Description: "GraphQL has no depth limit: a deeply nested query is accepted", Severity: "medium", ExpectedTool: "web.graphql", Mode: modeLight,
			Probe: "/graphql", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.graphql", Path: "/graphql", Any: []string{"depth limit"}}}},
		{ID: "GT-GQL-05", Category: "graphql", Path: "/graphql", Description: "GraphQL processes batched operations: a single request is amplified", Severity: "medium", ExpectedTool: "web.graphql", Mode: modeLight,
			Probe: "/graphql", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.graphql", Path: "/graphql", Any: []string{"batched operations"}}}},
		{ID: "GT-SMUGGLE-01", Category: "smuggling", Path: "/ (front proxy)", Description: "HTTP request smuggling: the front-end accepts an ambiguous framing (CL+TE)", Severity: "high", ExpectedTool: "web.smuggle", Mode: modeLight,
			Matchers: []MatchRule{{Tool: "web.smuggle", Any: []string{"smuggling"}}}},
		{ID: "GT-RACE-01", Category: "race", Path: "/api/coupon", Description: "Race condition: a single use coupon is redeemed twice concurrently", Severity: "medium", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/api/coupon", ProbeStatus: 200,
			Matchers: []MatchRule{}},
		{ID: "GT-USERENUM-01", Category: "auth", Path: "/api/login", Description: "User enumeration: the response time tells whether the account exists", Severity: "medium", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/api/login?user=admin", ProbeStatus: 200,
			Matchers: []MatchRule{}},
		{ID: "GT-RATELIMIT-01", Category: "auth", Path: "/api/login", Description: "Missing rate limit: the login endpoint never throttles", Severity: "medium", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/api/login?user=admin", ProbeStatus: 200,
			Matchers: []MatchRule{}},
		{ID: "GT-GIT-01", Category: "exposure", Path: "/.git/", Description: "The git repository is exposed", Severity: "high", ExpectedTool: "web.fuzz", Mode: modeFull,
			Probe: "/.git/", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.fuzz", Any: []string{".git"}}}},
		{ID: "GT-GIT-02", Category: "exposure", Path: "/.git/config", Description: "A personal access token travels in the URL of the git remote", Severity: "high", ExpectedTool: "web.artifact", Mode: modeLight,
			Probe: "/.git/config", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.artifact", Path: "/.git/config", Any: []string{"github token"}}}},
		{ID: "GT-CORS-01", Category: "cors", Path: "/api/cors", Description: "Permissive CORS: any origin is accepted together with the credentials", Severity: "high", ExpectedTool: "web.csrf", Mode: modeLight,
			Probe: "/api/cors", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.csrf", Path: "/api/cors", Any: []string{"access-control-allow-origin"}}}},
		{ID: "GT-COOKIE-01", Category: "misconfig", Path: "/login", Description: "The session cookie travels without Secure, HttpOnly nor SameSite", Severity: "medium", ExpectedTool: toolUnsupported, Mode: modeNone,
			Matchers: []MatchRule{}},
		{ID: "GT-VERB-01", Category: "misconfig", Path: "/api/data", Description: "Verb tampering: the endpoint answers the state changing verbs too", Severity: "low", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/api/data", ProbeStatus: 200,
			Matchers: []MatchRule{}},
		{ID: "GT-DEBUGVARS-01", Category: "exposure", Path: "/debug/vars", Description: "Information disclosure: the debug endpoint exposes the configuration and its secrets", Severity: "medium", ExpectedTool: "web.artifact", Mode: modeLight,
			Probe: "/debug/vars", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.artifact", Path: "/debug/vars", Any: []string{"aws access key"}}}},
		{ID: "GT-SECTXT-01", Category: "recon", Path: "/security.txt", Description: "security.txt is missing: the contact channel of the project does not exist", Severity: "info", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/security.txt", ProbeStatus: 404,
			Matchers: []MatchRule{}},
		{ID: "GT-SUBDOMAIN-01", Category: "recon", Path: "dev.payments.acme-corp.local", Description: "Subdomain takeover: the vhost still answers from a deleted bucket", Severity: "high", ExpectedTool: toolUnsupported, Mode: modeNone,
			Matchers: []MatchRule{}},
		{ID: "GT-CACHE-01", Category: "misconfig", Path: "/api/cache", Description: "Cache poisoning: a shared cache serves a response that depends on the headers without Vary", Severity: "medium", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/api/cache", ProbeStatus: 200,
			Matchers: []MatchRule{}},
		{ID: "GT-UNICODE-01", Category: "misconfig", Path: "/unicode/", Description: "Unicode smuggling: the fullwidth spelling of a blocked path slips through the edge", Severity: "medium", ExpectedTool: toolUnsupported, Mode: modeNone,
			Probe: "/unicode/admin", ProbeStatus: 403,
			Matchers: []MatchRule{}},
		{ID: "GT-SECRETJS-01", Category: "exposure", Path: "/static/app.js", Description: "The API key of the backend travels in the JavaScript bundle", Severity: "high", ExpectedTool: "web.artifact", Mode: modeLight,
			Probe: "/static/app.js", ProbeStatus: 200,
			Matchers: []MatchRule{{Tool: "web.artifact", Path: "/static/app.js", Any: []string{"aws access key"}}}},
	}
}

// vulnerabilityMarkers decide whether a finding claims a vulnerability (and
// therefore counts against the precision) or is recon noise.
var vulnerabilityMarkers = []string{
	"injection", "xss", "traversal", "ssrf", "csrf", "redirect", "deserializ",
	"command", "disclosure", "exposed", "missing", "weak", "deprecated",
	"insecure", "hardcoded", "leak", "vulnerab", "smuggling", "idor", "bola",
	"introspection", "token", "credential", "secret", "exposure", "ssti",
	"template injection", "sensitive",
}

// findingHaystack aplana un finding del contrato canonico a texto buscable.
// El contrato ya no expone un campo "detail" plano: la evidencia vive en
// "evidence" (objeto) y la taxonomia en "cwe"/"tags"/"rule_id", asi que el
// matching contra el ground truth tiene que mirar el conjunto, no un campo.
func findingHaystack(f map[string]any) string {
	parts := []string{
		strOf(f, "title"),
		strOf(f, "target"),
		strOf(f, "vector"),
		strOf(f, "cwe"),
		strOf(f, "rule_id"),
		strOf(f, "source_tool"),
		strOf(f, "remediation"),
	}
	for _, key := range []string{"tags", "owasp", "references"} {
		if raw, ok := f[key].([]any); ok {
			for _, item := range raw {
				if s, ok := item.(string); ok {
					parts = append(parts, s)
				}
			}
		}
	}
	if evidence, ok := f["evidence"].(map[string]any); ok {
		for _, v := range evidence {
			switch value := v.(type) {
			case string:
				parts = append(parts, value)
			default:
				if encoded, err := json.Marshal(value); err == nil {
					parts = append(parts, string(encoded))
				}
			}
		}
	}
	return strings.Join(parts, " ")
}

// rawHaystack is what a parser of the raw output of a scanner would keep:
// the title and the URL. It is the haystack of the runners that do not speak
// the canonical contract.
func rawHaystack(f map[string]any) string {
	return strings.Join([]string{strOf(f, "title"), strOf(f, "target")}, " ")
}

// stripContract reduces a canonical finding to the shape a scanner would
// produce without Argos: a title, a URL and the severity of the tool.
func stripContract(f map[string]any) map[string]any {
	return map[string]any{
		"title":       strOf(f, "title"),
		"target":      strOf(f, "target"),
		"severity":    strOf(f, "severity"),
		"source_tool": strOf(f, "source_tool"),
	}
}

// taxonomyKey is the identity the agent layer gives to a finding.
//
// A finding that declares a CWE is identified by its taxonomy (CWE, target,
// vector); a finding without a CWE falls back to the historical fingerprint by
// title. It is the same rule the backend applies when it reconciles the
// findings of a session (packages/core/src/security/ingest.ts).
func taxonomyKey(f map[string]any) string {
	target := strings.ToLower(strings.TrimSpace(strOf(f, "target")))
	vector := strings.ToLower(strings.TrimSpace(strOf(f, "vector")))
	if vector == "" {
		vector = target
	}
	cwe := strings.ToLower(strings.TrimSpace(strOf(f, "cwe")))
	if cwe == "" {
		return "v1|" + strings.ToLower(strOf(f, "title")) + "|" + vector + "|" + target
	}
	return "v2|" + cwe + "|" + target + "|" + vector
}

// dedupeByTaxonomy keeps one finding per class of problem: it is what the
// agent layer does before the findings reach the panel.
func dedupeByTaxonomy(findings []map[string]any) []map[string]any {
	seen := map[string]bool{}
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		key := taxonomyKey(f)
		if key != "" {
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		out = append(out, f)
	}
	return out
}

// metrics is the outcome of the comparison between the findings of a runner
// and the ground truth.
type metrics struct {
	TotalGT            int
	DetectedGT         int
	LightTotal         int
	LightDetected      int
	Reported           int
	TruePositives      int
	FalsePositives     int
	RecallPercent      float64
	LightRecallPercent float64
	PrecisionPercent   float64
	FPRPercent         float64
}

// computeMetrics compares the findings of one runner with the ground truth.
//
// A finding that matches one ground truth item is a true positive; a finding
// that matches none and claims a vulnerability is a false positive; the rest
// is recon noise and does not count against the precision.
func computeMetrics(items []GroundTruthItem, findings []map[string]any, haystackOf func(map[string]any) string) metrics {
	m := metrics{TotalGT: len(items)}
	detected, _ := matchGroundTruth(items, findings, haystackOf)
	for _, f := range findings {
		m.Reported++
		haystack := strings.ToLower(haystackOf(f))
		target := strings.ToLower(strOf(f, "target"))
		tool := strOf(f, "source_tool")
		matched := false
		for i := range items {
			if matchesRule(items[i].Matchers, haystack, target, tool) {
				matched = true
			}
		}
		if matched {
			m.TruePositives++
			continue
		}
		if claimsVulnerability(f) {
			m.FalsePositives++
		}
	}
	for i := range items {
		if items[i].Mode != modeLight {
			continue
		}
		m.LightTotal++
		if detected[i] {
			m.LightDetected++
		}
	}
	for i := range items {
		if detected[i] {
			m.DetectedGT++
		}
	}
	if m.TotalGT > 0 {
		m.RecallPercent = float64(m.DetectedGT) / float64(m.TotalGT) * 100
	}
	if m.LightTotal > 0 {
		m.LightRecallPercent = float64(m.LightDetected) / float64(m.LightTotal) * 100
	}
	if m.TruePositives+m.FalsePositives > 0 {
		total := float64(m.TruePositives + m.FalsePositives)
		m.PrecisionPercent = float64(m.TruePositives) / total * 100
		m.FPRPercent = float64(m.FalsePositives) / total * 100
	}
	return m
}

// matchGroundTruth returns, for every item of the catalogue, whether a
// finding of the runner detected it and which tool did it.
func matchGroundTruth(items []GroundTruthItem, findings []map[string]any, haystackOf func(map[string]any) string) ([]bool, []string) {
	detected := make([]bool, len(items))
	matchedBy := make([]string, len(items))
	for _, f := range findings {
		haystack := strings.ToLower(haystackOf(f))
		target := strings.ToLower(strOf(f, "target"))
		tool := strOf(f, "source_tool")
		for i := range items {
			if !matchesRule(items[i].Matchers, haystack, target, tool) {
				continue
			}
			if !detected[i] {
				detected[i] = true
				matchedBy[i] = tool
			}
		}
	}
	return detected, matchedBy
}

// matchesRule reports whether a finding satisfies one of the rules of a
// ground truth item.
func matchesRule(rules []MatchRule, haystack, target, tool string) bool {
	for _, rule := range rules {
		if rule.Tool != "" && !strings.EqualFold(rule.Tool, tool) {
			continue
		}
		if rule.Path != "" && !strings.Contains(target, strings.ToLower(rule.Path)) {
			continue
		}
		ok := true
		for _, keyword := range rule.All {
			if !strings.Contains(haystack, strings.ToLower(keyword)) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if len(rule.Any) > 0 {
			found := false
			for _, keyword := range rule.Any {
				if strings.Contains(haystack, strings.ToLower(keyword)) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		return true
	}
	return false
}

// claimsVulnerability reports whether a finding claims a real issue.
//
// The canonical severity decides it when the finding carries one: the
// recon noise of the scanners is "info". A finding without a severity (the
// output of the tools that do not normalize it) is judged by its title.
func claimsVulnerability(f map[string]any) bool {
	switch strings.ToLower(strOf(f, "severity")) {
	case "critical", "high", "medium":
		return true
	}
	title := strings.ToLower(strOf(f, "title"))
	for _, marker := range vulnerabilityMarkers {
		if strings.Contains(title, marker) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The runs
// ---------------------------------------------------------------------------

// toolCall is one call of the Argos MCP server.
type toolCall struct {
	Tool    string
	Args    map[string]any
	Timeout time.Duration
}

// lightToolCalls are the calls the light mode runs: every one of them is
// native, so the mode does not download a single binary.
func lightToolCalls(base, proxy string) []toolCall {
	return []toolCall{
		{Tool: "web.csrf", Args: map[string]any{"target": base + "/login"}, Timeout: time.Minute},
		{Tool: "web.csrf", Args: map[string]any{"target": base + "/api/cors"}, Timeout: time.Minute},
		{Tool: "web.ssrf", Args: map[string]any{"target": base + "/fetch", "parameter": "url", "timeout": 5}, Timeout: 3 * time.Minute},
		{Tool: "web.ssti", Args: map[string]any{"target": base + "/render", "parameter": "tpl"}, Timeout: 2 * time.Minute},
		{Tool: "web.graphql", Args: map[string]any{"target": base + "/graphql"}, Timeout: 2 * time.Minute},
		{Tool: "web.jwt", Args: map[string]any{"header": "Authorization", "target": base + "/api/token"}, Timeout: time.Minute},
		{Tool: "web.smuggle", Args: map[string]any{"target": proxy}, Timeout: 2 * time.Minute},
		{Tool: "web.artifact", Args: map[string]any{"target": base + "/static/app.js"}, Timeout: time.Minute},
		{Tool: "web.artifact", Args: map[string]any{"target": base + "/debug/vars"}, Timeout: time.Minute},
		{Tool: "web.artifact", Args: map[string]any{"target": base + "/.git/config"}, Timeout: time.Minute},
	}
}

// fullToolCalls are the calls of the full mode: the third party scanners join
// the native ones.
//
// The fuzz runs with the "common" wordlist: the default profile carries
// 119600 entries and the sensitive paths of the target (.env, .git, backup)
// are in the short one.
func fullToolCalls(base, proxy string) []toolCall {
	calls := []toolCall{
		{Tool: "web.probe", Args: map[string]any{"target": base}, Timeout: 3 * time.Minute},
		{Tool: "web.crawl", Args: map[string]any{"target": base, "depth": 2}, Timeout: 4 * time.Minute},
		{Tool: "web.fuzz", Args: map[string]any{"target": base, "wordlist": "common", "timeout": 240}, Timeout: 6 * time.Minute},
		{Tool: "web.sqli", Args: map[string]any{"target": base + "/item?id=1", "native": true}, Timeout: 4 * time.Minute},
		{Tool: "web.sqli", Args: map[string]any{"target": base + "/search?q=1", "native": true}, Timeout: 4 * time.Minute},
		{Tool: "web.xss", Args: map[string]any{"target": base + "/profile?user=admin"}, Timeout: 4 * time.Minute},
		{Tool: "web.scan", Args: map[string]any{"target": base, "tags": "misconfig,exposure", "timeout": 240}, Timeout: 6 * time.Minute},
	}
	return append(calls, lightToolCalls(base, proxy)...)
}

// collectFindings turns the result of a tool call into the findings it
// produced.
//
// The tools that do not publish findings (web.artifact returns the
// intelligence it extracted) are translated into the same shape so the
// matcher sees one kind of record.
func collectFindings(tool string, res map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, f := range listOf(res, "findings") {
		if fm, ok := f.(map[string]any); ok {
			if strOf(fm, "source_tool") == "" {
				fm["source_tool"] = tool
			}
			out = append(out, fm)
		}
	}
	if tool == "web.artifact" {
		target := strOf(res, "target")
		for _, secret := range listOf(res, "secrets") {
			sm, ok := secret.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, map[string]any{
				"title":       "Secret exposed in the artifact: " + strOf(sm, "type"),
				"target":      target,
				"source_tool": tool,
				"severity":    "high",
				"confidence":  "confirmed",
				"tags":        []any{"secret-exposure"},
				"evidence":    map[string]any{"type": strOf(sm, "type"), "line": sm["line"]},
			})
		}
	}
	return out
}

// runArgosTools runs the Argos tools over the practice target and returns
// every finding they produced, with the time the round took.
func runArgosTools(t *testing.T, client *mcpClient, calls []toolCall) ([]map[string]any, []string, time.Duration) {
	t.Helper()
	findings := []map[string]any{}
	executed := []string{}
	started := time.Now()
	idSeq := 200
	for _, call := range calls {
		idSeq++
		res, err := client.call(idSeq, "tools/call", map[string]any{"name": call.Tool, "arguments": call.Args}, call.Timeout)
		if err != nil {
			t.Logf("tool %s: %v", call.Tool, err)
			executed = append(executed, call.Tool+"=error")
			continue
		}
		unwrapped := unwrapToolResult(t, res)
		produced := collectFindings(call.Tool, unwrapped)
		t.Logf("tool %-14s -> %d findings", call.Tool, len(produced))
		if len(produced) == 0 {
			// A tool that reports nothing has to say why: a missing binary
			// and a target without the vector are very different things.
			t.Logf("tool %-14s status=%q summary=%q exit=%v executor=%q stderr=%q",
				call.Tool, strOf(unwrapped, "status"), strOf(unwrapped, "summary"),
				unwrapped["exit_code"], strOf(unwrapped, "executor"),
				truncateForLog(strOf(unwrapped, "stderr_tail")))
		}
		findings = append(findings, produced...)
		executed = append(executed, fmt.Sprintf("%s=%d", call.Tool, len(produced)))
	}
	return findings, executed, time.Since(started)
}

// rawToolRunner runs the third party binaries without Argos in the path.
type rawToolRunner struct {
	toolsDir string
	target   string
}

// binaryPath returns the path of a downloaded binary, or "" when it is not
// installed.
func (r rawToolRunner) binaryPath(name string) string {
	candidates := []string{
		filepath.Join(r.toolsDir, name, exeName(name)),
		filepath.Join(r.toolsDir, name),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// templatesPath returns the directory of the nuclei templates, when the
// scanner installed them.
func (r rawToolRunner) templatesPath() string {
	root := filepath.Join(r.toolsDir, "nuclei-templates")
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(root, entry.Name())
		}
	}
	return ""
}

// run executes the raw third party scanners and returns their findings the
// way a naive integration would parse them: a title, a URL and the severity
// of the tool.
//
// A binary that is not installed, or that the operating system refuses to
// run (an antivirus can quarantine a scanner), is reported as unavailable:
// the runner is then partial and the report says which part is missing.
func (r rawToolRunner) run(t *testing.T) ([]map[string]any, []string, []string) {
	t.Helper()
	findings := []map[string]any{}
	used := []string{}
	missing := []string{}

	if nuclei := r.binaryPath("nuclei"); nuclei == "" {
		missing = append(missing, "nuclei: not installed")
	} else {
		args := []string{"-u", r.target, "-jsonl", "-silent", "-no-color", "-timeout", "10", "-retries", "0"}
		if templates := r.templatesPath(); templates != "" {
			args = append(args, "-t", templates)
		}
		out, err := exec.Command(nuclei, args...).CombinedOutput()
		if binaryFailed(err) {
			missing = append(missing, "nuclei: the binary could not be executed: "+err.Error())
			t.Logf("raw nuclei failed: %v", err)
		} else {
			findings = append(findings, parseRawNuclei(string(out))...)
			used = append(used, "nuclei")
		}
	}

	if dalfox := r.binaryPath("dalfox"); dalfox == "" {
		missing = append(missing, "dalfox: not installed")
	} else {
		out, err := exec.Command(dalfox, "scan", r.target+"/profile?user=admin", "--format", "json", "--silence", "--timeout", "15").CombinedOutput()
		if binaryFailed(err) {
			missing = append(missing, "dalfox: the binary could not be executed: "+err.Error())
			t.Logf("raw dalfox failed: %v", err)
		} else {
			findings = append(findings, parseRawDalfox(string(out))...)
			used = append(used, "dalfox")
		}
	}

	return findings, used, missing
}

// binaryFailed reports whether a scanner could not be executed at all.
//
// A scanner that runs and exits with a non zero code (dalfox does it when it
// finds something) is NOT a failure: only the errors that happen before the
// process starts (a binary quarantined by the antivirus, a missing runtime)
// mean that the scanner was not available.
func binaryFailed(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *exec.ExitError
	return !errors.As(err, &exitErr)
}

// parseRawNuclei reads the JSONL of nuclei the way a naive integration would:
// the name of the template, the URL it matched and its severity.
func parseRawNuclei(out string) []map[string]any {
	findings := []map[string]any{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			continue
		}
		info, _ := doc["info"].(map[string]any)
		if info == nil {
			continue
		}
		target := strOf(doc, "matched-at")
		if target == "" {
			target = strOf(doc, "host")
		}
		findings = append(findings, map[string]any{
			"title":       strOf(info, "name"),
			"target":      target,
			"severity":    strOf(info, "severity"),
			"source_tool": "nuclei",
		})
	}
	return findings
}

// parseRawDalfox reads the JSON of dalfox the way a naive integration would.
func parseRawDalfox(out string) []map[string]any {
	findings := []map[string]any{}
	index := strings.Index(out, `{"findings"`)
	if index < 0 {
		return findings
	}
	decoder := json.NewDecoder(strings.NewReader(out[index:]))
	var payload struct {
		Findings []struct {
			Type     string `json:"type"`
			Severity string `json:"severity"`
			Data     struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"findings"`
	}
	if err := decoder.Decode(&payload); err != nil {
		return findings
	}
	for _, f := range payload.Findings {
		target := f.Data.URL
		if target == "" {
			target = ""
		}
		findings = append(findings, map[string]any{
			"title":       "XSS: " + f.Type,
			"target":      target,
			"severity":    f.Severity,
			"source_tool": "dalfox",
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// The ground truth validation (the smoke test)
// ---------------------------------------------------------------------------

// validateGroundTruth checks the shape of the catalogue: the harness has to
// fail loudly when the ground truth is malformed, otherwise the recall it
// measures is meaningless.
func validateGroundTruth(items []GroundTruthItem) error {
	if len(items) == 0 {
		return fmt.Errorf("the ground truth is empty")
	}
	seen := map[string]bool{}
	severities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	for _, item := range items {
		if item.ID == "" {
			return fmt.Errorf("a ground truth item has no id")
		}
		if seen[item.ID] {
			return fmt.Errorf("duplicated ground truth id: %s", item.ID)
		}
		seen[item.ID] = true
		if item.Category == "" {
			return fmt.Errorf("%s: the category is empty", item.ID)
		}
		if item.Path == "" {
			return fmt.Errorf("%s: the path is empty", item.ID)
		}
		if item.Description == "" {
			return fmt.Errorf("%s: the description is empty", item.ID)
		}
		if !severities[item.Severity] {
			return fmt.Errorf("%s: unknown severity %q", item.ID, item.Severity)
		}
		if item.ExpectedTool == "" {
			return fmt.Errorf("%s: the expected tool is empty", item.ID)
		}
		switch item.Mode {
		case modeLight, modeFull, modeNone:
		default:
			return fmt.Errorf("%s: unknown mode %q", item.ID, item.Mode)
		}
		if item.ExpectedTool != toolUnsupported && !strings.HasPrefix(item.ExpectedTool, knownToolNamespaces) {
			return fmt.Errorf("%s: unknown tool %q", item.ID, item.ExpectedTool)
		}
		if item.ExpectedTool == toolUnsupported && item.Mode != modeNone {
			return fmt.Errorf("%s: an unsupported vector cannot be measurable", item.ID)
		}
		if item.Supported() && len(item.Matchers) == 0 {
			return fmt.Errorf("%s: a supported vector needs at least one match rule", item.ID)
		}
	}
	return nil
}

// TestBenchmarkGroundTruth is the smoke test of the benchmark: it always
// runs (it needs no binary and no network) and it checks that the catalogue
// is well formed and that the practice target really exposes every vector.
func TestBenchmarkGroundTruth(t *testing.T) {
	items := defaultGroundTruth()
	if err := validateGroundTruth(items); err != nil {
		t.Fatalf("the ground truth is malformed: %v", err)
	}

	light := 0
	full := 0
	unsupported := 0
	highSeverity := 0
	for _, item := range items {
		switch item.Mode {
		case modeLight:
			light++
		case modeFull:
			full++
		default:
			unsupported++
		}
		if item.Severity == "high" || item.Severity == "critical" {
			highSeverity++
		}
	}
	t.Logf("ground truth: %d vectors (%d light, %d full, %d unsupported), %d of high or critical severity",
		len(items), light, full, unsupported, highSeverity)
	if len(items) < 30 {
		t.Fatalf("the ground truth needs at least 30 vectors, got %d", len(items))
	}
	if highSeverity < 20 {
		t.Fatalf("the ground truth needs at least 20 vectors of high or critical severity, got %d", highSeverity)
	}

	srv := httptest.NewServer(practicetarget.Handler())
	defer srv.Close()
	probeGroundTruth(t, srv.URL, items)
}

// probeGroundTruth checks that the practice target really exposes every
// vector of the catalogue.
func probeGroundTruth(t *testing.T, base string, items []GroundTruthItem) {
	t.Helper()
	for _, item := range items {
		if item.Probe == "" {
			continue
		}
		want := item.ProbeStatus
		if want == 0 {
			want = 200
		}
		code := probeStatus(t, base+item.Probe)
		if code != want {
			t.Errorf("%s: the target answered %d for %s, want %d", item.ID, code, item.Probe, want)
		}
	}
}

// probeStatus returns the status code of a request to the practice target.
func probeStatus(t *testing.T, url string) int {
	t.Helper()
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// ---------------------------------------------------------------------------
// The benchmark
// ---------------------------------------------------------------------------

func TestWebBenchmark(t *testing.T) {
	if env.Get("ARGOS_E2E") != "1" {
		t.Skip("set ARGOS_E2E=1 to run the reproducible pentest benchmark")
	}
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}

	start := time.Now()
	light := env.Get("ARGOS_E2E_LIGHT") == "1"
	mode := modeFull
	if light {
		mode = modeLight
	}

	gt := defaultGroundTruth()
	if err := validateGroundTruth(gt); err != nil {
		t.Fatalf("the ground truth is malformed: %v", err)
	}

	srv := httptest.NewServer(practicetarget.Handler())
	defer srv.Close()
	base := srv.URL
	proxy, err := practicetarget.NewFrontProxy(base)
	if err != nil {
		t.Fatalf("cannot start the front proxy: %v", err)
	}
	defer proxy.Close()
	t.Logf("benchmark practice target: %s (front proxy: %s)", base, proxy.URL())

	work := t.TempDir()
	toolsDir := env.Get("ARGOS_E2E_TOOLS_DIR")
	if toolsDir == "" {
		toolsDir = filepath.Join(work, "tools")
	}
	homeDir := env.Get("ARGOS_E2E_HOME")
	if homeDir == "" {
		homeDir = filepath.Join(work, "home")
	}
	memDir := filepath.Join(work, "memory")
	for _, d := range []string{toolsDir, homeDir, filepath.Join(homeDir, "AppData", "Roaming"), filepath.Join(homeDir, "AppData", "Local"), memDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	client, stderr, err := startWebServer(t, work, toolsDir, homeDir, memDir)
	if err != nil {
		// The measurement could not happen. The job degrades to the smoke
		// test: the ground truth is checked and the target is probed, but
		// NO recall is measured and the gate does not apply.
		t.Logf("SMOKE MODE: the benchmark could not measure the coverage: %v", err)
		t.Logf("SMOKE MODE: no recall and no precision were measured; the regression gate does not apply to this run")
		if stderr != nil {
			t.Logf("--- web.exe stderr (tail) ---\n%s", tailStr(stderr.String(), 2000))
		}
		probeGroundTruth(t, base, gt)
		t.Skip("the benchmark degraded to the smoke test: the coverage was not measured")
	}
	defer func() {
		if stderr != nil {
			t.Logf("--- web.exe stderr (tail) ---\n%s", tailStr(stderr.String(), 2000))
		}
	}()

	calls := fullToolCalls(base, proxy.URL())
	if light {
		calls = lightToolCalls(base, proxy.URL())
	}

	argosFindings, executed, argosDuration := runArgosTools(t, client, calls)
	t.Logf("argos tools executed: %s", strings.Join(executed, " "))

	// The third party scanners, without Argos in the path.
	rawStarted := time.Now()
	rawFindings, rawUsed, rawMissing := rawToolRunner{toolsDir: toolsDir, target: base}.run(t)
	rawDuration := time.Since(rawStarted)
	rawReason := ""
	if len(rawUsed) == 0 {
		rawReason = "the third party binaries are not available: " + strings.Join(rawMissing, "; ")
	} else {
		rawReason = "run with " + strings.Join(rawUsed, ", ")
		if len(rawMissing) > 0 {
			rawReason += "; not available: " + strings.Join(rawMissing, "; ")
		}
	}
	t.Logf("raw tools: %d findings (%s)", len(rawFindings), rawReason)

	// The agent layer groups the findings that describe the same class of
	// problem before they reach the panel: that is the shape the first
	// runner measures.
	deduped := dedupeByTaxonomy(argosFindings)
	fullMetrics := computeMetrics(gt, deduped, findingHaystack)
	fullResult := RunnerResult{
		Runner:             runnerArgosFull,
		Description:        "the Argos tools with the canonical contract and the taxonomy dedup",
		Measured:           true,
		DurationSec:        argosDuration.Seconds(),
		TotalReported:      len(deduped),
		TruePositives:      fullMetrics.TruePositives,
		FalsePositives:     fullMetrics.FalsePositives,
		DetectedGT:         fullMetrics.DetectedGT,
		RecallPercent:      fullMetrics.RecallPercent,
		LightRecallPercent: fullMetrics.LightRecallPercent,
		PrecisionPercent:   fullMetrics.PrecisionPercent,
		FPRPercent:         fullMetrics.FPRPercent,
	}

	// The catalogue carries the outcome of the first runner: it is the one
	// the report describes.
	detected, matchedBy := matchGroundTruth(gt, deduped, findingHaystack)
	for i := range gt {
		gt[i].Detected = detected[i]
		gt[i].MatchedBy = matchedBy[i]
	}

	noAgentsFindings := make([]map[string]any, 0, len(argosFindings))
	for _, f := range argosFindings {
		noAgentsFindings = append(noAgentsFindings, stripContract(f))
	}
	noAgentsMetrics := computeMetrics(gt, noAgentsFindings, rawHaystack)
	noAgentsResult := RunnerResult{
		Runner:             runnerArgosNoAgents,
		Description:        "the same tools without the canonical contract: only the title and the URL survive",
		Measured:           true,
		DurationSec:        argosDuration.Seconds(),
		TotalReported:      len(noAgentsFindings),
		TruePositives:      noAgentsMetrics.TruePositives,
		FalsePositives:     noAgentsMetrics.FalsePositives,
		DetectedGT:         noAgentsMetrics.DetectedGT,
		RecallPercent:      noAgentsMetrics.RecallPercent,
		LightRecallPercent: noAgentsMetrics.LightRecallPercent,
		PrecisionPercent:   noAgentsMetrics.PrecisionPercent,
		FPRPercent:         noAgentsMetrics.FPRPercent,
	}

	rawMetrics := computeMetrics(gt, rawFindings, rawHaystack)
	rawResult := RunnerResult{
		Runner:             runnerRawTools,
		Description:        "the third party scanners (nuclei, dalfox) without Argos in the path",
		Measured:           len(rawUsed) > 0,
		Reason:             rawReason,
		DurationSec:        rawDuration.Seconds(),
		TotalReported:      len(rawFindings),
		TruePositives:      rawMetrics.TruePositives,
		FalsePositives:     rawMetrics.FalsePositives,
		DetectedGT:         rawMetrics.DetectedGT,
		RecallPercent:      rawMetrics.RecallPercent,
		LightRecallPercent: rawMetrics.LightRecallPercent,
		PrecisionPercent:   rawMetrics.PrecisionPercent,
		FPRPercent:         rawMetrics.FPRPercent,
	}

	lightTotal := 0
	unsupported := 0
	for _, item := range gt {
		switch item.Mode {
		case modeLight:
			lightTotal++
		case modeNone:
			unsupported++
		}
	}

	report := BenchmarkReport{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Target:      base,
		Mode:        mode,
		DurationSec: time.Since(start).Seconds(),
		TotalGT:     len(gt),
		LightGT:     lightTotal,
		Unsupported: unsupported,
		Runners:     []RunnerResult{fullResult, noAgentsResult, rawResult},
		Items:       gt,
	}

	report.Gate = checkBaseline(t, report, mode)

	writeReport(t, report)

	t.Logf("BENCHMARK COMPLETADO (%s): argos_full recall=%.1f%% (light %.1f%%) precision=%.1f%% fpr=%.1f%%",
		mode, fullResult.RecallPercent, fullResult.LightRecallPercent, fullResult.PrecisionPercent, fullResult.FPRPercent)
	t.Logf("argos_no_agents: recall=%.1f%% precision=%.1f%% | raw_tools: recall=%.1f%% precision=%.1f%%",
		noAgentsResult.RecallPercent, noAgentsResult.PrecisionPercent, rawResult.RecallPercent, rawResult.PrecisionPercent)

	if fullResult.DetectedGT == 0 {
		t.Fatalf("the benchmark did not detect a single vulnerability of the ground truth")
	}
}

// startWebServer builds and launches the argos-web MCP server.
//
// It returns an error instead of failing the test: when the server cannot
// start the benchmark degrades to the smoke test.
func startWebServer(t *testing.T, work, toolsDir, homeDir, memDir string) (*mcpClient, *bytes.Buffer, error) {
	t.Helper()
	exe := buildWebExe(t, work)
	cmd := exec.Command(exe, "--mcp", "--memory-dir", memDir)
	cmd.Env = append(os.Environ(),
		"ARGOS_TOOLS_DIR="+toolsDir,
		"HOME="+homeDir,
		"USERPROFILE="+homeDir,
		"APPDATA="+filepath.Join(homeDir, "AppData", "Roaming"),
		"LOCALAPPDATA="+filepath.Join(homeDir, "AppData", "Local"),
		"OPENCODE_CONFIG_DIR=",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, &stderr, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, &stderr, err
	}
	if err := cmd.Start(); err != nil {
		return nil, &stderr, fmt.Errorf("cannot start web.exe: %w", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	client := &mcpClient{stdin: stdin, lines: make(chan string, 16)}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
		for sc.Scan() {
			client.lines <- sc.Text()
		}
		close(client.lines)
	}()

	if _, err := client.call(1, "initialize", map[string]any{"protocolVersion": "2024-11-05"}, 30*time.Second); err != nil {
		return nil, &stderr, fmt.Errorf("initialize failed: %w", err)
	}
	return client, &stderr, nil
}

// checkBaseline compares the benchmark against the versioned baseline.
//
// When the baseline cannot be read the gate is not enforced: a benchmark
// without a reference is a report, not a gate.
func checkBaseline(t *testing.T, report BenchmarkReport, mode string) GateResult {
	t.Helper()
	gate := GateResult{Checked: false, Passed: true}
	baseline, err := loadBaseline()
	if err != nil {
		gate.Reason = "no baseline to compare against: " + err.Error()
		t.Logf("GATE: %s", gate.Reason)
		return gate
	}
	gate.BaselineRecall = baseline.RecallPercent
	gate.BaselinePrec = baseline.PrecisionPercent

	if baseline.Mode != "" && baseline.Mode != mode {
		gate.Reason = fmt.Sprintf("the baseline was recorded in %s mode and this run is %s: the gate does not apply", baseline.Mode, mode)
		t.Logf("GATE: %s", gate.Reason)
		return gate
	}

	var measured *RunnerResult
	for i := range report.Runners {
		if report.Runners[i].Runner == baseline.Runner {
			measured = &report.Runners[i]
		}
	}
	if measured == nil {
		gate.Reason = "the baseline names the runner " + baseline.Runner + ", which the report does not have"
		return gate
	}
	if !measured.Measured {
		gate.Reason = "the runner was not measured: " + measured.Reason
		t.Logf("GATE: %s (no recall was measured, the gate does not apply)", gate.Reason)
		return gate
	}

	gate.Checked = true
	gate.Passed = true
	recall := measured.LightRecallPercent
	precision := measured.PrecisionPercent

	if recall < baseline.RecallPercent-baseline.RecallTolerance {
		gate.Passed = false
		gate.Reason = fmt.Sprintf("the light recall fell to %.1f%%, the baseline demands %.1f%% (tolerance %.1f%%)",
			recall, baseline.RecallPercent, baseline.RecallTolerance)
	}
	if measured.RecallPercent < baseline.OverallRecall-2 {
		gate.Passed = false
		gate.Reason = fmt.Sprintf("the overall recall fell to %.1f%%, the baseline demands %.1f%%",
			measured.RecallPercent, baseline.OverallRecall)
	}
	if precision < baseline.PrecisionPercent-baseline.PrecisionTolerance {
		gate.Passed = false
		gate.Reason = fmt.Sprintf("the precision fell to %.1f%%, the baseline demands %.1f%% (tolerance %.1f%%)",
			precision, baseline.PrecisionPercent, baseline.PrecisionTolerance)
	}
	if !gate.Passed {
		t.Errorf("BENCHMARK GATE: %s", gate.Reason)
		return gate
	}
	t.Logf("GATE: ok (recall %.1f%% >= %.1f%%, precision %.1f%% >= %.1f%%)",
		recall, baseline.RecallPercent, precision, baseline.PrecisionPercent)
	return gate
}

// loadBaseline reads the versioned baseline of the gate.
func loadBaseline() (*Baseline, error) {
	raw, err := os.ReadFile(baselineFileName)
	if err != nil {
		return nil, err
	}
	var baseline Baseline
	if err := json.Unmarshal(raw, &baseline); err != nil {
		return nil, err
	}
	if baseline.RecallTolerance <= 0 {
		baseline.RecallTolerance = 5
	}
	if baseline.PrecisionTolerance <= 0 {
		baseline.PrecisionTolerance = 2
	}
	return &baseline, nil
}

// writeReport writes the JSON and the Markdown artifacts of the benchmark.
func writeReport(t *testing.T, report BenchmarkReport) {
	t.Helper()
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("cannot encode the report: %v", err)
	}
	if err := os.WriteFile(reportFileName, raw, 0o644); err != nil {
		t.Fatalf("cannot write %s: %v", reportFileName, err)
	}
	if err := os.WriteFile(reportMarkdownName, []byte(renderReportMarkdown(report)), 0o644); err != nil {
		t.Fatalf("cannot write %s: %v", reportMarkdownName, err)
	}
	t.Logf("report written: %s, %s", reportFileName, reportMarkdownName)
}

// renderReportMarkdown renders the human readable report.
func renderReportMarkdown(report BenchmarkReport) string {
	var sb strings.Builder
	sb.WriteString("# Argos Security Benchmark Report\n\n")
	sb.WriteString(fmt.Sprintf("- **Fecha:** %s\n", report.Timestamp))
	sb.WriteString(fmt.Sprintf("- **Modo:** %s\n", report.Mode))
	sb.WriteString(fmt.Sprintf("- **Duración:** %.2fs\n", report.DurationSec))
	sb.WriteString(fmt.Sprintf("- **Ground truth:** %d vectores (%d medibles en modo light, %d sin tool que los detecte)\n\n",
		report.TotalGT, report.LightGT, report.Unsupported))

	sb.WriteString("## Runners\n\n")
	sb.WriteString("| Runner | Recall | Recall (light) | Precision | FPR | Hallazgos | TP | FP |\n")
	sb.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, r := range report.Runners {
		if !r.Measured {
			sb.WriteString(fmt.Sprintf("| `%s` | n/d | n/d | n/d | n/d | %d | %d | %d |\n",
				r.Runner, r.TotalReported, r.TruePositives, r.FalsePositives))
			continue
		}
		sb.WriteString(fmt.Sprintf("| `%s` | %.1f%% | %.1f%% | %.1f%% | %.1f%% | %d | %d | %d |\n",
			r.Runner, r.RecallPercent, r.LightRecallPercent, r.PrecisionPercent, r.FPRPercent,
			r.TotalReported, r.TruePositives, r.FalsePositives))
	}
	sb.WriteString("\n")
	for _, r := range report.Runners {
		sb.WriteString(fmt.Sprintf("- `%s`: %s", r.Runner, r.Description))
		if r.Reason != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", r.Reason))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("\n## Ground truth\n\n")
	sb.WriteString("| ID | Categoría | Ruta | Descripción | Severidad | Tool | Modo | Detectado |\n")
	sb.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, it := range report.Items {
		det := "❌ No"
		if it.Detected {
			det = "✅ Sí (" + it.MatchedBy + ")"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			it.ID, it.Category, it.Path, it.Description, it.Severity, it.ExpectedTool, it.Mode, det))
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// The arithmetic of the metrics
// ---------------------------------------------------------------------------

// TestBenchmarkMetricsArithmetic checks the arithmetic of the benchmark over
// a synthetic set with known true positives, false positives and false
// negatives.
func TestBenchmarkMetricsArithmetic(t *testing.T) {
	items := []GroundTruthItem{
		{ID: "T-01", Mode: modeLight, Matchers: []MatchRule{{Any: []string{"alpha"}}}},
		{ID: "T-02", Mode: modeLight, Matchers: []MatchRule{{Any: []string{"bravo"}}}},
		{ID: "T-03", Mode: modeLight, Matchers: []MatchRule{{Any: []string{"charlie"}}}},
		{ID: "T-04", Mode: modeLight, Matchers: []MatchRule{{Any: []string{"delta"}}}},
		{ID: "T-05", Mode: modeFull, Matchers: []MatchRule{{Any: []string{"echo"}}}},
		{ID: "T-06", Mode: modeFull, Matchers: []MatchRule{{Any: []string{"foxtrot"}}}},
		{ID: "T-07", Mode: modeFull, Matchers: []MatchRule{{Any: []string{"golf"}}}},
		{ID: "T-08", Mode: modeFull, Matchers: []MatchRule{{Any: []string{"hotel"}}}},
		{ID: "T-09", Mode: modeFull, Matchers: []MatchRule{{Any: []string{"india"}}}},
		{ID: "T-10", Mode: modeFull, Matchers: []MatchRule{{Any: []string{"juliet"}}}},
	}

	findings := []map[string]any{
		// Eight true positives: they cover T-01..T-08.
		{"title": "alpha detected", "target": "http://t/1", "severity": "high"},
		{"title": "bravo detected", "target": "http://t/2", "severity": "high"},
		{"title": "charlie detected", "target": "http://t/3", "severity": "high"},
		{"title": "delta detected", "target": "http://t/4", "severity": "high"},
		{"title": "echo detected", "target": "http://t/5", "severity": "high"},
		{"title": "foxtrot detected", "target": "http://t/6", "severity": "high"},
		{"title": "golf detected", "target": "http://t/7", "severity": "high"},
		{"title": "hotel detected", "target": "http://t/8", "severity": "high"},
		// Four false positives: they claim a vulnerability and match nothing.
		{"title": "SQL injection in the login form", "target": "http://t/99", "severity": "high"},
		{"title": "Path traversal in the download endpoint", "target": "http://t/98", "severity": "medium"},
		{"title": "Exposed configuration file", "target": "http://t/97", "severity": "high"},
		{"title": "Command injection in the ping endpoint", "target": "http://t/96", "severity": "critical"},
		// Two pieces of recon noise: they claim nothing, so they do not
		// count against the precision.
		{"title": "Technology detected: nginx", "target": "http://t/", "severity": "info"},
		{"title": "HTTP/2 supported", "target": "http://t/", "severity": "info"},
	}

	m := computeMetrics(items, findings, findingHaystack)

	if m.Reported != len(findings) {
		t.Fatalf("reported=%d, want %d", m.Reported, len(findings))
	}
	if m.TruePositives != 8 {
		t.Fatalf("true positives=%d, want 8", m.TruePositives)
	}
	if m.FalsePositives != 4 {
		t.Fatalf("false positives=%d, want 4", m.FalsePositives)
	}
	if m.DetectedGT != 8 {
		t.Fatalf("detected ground truth=%d, want 8", m.DetectedGT)
	}
	if m.LightTotal != 4 || m.LightDetected != 4 {
		t.Fatalf("light coverage=%d/%d, want 4/4", m.LightDetected, m.LightTotal)
	}
	// Recall: 8 of the 10 vectors of the ground truth.
	if !almost(m.RecallPercent, 80) {
		t.Fatalf("recall=%.4f, want 80", m.RecallPercent)
	}
	// Recall of the light subset: 4 of 4.
	if !almost(m.LightRecallPercent, 100) {
		t.Fatalf("light recall=%.4f, want 100", m.LightRecallPercent)
	}
	// Precision: 8 of the 12 findings that claim a vulnerability.
	if !almost(m.PrecisionPercent, 8.0/12.0*100) {
		t.Fatalf("precision=%.4f, want %.4f", m.PrecisionPercent, 8.0/12.0*100)
	}
	// FPR: 4 of the 12 findings that claim a vulnerability.
	if !almost(m.FPRPercent, 4.0/12.0*100) {
		t.Fatalf("fpr=%.4f, want %.4f", m.FPRPercent, 4.0/12.0*100)
	}

	// An empty run does not divide by zero.
	empty := computeMetrics(items, nil, findingHaystack)
	if empty.RecallPercent != 0 || empty.PrecisionPercent != 0 || empty.FPRPercent != 0 {
		t.Fatalf("an empty run must report zeros, got %+v", empty)
	}
}

// almost compares two floats with the tolerance of the harness.
func almost(got, want float64) bool {
	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	return diff < 0.0001
}

// truncateForLog shortens the output of a tool for the log.
func truncateForLog(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 300 {
		return value[:300] + "..."
	}
	return value
}
