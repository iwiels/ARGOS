package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

func RegisterSqli(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.sqli",
			Description: "SQL injection detection and deterministic confirmation: nuclei sqli templates, native differential detector (boolean, error based and time based) or sqlmap confirmation.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":       {Type: "string", Description: "Target URL with parameters, e.g. https://example.com/item?id=1"},
					"mode":         {Type: "string", Description: "detect (default): nuclei sqli templates + native differential detector; confirm: non-destructive sqlmap confirmation; impact: sqlmap plus DBMS banner and current database"},
					"method":       {Type: "string", Description: "HTTP method of the request under test (default GET, POST when a body is given)"},
					"body":         {Type: "string", Description: "Request body to probe: form encoded (a=1&b=2) or JSON ({\"a\":\"1\"}). It enables the body and json surfaces."},
					"content_type": {Type: "string", Description: "Content type of the body: application/x-www-form-urlencoded (default) or application/json (auto detected from the body)"},
					"surfaces":     {Type: "array", Items: &mcp.Items{Type: "string"}, Description: "Surfaces to probe: query, body, json, header (default: query and header)"},
					"native":       {Type: "boolean", Description: "Also run the built-in differential detector (default true)"},
					"confirm":      {Type: "boolean", Description: "Run non-destructive deterministic confirmation using sqlmap (default false, same as mode=confirm)"},
					"impact":       {Type: "boolean", Description: "Extract DBMS profile and banner without dumping data (default false, same as mode=impact)"},
					"timeout":      {Type: "integer", Description: "Scan timeout in seconds (default 180, max 300)"},
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
				Target      string   `json:"target"`
				Mode        string   `json:"mode"`
				Method      string   `json:"method"`
				Body        string   `json:"body"`
				ContentType string   `json:"content_type"`
				Surfaces    []string `json:"surfaces"`
				Native      *bool    `json:"native"`
				Confirm     bool     `json:"confirm"`
				Impact      bool     `json:"impact"`
				Timeout     int      `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			mode, e := resolveSqliMode(input.Mode, input.Confirm, input.Impact)
			if e != nil {
				return nil, e
			}
			timeout := clampTimeout(input.Timeout, 180)

			if mode == sqliModeConfirm || mode == sqliModeImpact {
				return runSqlmapConfirmation(toolContext(ctx), env, target, mode, timeout)
			}

			native := input.Native == nil || *input.Native

			bin, installed, e := env.Binary(toolContext(ctx), "nuclei")
			if e != nil {
				return nil, e
			}
			r := run(toolContext(ctx), bin, runOptions{
				Args:    []string{"-u", target, "-tags", "sqli", "-jsonl", "-silent", "-no-color"},
				Timeout: time.Duration(timeout) * time.Second,
			})
			fs := parseNuclei(r.Output, target, "web.sqli")

			if native && canRunNativeSqli(r) {
				// The native detector shares the scan budget with nuclei, but it
				// never runs out of time in the middle of a slot: the remaining
				// budget is at least one minute.
				budget := time.Duration(timeout)*time.Second - r.Duration
				if budget < time.Minute {
					budget = time.Minute
				}
				if budget > 2*time.Minute {
					budget = 2 * time.Minute
				}
				nf := detectSQLiSpec(env.Client(), sqliSpec{
					URL:         target,
					Method:      input.Method,
					Body:        input.Body,
					ContentType: input.ContentType,
					Surfaces:    input.Surfaces,
				}, budget)
				fs = append(fs, nf...)
			}
			fs, truncated := capFindings(fs)

			res := baseResult("web.sqli", target, r)
			res["mode"] = mode
			res["findings"] = findingsToMaps(fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d SQLi indicators", len(fs))
			if installed {
				res["installed"] = "nuclei " + env.Spec("nuclei").Version
			}
			return res, nil
		},
	)
}

func canRunNativeSqli(result *runResult) bool {
	return result != nil && result.Sandboxed && result.ExitCode == 0 && !result.TimedOut
}

// Canonical modes of the tool.
const (
	sqliModeDetect  = "detect"
	sqliModeConfirm = "confirm"
	sqliModeImpact  = "impact"
)

// resolveSqliMode maps the mode argument (and the legacy confirm/impact
// booleans) onto the canonical mode set.
func resolveSqliMode(raw string, confirm, impact bool) (string, *mcp.ErrorObj) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	if mode == "" {
		switch {
		case impact:
			mode = sqliModeImpact
		case confirm:
			mode = sqliModeConfirm
		default:
			mode = sqliModeDetect
		}
	}
	switch mode {
	case sqliModeDetect, sqliModeConfirm, sqliModeImpact:
		return mode, nil
	}
	return "", invalidParams(fmt.Errorf("mode must be one of %s, %s or %s", sqliModeDetect, sqliModeConfirm, sqliModeImpact))
}

// runSqlmapConfirmation runs the deterministic sqlmap confirmation. The
// confirmation is read only: the banner and the current database are the
// deepest information the tool extracts.
func runSqlmapConfirmation(ctx context.Context, env *Env, target, mode string, timeout int) (interface{}, *mcp.ErrorObj) {
	py, err := DetectRuntime("python")
	if err != nil {
		return nil, &mcp.ErrorObj{Code: -32603, Message: "sqlmap confirmation requires Python 3: " + err.Error()}
	}
	bin, installed, e := env.Binary(ctx, "sqlmap")
	if e != nil {
		return nil, e
	}
	tmpDir, err := os.MkdirTemp("", "sqlmap-*")
	if err == nil {
		defer os.RemoveAll(tmpDir)
	}
	args := []string{bin, "-u", target, "--batch", "--smart", "--level=1", "--risk=1", "--timeout=15", "--retries=1", "--threads=1"}
	if tmpDir != "" {
		args = append(args, "--output-dir="+tmpDir)
	}
	if mode == sqliModeImpact {
		args = append(args, "--banner", "--current-db")
	}
	r := run(ctx, py, runOptions{
		Args:    args,
		Timeout: time.Duration(timeout) * time.Second,
	})
	combinedOut := r.Output
	if r.Stderr != "" {
		combinedOut += "\n" + r.Stderr
	}
	f, confirmed := parseSqlmapOutput(combinedOut, target)
	var fs []Finding
	if confirmed {
		fs = append(fs, f)
	}
	fs, truncated := capFindings(fs)
	res := baseResult("web.sqli", target, r)
	res["mode"] = mode
	res["findings"] = findingsToMaps(fs)
	res["truncated"] = truncated
	res["confirmed"] = confirmed
	if confirmed {
		res["summary"] = "1 SQLi confirmada (sqlmap)"
	} else {
		res["summary"] = "0 SQLi confirmadas (sqlmap)"
	}
	if installed {
		res["installed"] = "sqlmap " + env.Spec("sqlmap").Version
	}
	return res, nil
}

// Surfaces where a parameter can live. The surface is part of the finding
// vector, so the auditor knows where the payload has to be replayed.
const (
	surfaceQuery  = "query"
	surfaceBody   = "body"
	surfaceJSON   = "json"
	surfaceHeader = "header"
)

const (
	// sqliUserAgent is the benign client identity of every probe.
	sqliUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	// sqliBaselineValue is the canonical benign value of every slot: the
	// boolean payloads are built around the value 1, so the baseline has to
	// be the same value for the comparison to mean something.
	sqliBaselineValue = "1"

	// sqliProbeTimeout bounds a single probe. The time based payloads sleep
	// for three seconds, so the budget leaves room for the round trip.
	sqliProbeTimeout = 10 * time.Second

	// sqliTimeThreshold is the latency delta over the baseline median that
	// turns a time based probe into a confirmation.
	sqliTimeThreshold = 2 * time.Second

	// sqliSimilarityInfluence is the similarity under which the value of the
	// parameter is considered to drive the response. The 0.85 margin absorbs
	// the dynamic parts of a page (a rotating token, a timestamp) that survive
	// the volatile token masking.
	sqliSimilarityInfluence = 0.85

	// sqliSimilarityDifferential is the similarity under which the true and
	// the false payload are considered to be two different answers.
	sqliSimilarityDifferential = 0.95

	// sqliSimilarityBaseline is the similarity over which an answer is
	// considered to be the normal answer of the endpoint and not an error
	// page.
	sqliSimilarityBaseline = 0.9

	// maxSqliBodyBytes caps the response body kept in memory per probe.
	maxSqliBodyBytes = 1 << 20
)

// sqliBooleanTrue and sqliBooleanFalse are the boolean pair: the first one is
// a tautology, the second one a contradiction.
const (
	sqliBooleanTrue  = "1' AND '1'='1"
	sqliBooleanFalse = "1' AND '1'='2"
)

// sqliTimePayloads are the time based payloads, one per database family. The
// first one that moves the latency is the one reported in the evidence.
var sqliTimePayloads = []string{
	"1' AND SLEEP(3)--",
	"1' AND WAITFOR DELAY '0:0:3'--",
	"1' AND pg_sleep(3)--",
}

// sqliHeaderSlots are the request headers worth probing: they are the ones an
// application usually forwards to a backend query (logging, geo lookup,
// session, language).
var sqliHeaderSlots = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
	"Accept-Language",
	"Cookie",
}

// sqlErrorMarkers are the fingerprints of a database error page.
//
// The generic "sql" substring is deliberately absent: it matches "MySQL",
// "PostgreSQL" or any "SQL" in a footer or a navigation link, which is the
// classic false positive of a naive detector.
var sqlErrorMarkers = []string{
	"sqlstate",
	"mysql_fetch",
	"mysql_num_rows",
	"mysqli_",
	"ora-",
	"pg_query",
	"postgresql",
	"syntax error at or near",
	"unclosed quotation mark",
	"warning: mysql_",
	"sqlite3",
	"odbc driver",
	"supplied argument is not a valid",
	"microsoft ole db provider",
	"you have an error in your sql syntax",
}

// sqliMarkerCompacts maps the comparable spelling of every marker (the one
// without whitespace) to its readable spelling, which is the one reported in
// the evidence.
var sqliMarkerCompacts = func() map[string]string {
	out := map[string]string{}
	for _, marker := range sqlErrorMarkers {
		out[strings.Join(strings.Fields(marker), "")] = marker
	}
	return out
}()

// sqliSpec describes the request under test.
type sqliSpec struct {
	URL         string
	Method      string
	Body        string
	ContentType string
	Surfaces    []string
}

// sqliSlot is one parameter location inside the request under test.
type sqliSlot struct {
	surface string
	name    string
}

// sqliTemplate is the request shape under test: a factory of fresh requests
// plus the way to write a payload into one of its parameter slots.
type sqliTemplate struct {
	newRequest func() (*http.Request, error)
	write      func(req *http.Request, slot sqliSlot, value string) error
	slots      []sqliSlot
	method     string
	target     string
}


// detectSQLiSpec runs the native differential detector over every parameter
// slot of the request described by spec.
func detectSQLiSpec(client *http.Client, spec sqliSpec, budget time.Duration) []Finding {
	tpl, err := newSqliTemplate(spec)
	if err != nil || len(tpl.slots) == 0 {
		return nil
	}
	deadline := time.Now().Add(budget)
	var fs []Finding
	for _, slot := range tpl.slots {
		if time.Now().After(deadline) {
			break
		}
		f, ok := detectSQLiSlot(context.Background(), client, tpl, slot, deadline)
		if ok {
			fs = append(fs, f)
		}
	}
	return fs
}

// newSqliTemplate builds the request under test and the list of slots to
// probe.
func newSqliTemplate(spec sqliSpec) (*sqliTemplate, error) {
	u, err := url.Parse(spec.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	method, body, contentType := sqliRequestShape(spec)
	formValues, jsonDoc := sqliParseBody(body, contentType)
	surfaces, explicit := sqliSurfaceSet(spec.Surfaces, body, contentType)

	tpl := &sqliTemplate{method: method, target: u.String()}

	if surfaces[surfaceQuery] {
		for _, name := range sortedMapKeys(u.Query()) {
			tpl.slots = append(tpl.slots, sqliSlot{surface: surfaceQuery, name: name})
		}
	}
	if surfaces[surfaceBody] {
		for _, name := range sortedMapKeys(formValues) {
			tpl.slots = append(tpl.slots, sqliSlot{surface: surfaceBody, name: name})
		}
	}
	if surfaces[surfaceJSON] {
		for _, name := range sortedMapKeys(jsonDoc) {
			tpl.slots = append(tpl.slots, sqliSlot{surface: surfaceJSON, name: name})
		}
	}
	// The headers are an extra surface of a request that already carries
	// parameters: a static page has nothing to inject.
	if surfaces[surfaceHeader] && (explicit || len(tpl.slots) > 0) {
		for _, name := range sqliHeaderSlots {
			tpl.slots = append(tpl.slots, sqliSlot{surface: surfaceHeader, name: name})
		}
	}
	if len(tpl.slots) == 0 {
		return tpl, nil
	}

	headerDefaults := sqliHeaderDefaults(tpl.target)
	tpl.newRequest = func() (*http.Request, error) {
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, tpl.target, reader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", sqliUserAgent)
		if body != "" {
			req.Header.Set("Content-Type", contentType)
			req.ContentLength = int64(len(body))
		}
		// Every probed header carries a benign value in the baseline, so the
		// comparison isolates the payload and not the presence of the header.
		for _, slot := range tpl.slots {
			if slot.surface != surfaceHeader {
				continue
			}
			if def, ok := headerDefaults[slot.name]; ok {
				req.Header.Set(slot.name, def)
			}
		}
		return req, nil
	}
	tpl.write = func(req *http.Request, slot sqliSlot, value string) error {
		switch slot.surface {
		case surfaceQuery:
			q := req.URL.Query()
			q.Set(slot.name, value)
			req.URL.RawQuery = q.Encode()
			return nil
		case surfaceBody:
			values := url.Values{}
			for k, v := range formValues {
				values[k] = append([]string(nil), v...)
			}
			values.Set(slot.name, value)
			return setSqliBody(req, values.Encode(), "application/x-www-form-urlencoded")
		case surfaceJSON:
			doc := map[string]any{}
			for k, v := range jsonDoc {
				doc[k] = v
			}
			doc[slot.name] = value
			raw, err := json.Marshal(doc)
			if err != nil {
				return fmt.Errorf("cannot encode the JSON body: %w", err)
			}
			return setSqliBody(req, string(raw), "application/json")
		case surfaceHeader:
			req.Header.Set(slot.name, value)
			return nil
		}
		return fmt.Errorf("unknown surface %q", slot.surface)
	}
	return tpl, nil
}

// sqliRequestShape resolves the method, the body and the content type of the
// request under test.
func sqliRequestShape(spec sqliSpec) (method, body, contentType string) {
	method = strings.ToUpper(strings.TrimSpace(spec.Method))
	body = spec.Body
	contentType = strings.TrimSpace(spec.ContentType)
	if contentType == "" {
		contentType = sqliDetectContentType(body)
	}
	if method == "" {
		if body != "" {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}
	return method, body, contentType
}

// sqliDetectContentType guesses the content type of a body.
func sqliDetectContentType(body string) string {
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "application/json"
	}
	return "application/x-www-form-urlencoded"
}

// sqliParseBody extracts the parameter names of a body: the form values of a
// form encoded body, the top level keys of a JSON body.
func sqliParseBody(body, contentType string) (url.Values, map[string]any) {
	if body == "" {
		return nil, nil
	}
	if strings.Contains(strings.ToLower(contentType), "json") {
		var doc map[string]any
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			return nil, nil
		}
		return nil, doc
	}
	values, err := url.ParseQuery(body)
	if err != nil {
		return nil, nil
	}
	return values, nil
}

// sqliSurfaceSet resolves the surfaces to probe. The default covers the query
// string and the common headers; the body surfaces only apply when the
// request carries a body. The second return value tells whether the caller
// asked for the surfaces explicitly.
func sqliSurfaceSet(requested []string, body, contentType string) (map[string]bool, bool) {
	out := map[string]bool{}
	if len(requested) == 0 {
		out[surfaceQuery] = true
		out[surfaceHeader] = true
		if body != "" {
			if strings.Contains(strings.ToLower(contentType), "json") {
				out[surfaceJSON] = true
			} else {
				out[surfaceBody] = true
			}
		}
		return out, false
	}
	for _, raw := range requested {
		surface := strings.ToLower(strings.TrimSpace(raw))
		switch surface {
		case surfaceQuery, surfaceBody, surfaceJSON, surfaceHeader:
			out[surface] = true
		}
	}
	// "body" means the request body, whatever its encoding.
	if out[surfaceBody] && body != "" && strings.Contains(strings.ToLower(contentType), "json") {
		out[surfaceJSON] = true
	}
	return out, true
}

// sqliHeaderDefaults returns the benign value every probed header carries in
// the baseline request.
func sqliHeaderDefaults(target string) map[string]string {
	referer := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		referer = u.Scheme + "://" + u.Host + "/"
	}
	return map[string]string{
		"User-Agent":      sqliUserAgent,
		"Referer":         referer,
		"X-Forwarded-For": "127.0.0.1",
		"Accept-Language": "en-US,en;q=0.9",
		"Cookie":          "sid=argos",
	}
}

// setSqliBody replaces the body of a request.
func setSqliBody(req *http.Request, body, contentType string) error {
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", contentType)
	return nil
}

// detectSQLiSlot runs the differential analysis over one parameter slot.
//
// The analysis has three independent legs:
//
//	reflection  - a random nonce travels with the payload; locating it in the
//	              response proves that the value is echoed back and makes the
//	              comparison against the baseline exact
//	boolean     - the tautology and the contradiction must produce two
//	              different answers, and one of them must look like the normal
//	              answer of the endpoint
//	time        - the payload must add more than two seconds to the median
//	              latency of the baseline
func detectSQLiSlot(ctx context.Context, client *http.Client, tpl *sqliTemplate, slot sqliSlot, deadline time.Time) (Finding, bool) {
	base0, ok := sqliProbe(ctx, client, tpl, slot, sqliBaselineValue, deadline)
	if !ok {
		return Finding{}, false
	}
	base1, ok := sqliProbe(ctx, client, tpl, slot, sqliBaselineValue, deadline)
	if !ok {
		return Finding{}, false
	}

	// The second baseline sample tells which tokens of the page are volatile
	// (a rotating CSRF token, a request id, a timestamp). They are masked
	// before any comparison, so a dynamic page does not hide the differential
	// and does not fake one either.
	volatile := volatileTokenKeys(sqliTokens(base0.body), sqliTokens(base1.body))
	baseMarkers := sqliMarkerSet(base0.body, base1.body)

	nonce, err := sqliNonce()
	if err != nil {
		return Finding{}, false
	}
	reflected, ok := sqliProbe(ctx, client, tpl, slot, sqliBaselineValue+nonce, deadline)
	if !ok {
		return Finding{}, false
	}
	offset := strings.Index(reflected.body, nonce)

	normBase := sqliNormalizeBody(base0.body, "", "", volatile)
	normReflect := sqliNormalizeBody(reflected.body, "", nonce, volatile)
	simInfluence := similarity(normReflect, normBase)

	trueRes, okTrue := sqliProbe(ctx, client, tpl, slot, sqliBooleanTrue, deadline)
	if !okTrue {
		return Finding{}, false
	}
	falseRes, okFalse := sqliProbe(ctx, client, tpl, slot, sqliBooleanFalse, deadline)
	if !okFalse {
		return Finding{}, false
	}

	normTrue := sqliNormalizeBody(trueRes.body, sqliBooleanTrue, "", volatile)
	normFalse := sqliNormalizeBody(falseRes.body, sqliBooleanFalse, "", volatile)
	simTrueFalse := similarity(normTrue, normFalse)
	simTrueBase := similarity(normTrue, normBase)
	simFalseBase := similarity(normFalse, normBase)
	booleanDiff := simTrueFalse < sqliSimilarityDifferential &&
		(simTrueBase > sqliSimilarityBaseline || simFalseBase > sqliSimilarityBaseline)

	markers := sqliNewMarkers([]string{trueRes.body, falseRes.body}, baseMarkers)
	serverError := (trueRes.status >= 500 || falseRes.status >= 500) && base0.status < 500

	// The influence of the value only counts when the parameter is not echoed
	// back: a reflected value changes the page by definition, and a search
	// box that filters by the value would be reported on every healthy site.
	influence := offset < 0 && reflected.status == base0.status && simInfluence < sqliSimilarityInfluence

	payloads := []string{sqliBooleanTrue, sqliBooleanFalse}
	timeDelta := time.Duration(0)
	timeConfirmed := false
	timePayload := ""
	var timeRes *probeResult
	if !(len(markers) >= 2 || (len(markers) >= 1 && booleanDiff)) {
		// A third baseline sample completes the median that the latency
		// delta is measured against.
		base2, ok := sqliProbe(ctx, client, tpl, slot, sqliBaselineValue, deadline)
		if ok {
			median := medianDuration(base0.elapsed, base1.elapsed, base2.elapsed)
			for _, payload := range sqliTimePayloads {
				res, ok := sqliProbe(ctx, client, tpl, slot, payload, deadline)
				payloads = append(payloads, payload)
				if !ok {
					continue
				}
				if delta := res.elapsed - median; delta > timeDelta {
					timeDelta = delta
					if delta > sqliTimeThreshold {
						timeConfirmed = true
						timePayload = payload
						timeRes = &res
						break
					}
				}
			}
		}
	}

	confidence := sqliConfidence(booleanDiff, len(markers), timeConfirmed, serverError, influence)
	if confidence == "" {
		return Finding{}, false
	}

	evidence := map[string]any{
		"surface":          slot.surface,
		"parameter":        slot.name,
		"method":           tpl.method,
		"baseline_status":  base0.status,
		"status_true":      trueRes.status,
		"status_false":     falseRes.status,
		"reflected_offset": offset,
		// similarity_true and similarity_false compare each payload answer
		// with the baseline; similarity_baseline compares the answer of the
		// nonce probe with the baseline (how much the value drives the
		// response) and similarity_true_false compares the two answers.
		"similarity_true":       round3(simTrueBase),
		"similarity_false":      round3(simFalseBase),
		"similarity_baseline":   round3(simInfluence),
		"similarity_true_false": round3(simTrueFalse),
		"time_delta_ms":         timeDelta.Milliseconds(),
		"server_error":          serverError,
		"markers":               markers,
		"payloads":              payloads,
	}

	// El PoC del hallazgo: la misma petición con el payload y el matcher que
	// decide si la inyección dejó de reproducirse.
	attachPoc(evidence, sqliPoc(tpl, slot, trueRes, timePayload, timeRes, timeConfirmed))

	f := Finding{
		Source:     "web.sqli",
		SourceTool: "web.sqli",
		RuleID:     "sqli:native",
		Title:      sqliTitle(confidence),
		Severity:   sqliSeverity(confidence),
		Confidence: confidence,
		CWE:        "CWE-89",
		OWASP:      []string{"A03:2021"},
		Target:     sqliTarget(tpl, slot),
		Vector:     slot.surface + ":" + slot.name,
		Evidence:   evidence,
		Remediation: "Use parameterized queries (prepared statements) for every value taken from the " +
			"request and allow-list the accepted values of the parameter.",
		Tags: []string{"sqli"},
	}
	if confidence == ConfidenceConfirmed {
		f.CVSS = &CVSSVector{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"}
	}
	return f, true
}

// sqliPoc builds the proof of concept of a SQLi finding: the request that
// reproduces it and the matcher that decides whether it still reproduces.
//
// The baseline is the response of the ORIGINAL probe, not the benign one: the
// matcher compares the replay with the answer that proved the injection.
func sqliPoc(tpl *sqliTemplate, slot sqliSlot, trueRes probeResult, timePayload string, timeRes *probeResult, timeConfirmed bool) *pocRecord {
	if timeConfirmed && timePayload != "" && timeRes != nil {
		req, ok := sqliReplayRequest(tpl, slot, timePayload)
		if !ok {
			return nil
		}
		return &pocRecord{
			Kind:     "sqli",
			Method:   req.Method,
			URL:      req.URL,
			Body:     req.Body,
			Headers:  req.Headers,
			Payload:  timePayload,
			Matcher:  pocMatcherTimingUnder(int(sqliTimeThreshold.Milliseconds())),
			Baseline: pocBaselineOf(timeRes.status, timeRes.body),
		}
	}

	payload := sqliBooleanTrue
	req, ok := sqliReplayRequest(tpl, slot, payload)
	if !ok {
		return nil
	}
	matcher := pocMatcherBodyAbsent(payload)
	if !strings.Contains(trueRes.body, payload) {
		// The payload is not echoed back: the differential lives in the shape
		// of the response, so the matcher compares the new response with the
		// original one instead of looking for the payload.
		matcher = pocMatcherBodyChanged()
	}
	return &pocRecord{
		Kind:     "sqli",
		Method:   req.Method,
		URL:      req.URL,
		Body:     req.Body,
		Headers:  req.Headers,
		Payload:  payload,
		Matcher:  matcher,
		Baseline: pocBaselineOf(trueRes.status, trueRes.body),
	}
}

// sqliReplayRequest rebuilds the request the detector issued, with the
// payload written into the probed slot.
func sqliReplayRequest(tpl *sqliTemplate, slot sqliSlot, payload string) (pocRequestOf, bool) {
	req, err := tpl.newRequest()
	if err != nil {
		return pocRequestOf{}, false
	}
	if err := tpl.write(req, slot, payload); err != nil {
		return pocRequestOf{}, false
	}
	return httpRequestToPoc(req)
}

// sqliConfidence maps the evidence onto the canonical confidence set.
//
//	confirmed - the tool asserted the condition: a time based delta, two
//	            database error markers, or one marker next to a boolean
//	            differential
//	probable  - a boolean differential, or a database error marker the
//	            baseline never produced
//	possible  - the response changed with the value of the parameter
func sqliConfidence(booleanDiff bool, markers int, timeConfirmed, serverError, influence bool) string {
	switch {
	case timeConfirmed, markers >= 2, markers >= 1 && (booleanDiff || serverError):
		return ConfidenceConfirmed
	case booleanDiff, markers >= 1:
		return ConfidenceProbable
	case influence, serverError:
		return ConfidencePossible
	}
	return ""
}

// sqliSeverity maps the confidence onto the canonical severity set.
func sqliSeverity(confidence string) string {
	switch confidence {
	case ConfidenceConfirmed:
		return SeverityCritical
	case ConfidenceProbable:
		return SeverityHigh
	default:
		return SeverityMedium
	}
}

// sqliTitle is the human readable title of the finding.
func sqliTitle(confidence string) string {
	switch confidence {
	case ConfidenceConfirmed:
		return "SQLi confirmada (boolean/time-based/error-based)"
	case ConfidenceProbable:
		return "Posible SQLi (diferencial boolean)"
	default:
		return "Posible SQLi (la respuesta depende del valor del parámetro)"
	}
}

// sqliTarget is the reproduction target of the finding: the probed URL with
// the parameter marked, or the plain target for the body and header surfaces.
func sqliTarget(tpl *sqliTemplate, slot sqliSlot) string {
	if slot.surface != surfaceQuery {
		return tpl.target
	}
	u, err := url.Parse(tpl.target)
	if err != nil {
		return tpl.target
	}
	return setParam(u, slot.name, "<probe>").String()
}

func setParam(u *url.URL, key, val string) *url.URL {
	q := u.Query()
	q.Set(key, val)
	c := *u
	c.RawQuery = q.Encode()
	return &c
}

// probeResult is the outcome of a single probe.
type probeResult struct {
	status  int
	body    string
	elapsed time.Duration
}

// sqliProbe performs one request against the target with the scope bound
// client and returns the status, the body and the elapsed time.
func sqliProbe(ctx context.Context, client *http.Client, tpl *sqliTemplate, slot sqliSlot, value string, deadline time.Time) (probeResult, bool) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return probeResult{}, false
	}
	timeout := remaining
	if timeout > sqliProbeTimeout {
		timeout = sqliProbeTimeout
	}
	req, err := tpl.newRequest()
	if err != nil {
		return probeResult{}, false
	}
	if err := tpl.write(req, slot, value); err != nil {
		return probeResult{}, false
	}
	return probeRequest(ctx, client, req, timeout)
}

// probeRequest runs the request and reads at most one mebibyte of the body.
func probeRequest(ctx context.Context, client *http.Client, req *http.Request, timeout time.Duration) (probeResult, bool) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	resp, err := client.Do(req.WithContext(ctx))
	elapsed := time.Since(start)
	if err != nil {
		return probeResult{elapsed: elapsed}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSqliBodyBytes))
	return probeResult{status: resp.StatusCode, body: string(body), elapsed: elapsed}, true
}

// sqliNonce returns a random token of eight hex characters. It travels with
// the payload and locates the reflected value inside the response.
func sqliNonce() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("cannot generate the probe nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// similarity returns the Jaccard similarity of two texts over word shingles.
//
// Word bigrams are used instead of a plain token set because the responses are
// HTML: a bigram keeps the local context, so a rotating token only invalidates
// the two shingles around it instead of the whole set. Jaccard is linear and
// order insensitive, which matters because the dynamic parts of a page are
// scattered across the document; a normalized Levenshtein would be quadratic
// and would charge a full edit for every character of a rotating token.
func similarity(a, b string) float64 {
	sa := sqliShingles(a)
	sb := sqliShingles(b)
	if len(sa) == 0 || len(sb) == 0 {
		if len(sa) == len(sb) {
			return 1
		}
		return 0
	}
	inter := 0
	for shingle := range sa {
		if sb[shingle] {
			inter++
		}
	}
	union := len(sa) + len(sb) - inter
	return float64(inter) / float64(union)
}

// sqliShingles splits a text into lowercase word bigrams. A single word text
// falls back to the unigram so short bodies still compare.
func sqliShingles(s string) map[string]bool {
	words := sqliTokens(s)
	out := make(map[string]bool, len(words))
	switch {
	case len(words) == 0:
	case len(words) == 1:
		out[words[0]] = true
	default:
		for i := 0; i+1 < len(words); i++ {
			out[words[i]+"\x00"+words[i+1]] = true
		}
	}
	return out
}

// sqliTokens splits a text into lowercase alphanumeric tokens.
func sqliTokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// sqliNormalizeBody prepares a response body for the comparison:
//
//   - the payload is replaced by the benign baseline value, so an application
//     that echoes the parameter back (a search box) or an error page that
//     quotes the payload does not look like a differential
//   - the nonce is removed, so a reflected value is not a difference
//   - the volatile tokens are replaced by a constant, so a rotating token is
//     not a difference either
func sqliNormalizeBody(body, payload, nonce string, volatile map[string]bool) string {
	body = strings.ToLower(body)
	if payload != "" {
		body = sqliReplacePayload(body, payload)
	}
	if nonce != "" {
		body = strings.ReplaceAll(body, strings.ToLower(nonce), "")
	}
	if len(volatile) == 0 {
		return body
	}
	return strings.Join(maskVolatileTokens(sqliTokens(body), volatile), " ")
}

// sqliReplacePayload replaces the payload by the baseline value, in its raw
// and in its HTML escaped spelling. The body is already lowercased, so the
// replacement is case insensitive.
func sqliReplacePayload(body, payload string) string {
	lower := strings.ToLower(payload)
	body = strings.ReplaceAll(body, lower, sqliBaselineValue)
	escaped := strings.ToLower(html.EscapeString(payload))
	if escaped != lower {
		body = strings.ReplaceAll(body, escaped, sqliBaselineValue)
	}
	return body
}

// volatileTokenKeys returns the context keys of the tokens that differ
// between the two baseline samples. The key is the pair of neighbours, so a
// token whose value rotates (a CSRF token, a timestamp, a request id) is
// recognized in any later response even though its value changed.
func volatileTokenKeys(a, b []string) map[string]bool {
	keys := map[string]bool{}
	size := len(a)
	if len(b) < size {
		size = len(b)
	}
	for i := 0; i < size; i++ {
		if a[i] == b[i] {
			continue
		}
		keys[tokenContextKey(a, i)] = true
		keys[tokenContextKey(b, i)] = true
	}
	return keys
}

// tokenContextKey is the neighbourhood of a token: the token before it and
// the token after it.
func tokenContextKey(tokens []string, i int) string {
	prev, next := "", ""
	if i > 0 {
		prev = tokens[i-1]
	}
	if i+1 < len(tokens) {
		next = tokens[i+1]
	}
	return prev + "\x00" + next
}

// maskVolatileTokens replaces the volatile tokens by a constant.
func maskVolatileTokens(tokens []string, volatile map[string]bool) []string {
	out := make([]string, len(tokens))
	for i, token := range tokens {
		if volatile[tokenContextKey(tokens, i)] {
			out[i] = "volatile"
			continue
		}
		out[i] = token
	}
	return out
}

// sqliMarkerSet returns the database error markers present in the bodies.
func sqliMarkerSet(bodies ...string) map[string]bool {
	out := map[string]bool{}
	for _, body := range bodies {
		low := sqliMarkerText(body)
		for compact, readable := range sqliMarkerCompacts {
			if strings.Contains(low, compact) {
				out[readable] = true
			}
		}
	}
	return out
}

var (
	// sqliTagPattern matches the HTML tags of a body.
	sqliTagPattern = regexp.MustCompile(`(?s)<[^>]*>`)
	// sqliEntityPattern matches the HTML entities of a body.
	sqliEntityPattern = regexp.MustCompile(`&(?:#39|quot|apos|lt|gt|amp);`)
)

// sqliMarkerText normalizes a body before the marker search: the tags are
// removed, the common entities decoded and the whitespace dropped, so an
// error rendered as "<b>Warning</b>: mysql_fetch_array()" still matches the
// marker "warning: mysql_".
func sqliMarkerText(body string) string {
	text := sqliTagPattern.ReplaceAllString(body, "")
	text = sqliEntityPattern.ReplaceAllStringFunc(text, func(entity string) string {
		switch entity {
		case "&#39;", "&apos;":
			return "'"
		case "&quot;":
			return "\""
		case "&lt;":
			return "<"
		case "&gt;":
			return ">"
		case "&amp;":
			return "&"
		}
		return entity
	})
	return strings.Join(strings.Fields(strings.ToLower(text)), "")
}

// sqliNewMarkers returns the markers the probes produced and the baseline did
// not. A page that always mentions "PostgreSQL" in its footer is not a
// database error, so the baseline filters the markers out.
func sqliNewMarkers(probeBodies []string, baseline map[string]bool) []string {
	found := sqliMarkerSet(probeBodies...)
	out := []string{}
	for marker := range found {
		if baseline[marker] {
			continue
		}
		out = append(out, marker)
	}
	sort.Strings(out)
	return out
}

// medianDuration returns the median of the samples.
func medianDuration(samples ...time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

// round3 rounds a similarity to three decimals for the evidence.
func round3(v float64) float64 {
	return math.Round(v*1000) / 1000
}

// sortedMapKeys returns the keys of a map in a stable order.
func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func parseSqlmapOutput(output, target string) (Finding, bool) {
	if strings.Contains(output, "all tested parameters do not appear to be injectable") {
		return Finding{}, false
	}
	if !strings.Contains(output, "Parameter:") && !strings.Contains(output, "is vulnerable") {
		return Finding{}, false
	}

	f := Finding{
		Source:     "web.sqli",
		SourceTool: "web.sqli",
		RuleID:     "sqlmap",
		Title:      "SQL Injection Confirmada (sqlmap)",
		Severity:   SeverityCritical,
		Confidence: ConfidenceConfirmed,
		CWE:        "CWE-89",
		OWASP:      []string{"A03:2021"},
		Target:     target,
		Tags:       []string{"sqli"},
		Remediation: "Use parameterized queries (prepared statements) for every value taken from the " +
			"request and allow-list the accepted values of the parameter.",
		CVSS: &CVSSVector{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"},
	}

	fields, order := sqlmapDetails(output)
	if len(order) > 0 {
		evidence := map[string]any{}
		for _, key := range order {
			evidence[key] = fields[key]
		}
		f.Evidence = evidence
	}
	if parameter := fields["parameter"]; parameter != "" {
		f.Vector = strings.Fields(parameter)[0]
	}
	return f, true
}

// sqlmapDetails extracts the labelled lines sqlmap prints for a confirmed
// injection. The "[hh:mm:ss]" prefix sqlmap adds to every line is stripped so
// the labels are matched on their own.
func sqlmapDetails(output string) (map[string]string, []string) {
	fields := map[string]string{}
	var order []string
	for _, l := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "[") {
			if idx := strings.Index(trimmed, "]"); idx >= 0 {
				trimmed = strings.TrimSpace(trimmed[idx+1:])
			}
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		switch key {
		case "parameter", "type", "title", "payload", "back-end dbms":
		default:
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, seen := fields[key]; !seen {
			order = append(order, key)
		}
		fields[key] = value
	}
	return fields, order
}
