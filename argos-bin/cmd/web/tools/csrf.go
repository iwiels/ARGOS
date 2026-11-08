package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// RegisterCSRF registers the CSRF detection tool.
func RegisterCSRF(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.csrf",
			Description: "CSRF detection on a page: missing anti-CSRF token, predictable token, SameSite=Lax on a state " +
				"changing form, permissive CORS with credentials and missing Origin/Referer validation. The analysis is " +
				"read-only: no state changing request is sent.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":  {Type: "string", Description: "URL of the page that hosts the forms"},
					"cookie":  {Type: "string", Description: "Cookie header to send, so the page is rendered as an authenticated session"},
					"headers": {Type: "object", Description: "Extra request headers, as a name to value map"},
					"timeout": {Type: "integer", Description: "Per-request timeout in seconds (default 15, max 60)"},
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
				Target  string            `json:"target"`
				Cookie  string            `json:"cookie"`
				Headers map[string]string `json:"headers"`
				Timeout int               `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			started := time.Now()
			callCtx := toolContext(ctx)

			headers := map[string]string{}
			for name, value := range input.Headers {
				headers[name] = value
			}
			if strings.TrimSpace(input.Cookie) != "" {
				headers["Cookie"] = input.Cookie
			}

			report := detectCSRF(callCtx, env, target, headers, vectorTimeout(input.Timeout))
			fs, truncated := capFindings(report.findings)
			res := vectorResult("web.csrf", target, started)
			res["forms"] = report.forms
			res["cookies"] = report.cookies
			res["cors"] = report.cors
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d CSRF issues detected", len(fs))
			return res, nil
		},
	)
}

// csrfReport is the outcome of the analysis of one page.
type csrfReport struct {
	findings []Finding
	forms    []map[string]any
	cookies  []map[string]any
	cors     map[string]any
}

// csrfTokenNames are the field names an anti-CSRF token travels in.
var csrfTokenNames = []string{
	"csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken", "_csrf", "csrfmiddlewaretoken",
	"xsrf", "xsrf_token", "_xsrf", "x-csrf-token", "_token", "authenticity_token",
	"__requestverificationtoken", "__csrf", "anticsrf", "anti_csrf", "verification_token",
	"request_token", "csrfmiddleware", "nonce",
}

// csrfForeignOrigin is the origin the tool pretends to come from when it
// checks whether the endpoint validates the Origin header.
const csrfForeignOrigin = "https://evil.example"

// detectCSRF analyses a page and reports the CSRF weaknesses it can prove
// without sending a single state changing request.
func detectCSRF(ctx context.Context, env *Env, target string, headers map[string]string, timeout time.Duration) *csrfReport {
	report := &csrfReport{}
	client := env.Client()

	page, err := vectorFetch(ctx, client, "GET", target, vectorHeader(headers), "", timeout)
	if err != nil {
		return report
	}

	forms := parseHTMLForms(page.Body)
	for _, form := range forms {
		report.forms = append(report.forms, map[string]any{
			"index":  form.Index,
			"action": form.Action,
			"method": form.Method,
			"fields": form.Fields,
			"token":  form.Token,
		})
	}

	cookies := parseSetCookies(page.Headers)
	for _, cookie := range cookies {
		report.cookies = append(report.cookies, cookie)
	}

	stateChanging := 0
	for _, form := range forms {
		if form.IsStateChanging() {
			stateChanging++
		}
	}

	// Missing token: a form that changes state without any anti-CSRF field.
	for _, form := range forms {
		if !form.IsStateChanging() || form.HasTokenField() {
			continue
		}
		report.findings = append(report.findings, Finding{
			Source: "web.csrf", SourceTool: "web.csrf", RuleID: "csrf:missing-token",
			Title:      fmt.Sprintf("CSRF: the %s form has no anti-CSRF token", form.Method),
			Severity:   SeverityMedium,
			Confidence: ConfidenceProbable,
			CWE:        "CWE-352",
			OWASP:      []string{"A01:2021"},
			Target:     target,
			Vector:     "form:" + form.Action,
			Evidence: map[string]any{
				"action": form.Action,
				"method": form.Method,
				"fields": form.Fields,
				"url":    target,
			},
			Remediation: "Require an unpredictable anti-CSRF token on every state changing form and validate it server side " +
				"together with the session that issued it.",
			Tags: []string{"broken-access-control"},
		})
	}

	// Predictable token: the same token is served twice, or it is a constant.
	report.findings = append(report.findings, csrfPredictableTokenFindings(ctx, client, target, headers, timeout, forms)...)

	// SameSite: Lax on a session cookie while the page has state changing forms.
	if stateChanging > 0 {
		for _, cookie := range cookies {
			sameSite, _ := cookie["same_site"].(string)
			if !strings.EqualFold(sameSite, "lax") {
				continue
			}
			report.findings = append(report.findings, Finding{
				Source: "web.csrf", SourceTool: "web.csrf", RuleID: "csrf:samesite-lax",
				Title:      "CSRF: the session cookie " + fmt.Sprint(cookie["name"]) + " is SameSite=Lax while the page has state changing forms",
				Severity:   SeverityMedium,
				Confidence: ConfidencePossible,
				CWE:        "CWE-352",
				OWASP:      []string{"A01:2021"},
				Target:     target,
				Vector:     "cookie:" + fmt.Sprint(cookie["name"]),
				Evidence: map[string]any{
					"cookie":               cookie["name"],
					"same_site":            sameSite,
					"set_cookie":           cookie["raw"],
					"state_changing_forms": stateChanging,
					"url":                  target,
				},
				Remediation: "Mark the session cookie SameSite=Strict (or SameSite=None with Secure) and require an anti-CSRF " +
					"token on the state changing endpoints.",
				Tags: []string{"broken-access-control"},
			})
		}
	}

	// CORS and Origin validation: the endpoint is asked with a foreign
	// Origin. A cross-origin GET never changes the state of the target.
	corsHeaders := map[string]string{
		"Origin":  csrfForeignOrigin,
		"Referer": csrfForeignOrigin + "/attacker-page",
	}
	corsResp, err := vectorFetch(ctx, client, "GET", target, vectorHeader(corsHeaders), "", timeout)
	cors := map[string]any{"origin": csrfForeignOrigin}
	if err == nil && corsResp != nil {
		allowOrigin := corsResp.Headers.Get("Access-Control-Allow-Origin")
		allowCredentials := strings.EqualFold(strings.TrimSpace(corsResp.Headers.Get("Access-Control-Allow-Credentials")), "true")
		cors["access_control_allow_origin"] = allowOrigin
		cors["access_control_allow_credentials"] = allowCredentials
		cors["vary"] = corsResp.Headers.Get("Vary")
		report.cors = cors

		switch {
		case allowCredentials && strings.TrimSpace(allowOrigin) == "*":
			report.findings = append(report.findings, csrfCorsFinding(
				"csrf:cors-wildcard-credentials",
				"CSRF: the endpoint allows any origin with credentials (Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true)",
				SeverityMedium, ConfidenceProbable, target, cors))
		case allowCredentials && strings.TrimSpace(allowOrigin) == csrfForeignOrigin:
			report.findings = append(report.findings, csrfCorsFinding(
				"csrf:cors-credentialed-origin",
				"CSRF: the endpoint reflects a foreign origin with credentials, so any site can read the authenticated responses",
				SeverityHigh, ConfidenceConfirmed, target, cors))
		case strings.TrimSpace(allowOrigin) == csrfForeignOrigin:
			report.findings = append(report.findings, csrfCorsFinding(
				"csrf:origin-not-validated",
				"CSRF: the endpoint reflects a foreign Origin, so the request origin is not validated",
				SeverityMedium, ConfidenceProbable, target, cors))
		}
	} else {
		report.cors = cors
	}

	return report
}

// csrfCorsFinding builds the canonical finding of a CORS weakness.
func csrfCorsFinding(ruleID, title, severity, confidence, target string, cors map[string]any) Finding {
	return Finding{
		Source:     "web.csrf",
		SourceTool: "web.csrf",
		RuleID:     ruleID,
		Title:      title,
		Severity:   severity,
		Confidence: confidence,
		CWE:        "CWE-942",
		OWASP:      []string{"A05:2021"},
		Target:     target,
		Vector:     "cors:" + csrfForeignOrigin,
		Evidence:   cors,
		Remediation: "Answer with an explicit list of trusted origins instead of reflecting the Origin header, and only send " +
			"Access-Control-Allow-Credentials for the origins that are really allowed.",
		Tags: []string{"broken-access-control"},
	}
}

// csrfPredictableTokenFindings reports the anti-CSRF tokens that can be
// predicted by the attacker.
//
// The page is fetched twice: a token that does not change between two
// requests of the same session is replayable.
func csrfPredictableTokenFindings(ctx context.Context, client *http.Client, target string, headers map[string]string, timeout time.Duration, forms []htmlForm) []Finding {
	var fs []Finding
	first := map[string]string{}
	for _, form := range forms {
		if form.Token != "" {
			first[form.Token] = form.TokenValue
		}
	}
	if len(first) == 0 {
		return nil
	}

	second, err := vectorFetch(ctx, client, "GET", target, vectorHeader(headers), "", timeout)
	if err != nil {
		return nil
	}
	secondForms := parseHTMLForms(second.Body)
	values := map[string]string{}
	for _, form := range secondForms {
		if form.Token != "" {
			values[form.Token] = form.TokenValue
		}
	}

	names := make([]string, 0, len(first))
	for name := range first {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		value := strings.TrimSpace(first[name])
		if value == "" {
			fs = append(fs, csrfTokenFinding("csrf:empty-token",
				"CSRF: the anti-CSRF token field "+name+" is empty, so the request is not protected",
				SeverityHigh, ConfidenceConfirmed, target, name, value, map[string]any{}))
			continue
		}
		if csrfConstantToken(value) {
			fs = append(fs, csrfTokenFinding("csrf:constant-token",
				"CSRF: the anti-CSRF token field "+name+" carries a constant value, so the request is not protected",
				SeverityHigh, ConfidenceConfirmed, target, name, value, map[string]any{}))
			continue
		}
		other, ok := values[name]
		if !ok {
			continue
		}
		if other == value {
			fs = append(fs, csrfTokenFinding("csrf:predictable-token",
				"CSRF: the anti-CSRF token is identical in two consecutive requests, so it can be replayed",
				SeverityHigh, ConfidenceProbable, target, name, value, map[string]any{
					"second_value": other,
				}))
		}
	}
	return fs
}

// csrfConstantToken reports whether the token is a placeholder instead of a
// random value.
func csrfConstantToken(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "1", "none", "null", "undefined", "true", "false", "csrf", "token", "xxx", "xxxx", "test":
		return true
	}
	return false
}

// csrfTokenFinding builds the canonical finding of a weak anti-CSRF token.
func csrfTokenFinding(ruleID, title, severity, confidence, target, field, value string, extra map[string]any) Finding {
	evidence := map[string]any{
		"field": field,
		"value": value,
		"url":   target,
	}
	for key, item := range extra {
		evidence[key] = item
	}
	return Finding{
		Source:     "web.csrf",
		SourceTool: "web.csrf",
		RuleID:     ruleID,
		Title:      title,
		Severity:   severity,
		Confidence: confidence,
		CWE:        "CWE-352",
		OWASP:      []string{"A01:2021"},
		Target:     target,
		Vector:     "form:" + field,
		Evidence:   evidence,
		Remediation: "Generate the anti-CSRF token from a cryptographically secure random source, bind it to the session " +
			"and validate it server side on every state changing request.",
		Tags: []string{"broken-access-control"},
	}
}

// htmlForm is one form of the page.
type htmlForm struct {
	Index      int
	Action     string
	Method     string
	Fields     []string
	Token      string
	TokenValue string
}

// IsStateChanging reports whether the method of the form changes the state
// of the application.
func (f htmlForm) IsStateChanging() bool {
	switch strings.ToUpper(f.Method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// HasTokenField reports whether the form carries an anti-CSRF field.
func (f htmlForm) HasTokenField() bool {
	return f.Token != ""
}

var (
	csrfFormOpenPattern  = regexp.MustCompile(`(?is)<form\b([^>]*)>`)
	csrfFormClosePattern = regexp.MustCompile(`(?is)</form\s*>`)
	csrfInputPattern     = regexp.MustCompile(`(?is)<(?:input|button|select)\b([^>]*)>`)
	csrfAttrPattern      = regexp.MustCompile("([a-zA-Z_:][-a-zA-Z0-9_:.]*)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'>]+))")
)

// parseHTMLForms extracts the forms of an HTML document.
func parseHTMLForms(body string) []htmlForm {
	var forms []htmlForm
	cursor := 0
	for {
		open := csrfFormOpenPattern.FindStringSubmatchIndex(body[cursor:])
		if open == nil {
			break
		}
		start := cursor + open[0]
		end := cursor + open[1]
		attributes := parseHTMLAttributes(body[cursor+open[2] : cursor+open[3]])

		contentEnd := len(body)
		if close := csrfFormClosePattern.FindStringIndex(body[end:]); close != nil {
			contentEnd = end + close[0]
		}
		content := body[end:contentEnd]

		form := htmlForm{
			Index:  len(forms),
			Action: attributes["action"],
			Method: strings.ToUpper(strings.TrimSpace(attributes["method"])),
		}
		if form.Method == "" {
			form.Method = "GET"
		}
		for _, match := range csrfInputPattern.FindAllStringSubmatch(content, -1) {
			attrs := parseHTMLAttributes(match[1])
			name := attrs["name"]
			if name == "" {
				continue
			}
			form.Fields = append(form.Fields, name)
			if isCSRFTokenName(name) {
				form.Token = name
				form.TokenValue = attrs["value"]
			}
		}
		forms = append(forms, form)

		cursor = contentEnd
		if cursor <= start {
			cursor = end
		}
	}
	return forms
}

// parseHTMLAttributes extracts the attributes of an HTML tag.
func parseHTMLAttributes(raw string) map[string]string {
	out := map[string]string{}
	for _, match := range csrfAttrPattern.FindAllStringSubmatch(raw, -1) {
		name := strings.ToLower(strings.TrimSpace(match[1]))
		value := match[2]
		if value == "" {
			value = match[3]
		}
		if value == "" {
			value = match[4]
		}
		out[name] = value
	}
	return out
}

// isCSRFTokenName reports whether the field name is the usual name of an
// anti-CSRF token.
func isCSRFTokenName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, candidate := range csrfTokenNames {
		if lower == candidate {
			return true
		}
	}
	return false
}

// parseSetCookies reads the cookies the response sets.
func parseSetCookies(headers map[string][]string) []map[string]any {
	var out []map[string]any
	values, ok := headers["Set-Cookie"]
	if !ok {
		return out
	}
	for _, raw := range values {
		parts := strings.Split(raw, ";")
		nameValue := strings.TrimSpace(parts[0])
		name, value, _ := strings.Cut(nameValue, "=")
		sameSite := ""
		secure := false
		httpOnly := false
		for _, attribute := range parts[1:] {
			attribute = strings.ToLower(strings.TrimSpace(attribute))
			switch {
			case attribute == "samesite=lax":
				sameSite = "Lax"
			case attribute == "samesite=strict":
				sameSite = "Strict"
			case attribute == "samesite=none":
				sameSite = "None"
			case attribute == "secure":
				secure = true
			case attribute == "httponly":
				httpOnly = true
			}
		}
		out = append(out, map[string]any{
			"name":      name,
			"value":     value,
			"same_site": sameSite,
			"secure":    secure,
			"http_only": httpOnly,
			"raw":       raw,
		})
	}
	return out
}
