package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

// RegisterOAuth registers the OAuth misconfiguration detector.
func RegisterOAuth(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.oauth",
			Description: "OAuth 2.0 / OIDC misconfiguration detection on an authorization request: missing state, " +
				"missing or plain PKCE, lax redirect_uri, misused response_type, mixed code and token grants, client secret " +
				"in the authorization request and refresh tokens without rotation.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":        {Type: "string", Description: "URL of the application that starts the OAuth flow"},
					"authorize_url": {Type: "string", Description: "Authorization request to analyse. When it is absent the tool looks for one in the links of the target"},
					"headers":       {Type: "object", Description: "Extra request headers, as a name to value map"},
					"timeout":       {Type: "integer", Description: "Per-request timeout in seconds (default 15, max 60)"},
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
				Target       string            `json:"target"`
				AuthorizeURL string            `json:"authorize_url"`
				Headers      map[string]string `json:"headers"`
				Timeout      int               `json:"timeout"`
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

			report := auditOAuth(callCtx, env, target, input.AuthorizeURL, headers, vectorTimeout(input.Timeout))
			fs, truncated := capFindings(report.findings)
			res := vectorResult("web.oauth", target, started)
			res["authorize_url"] = report.authorizeURL
			res["parameters"] = report.parameters
			res["scopes"] = report.scopes
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d OAuth issues detected", len(fs))
			return res, nil
		},
	)
}

// oauthReport is the outcome of the analysis of one authorization request.
type oauthReport struct {
	findings     []Finding
	authorizeURL string
	parameters   map[string]string
	scopes       []string
}

// oauthAuthorizePattern matches the links that carry an OAuth authorization
// request.
var oauthAuthorizePattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^\s"'<>]+|/[\w./-]*(?:oauth2?|openid|saml)[\w./-]*(?:authorize|auth)[\w./-]*)`)

// auditOAuth analyses the authorization request of an application.
func auditOAuth(ctx context.Context, env *Env, target, authorizeURL string, headers map[string]string, timeout time.Duration) *oauthReport {
	report := &oauthReport{}

	candidate := strings.TrimSpace(authorizeURL)
	if candidate == "" {
		// The target itself can be the authorization request.
		if parsed, err := url.Parse(target); err == nil {
			query := parsed.Query()
			if query.Get("client_id") != "" || query.Get("response_type") != "" {
				candidate = target
			}
		}
	}
	if candidate == "" {
		candidate = oauthFindAuthorizeRequest(ctx, env, target, headers, timeout)
	}
	if candidate == "" {
		return report
	}
	report.authorizeURL = candidate

	parsed, err := url.Parse(candidate)
	if err != nil {
		return report
	}
	query := parsed.Query()
	parameters := map[string]string{}
	for name := range query {
		parameters[name] = query.Get(name)
	}
	report.parameters = parameters
	report.scopes = strings.Fields(query.Get("scope"))

	report.findings = append(report.findings, oauthStateFinding(candidate, parameters)...)
	report.findings = append(report.findings, oauthPKCEFindings(candidate, parameters)...)
	report.findings = append(report.findings, oauthRedirectURIFindings(candidate, parameters)...)
	report.findings = append(report.findings, oauthResponseTypeFindings(candidate, parameters)...)
	report.findings = append(report.findings, oauthSecretFindings(candidate, parameters)...)
	report.findings = append(report.findings, oauthRefreshTokenFinding(candidate, parameters, report.scopes)...)
	report.findings = append(report.findings, oauthNonceFinding(candidate, parameters, report.scopes)...)

	return report
}

// oauthFindAuthorizeRequest looks for the authorization request in the links
// of the application.
func oauthFindAuthorizeRequest(ctx context.Context, env *Env, target string, headers map[string]string, timeout time.Duration) string {
	resp, err := vectorFetch(ctx, env.Client(), "GET", target, vectorHeader(headers), "", timeout)
	if err != nil || resp == nil {
		return ""
	}
	base, err := url.Parse(target)
	if err != nil {
		return ""
	}
	candidates := oauthAuthorizePattern.FindAllString(resp.Body, -1)
	for _, candidate := range candidates {
		candidate = strings.TrimRight(candidate, ".,;)\"'")
		// The HTML escapes the ampersand of the query string.
		candidate = strings.ReplaceAll(candidate, "&amp;", "&")
		parsed, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		if !parsed.IsAbs() {
			parsed = base.ResolveReference(parsed)
		}
		query := parsed.Query()
		if query.Get("client_id") != "" || query.Get("response_type") != "" {
			return parsed.String()
		}
	}
	return ""
}

// oauthStateFinding reports an authorization request without a state.
func oauthStateFinding(authorizeURL string, parameters map[string]string) []Finding {
	state := strings.TrimSpace(parameters["state"])
	if state != "" {
		return nil
	}
	return []Finding{{
		Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:missing-state",
		Title:      "OAuth: the authorization request carries no state parameter",
		Severity:   SeverityHigh,
		Confidence: ConfidenceConfirmed,
		CWE:        "CWE-352",
		OWASP:      []string{"A01:2021"},
		Target:     authorizeURL,
		Vector:     "oauth:state",
		Evidence: map[string]any{
			"authorize_url": authorizeURL,
			"parameters":    parameters,
			"missing":       "state",
		},
		Remediation: "Generate an unpredictable state, bind it to the session of the user that starts the flow and compare it " +
			"with the value that comes back on the callback before exchanging the code.",
		Tags: []string{"broken-access-control"},
	}}
}

// oauthPKCEFindings reports the missing or downgraded PKCE.
func oauthPKCEFindings(authorizeURL string, parameters map[string]string) []Finding {
	var fs []Finding
	responseType := strings.ToLower(parameters["response_type"])
	challenge := strings.TrimSpace(parameters["code_challenge"])
	method := strings.ToUpper(strings.TrimSpace(parameters["code_challenge_method"]))

	if challenge != "" && method == "PLAIN" {
		fs = append(fs, Finding{
			Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:pkce-plain",
			Title:      "OAuth: the PKCE challenge uses the plain method, so the code verifier travels in the authorization request",
			Severity:   SeverityHigh,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-287",
			OWASP:      []string{"A07:2021"},
			Target:     authorizeURL,
			Vector:     "oauth:code_challenge_method",
			Evidence: map[string]any{
				"authorize_url":         authorizeURL,
				"code_challenge_method": method,
				"parameters":            parameters,
			},
			Remediation: "Use the S256 method for the PKCE challenge; the plain method leaks the verifier to the browser and to " +
				"the authorization server logs.",
			Tags: []string{"weak-auth"},
		})
	}

	if challenge == "" && strings.Contains(responseType, "code") {
		fs = append(fs, Finding{
			Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:missing-pkce",
			Title:      "OAuth: the authorization code flow does not use PKCE",
			Severity:   SeverityHigh,
			Confidence: ConfidenceProbable,
			CWE:        "CWE-287",
			OWASP:      []string{"A07:2021"},
			Target:     authorizeURL,
			Vector:     "oauth:code_challenge",
			Evidence: map[string]any{
				"authorize_url": authorizeURL,
				"response_type": parameters["response_type"],
				"parameters":    parameters,
			},
			Remediation: "Send a code_challenge (S256) with every authorization request and verify the code_verifier on the token " +
				"endpoint, also for the public clients.",
			Tags: []string{"weak-auth"},
		})
	}
	return fs
}

// oauthRedirectURIFindings reports the lax redirect URIs.
func oauthRedirectURIFindings(authorizeURL string, parameters map[string]string) []Finding {
	redirect := strings.TrimSpace(parameters["redirect_uri"])
	if redirect == "" {
		return []Finding{{
			Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:missing-redirect-uri",
			Title:      "OAuth: the authorization request carries no redirect_uri",
			Severity:   SeverityHigh,
			Confidence: ConfidenceProbable,
			CWE:        "CWE-601",
			OWASP:      []string{"A01:2021"},
			Target:     authorizeURL,
			Vector:     "oauth:redirect_uri",
			Evidence: map[string]any{
				"authorize_url": authorizeURL,
				"parameters":    parameters,
				"missing":       "redirect_uri",
			},
			Remediation: "Send an explicit redirect_uri and register it in the authorization server.",
			Tags:        []string{"open-redirect"},
		}}
	}

	if _, err := url.Parse(redirect); err != nil {
		return nil
	}
	loose := false
	reason := ""
	for _, marker := range []string{"*", "{{", "${", "%s", "%2a"} {
		if strings.Contains(redirect, marker) {
			loose = true
			reason = "the redirect_uri contains the wildcard marker " + marker
			break
		}
	}
	if !loose {
		return nil
	}
	return []Finding{{
		Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:open-redirect-uri",
		Title:      "OAuth: the redirect_uri is lax, so the authorization code can be sent to an attacker controlled URI",
		Severity:   SeverityHigh,
		Confidence: ConfidenceProbable,
		CWE:        "CWE-601",
		OWASP:      []string{"A01:2021"},
		Target:     authorizeURL,
		Vector:     "oauth:redirect_uri",
		Evidence: map[string]any{
			"authorize_url": authorizeURL,
			"redirect_uri":  redirect,
			"reason":        reason,
			"parameters":    parameters,
		},
		Remediation: "Register the exact redirect URIs in the authorization server and reject every request whose redirect_uri " +
			"is not an exact match of one of them.",
		Tags: []string{"open-redirect"},
	}}
}

// oauthResponseTypeFindings reports the misused response_type.
func oauthResponseTypeFindings(authorizeURL string, parameters map[string]string) []Finding {
	raw := strings.TrimSpace(parameters["response_type"])
	if raw == "" {
		return []Finding{{
			Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:missing-response-type",
			Title:      "OAuth: the authorization request carries no response_type",
			Severity:   SeverityMedium,
			Confidence: ConfidenceProbable,
			CWE:        "CWE-310",
			OWASP:      []string{"A07:2021"},
			Target:     authorizeURL,
			Vector:     "oauth:response_type",
			Evidence: map[string]any{
				"authorize_url": authorizeURL,
				"parameters":    parameters,
				"missing":       "response_type",
			},
			Remediation: "Always send an explicit response_type and refuse the requests that do not declare one.",
			Tags:        []string{"broken-authentication"},
		}}
	}

	// The response_type can be a space separated (or comma separated) list:
	// the query decoding already turned the "+" into a space.
	values := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(raw)), func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == '\n' || r == '\r'
	})
	hasCode := false
	hasToken := false
	for _, value := range values {
		switch value {
		case "code":
			hasCode = true
		case "token":
			hasToken = true
		}
	}

	var fs []Finding
	if hasCode && hasToken {
		fs = append(fs, Finding{
			Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:mixed-response-types",
			Title:      "OAuth: the authorization request mixes the code and the token grants, so the access token travels in the URL",
			Severity:   SeverityHigh,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-310",
			OWASP:      []string{"A07:2021"},
			Target:     authorizeURL,
			Vector:     "oauth:response_type",
			Evidence: map[string]any{
				"authorize_url": authorizeURL,
				"response_type": raw,
				"parameters":    parameters,
			},
			Remediation: "Use a single response_type per request and prefer the authorization code flow with PKCE over the " +
				"implicit flow.",
			Tags: []string{"broken-authentication", "token"},
		})
	}
	if hasToken && !hasCode {
		fs = append(fs, Finding{
			Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:implicit-flow",
			Title:      "OAuth: the authorization request uses the implicit flow, so the access token travels in the URL fragment",
			Severity:   SeverityMedium,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-598",
			OWASP:      []string{"A07:2021"},
			Target:     authorizeURL,
			Vector:     "oauth:response_type",
			Evidence: map[string]any{
				"authorize_url": authorizeURL,
				"response_type": raw,
				"parameters":    parameters,
			},
			Remediation: "Migrate the client to the authorization code flow with PKCE: the implicit flow exposes the access token " +
				"in the browser history and in the referrer.",
			Tags: []string{"token"},
		})
	}
	return fs
}

// oauthSecretFindings reports the credentials that travel in the
// authorization request.
func oauthSecretFindings(authorizeURL string, parameters map[string]string) []Finding {
	var fs []Finding
	if secret := strings.TrimSpace(parameters["client_secret"]); secret != "" {
		fs = append(fs, Finding{
			Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:client-secret-in-request",
			Title:      "OAuth: the client_secret travels in the authorization request, so it is exposed to the browser and to the logs",
			Severity:   SeverityHigh,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-798",
			OWASP:      []string{"A07:2021"},
			Target:     authorizeURL,
			Vector:     "oauth:client_secret",
			Evidence: map[string]any{
				"authorize_url": authorizeURL,
				"client_secret": "present",
				"parameters":    redactOAuthSecrets(parameters),
			},
			Remediation: "Keep the client_secret on the server: a confidential client authenticates on the token endpoint, " +
				"never in the authorization request.",
			Tags: []string{"hardcoded-credentials"},
		})
	}
	return fs
}

// oauthRefreshTokenFinding reports the refresh tokens that are not bound to
// the client.
//
// The rotation can only be observed when the flow completes, so the tool
// reports the exposure: a refresh token that is requested without PKCE is not
// bound to the instance that asked for it.
func oauthRefreshTokenFinding(authorizeURL string, parameters map[string]string, scopes []string) []Finding {
	offline := false
	for _, scope := range scopes {
		if strings.EqualFold(scope, "offline_access") {
			offline = true
			break
		}
	}
	if !offline {
		return nil
	}
	if strings.TrimSpace(parameters["code_challenge"]) != "" {
		return nil
	}
	return []Finding{{
		Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:refresh-token-without-rotation",
		Title:      "OAuth: the flow requests a refresh token without PKCE, so the refresh token is not bound to the client",
		Severity:   SeverityMedium,
		Confidence: ConfidencePossible,
		CWE:        "CWE-613",
		OWASP:      []string{"A07:2021"},
		Target:     authorizeURL,
		Vector:     "oauth:scope",
		Evidence: map[string]any{
			"authorize_url": authorizeURL,
			"scopes":        scopes,
			"parameters":    parameters,
			"note":          "the rotation of the refresh token can only be observed completing the flow: the tool reports the exposure",
		},
		Remediation: "Bind the refresh token to the client (PKCE on the refresh) and rotate it on every use, invalidating the " +
			"previous one.",
		Tags: []string{"token"},
	}}
}

// oauthNonceFinding reports the OIDC flows without a nonce.
func oauthNonceFinding(authorizeURL string, parameters map[string]string, scopes []string) []Finding {
	openid := false
	for _, scope := range scopes {
		if strings.EqualFold(scope, "openid") {
			openid = true
			break
		}
	}
	if !openid {
		return nil
	}
	if strings.TrimSpace(parameters["nonce"]) != "" {
		return nil
	}
	return []Finding{{
		Source: "web.oauth", SourceTool: "web.oauth", RuleID: "oauth:missing-nonce",
		Title:      "OIDC: the authentication request carries no nonce, so the ID token is not bound to the session",
		Severity:   SeverityMedium,
		Confidence: ConfidencePossible,
		CWE:        "CWE-345",
		OWASP:      []string{"A07:2021"},
		Target:     authorizeURL,
		Vector:     "oauth:nonce",
		Evidence: map[string]any{
			"authorize_url": authorizeURL,
			"scopes":        scopes,
			"parameters":    parameters,
			"missing":       "nonce",
		},
		Remediation: "Send a nonce in the authentication request and verify it in the ID token.",
		Tags:        []string{"broken-authentication"},
	}}
}

// redactOAuthSecrets removes the credentials from the evidence.
func redactOAuthSecrets(parameters map[string]string) map[string]string {
	out := map[string]string{}
	for name, value := range parameters {
		if strings.Contains(strings.ToLower(name), "secret") {
			out[name] = "present"
			continue
		}
		out[name] = value
	}
	return out
}
