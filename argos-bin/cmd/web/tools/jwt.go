package tools

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// RegisterJWT registers the JWT analysis tool.
func RegisterJWT(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.jwt",
			Description: "JWT analysis: algorithm confusion (alg:none, RS256 to HS256), controllable key references " +
				"(kid/jku/x5u), missing or expired exp, permissive issuer/audience and sensitive or mutable claims. " +
				"The signature is verified against the supplied key whenever one is available.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"token":      {Type: "string", Description: "The JWT to analyse (the 'Bearer ' prefix is accepted)"},
					"header":     {Type: "string", Description: "Name of the request header that carries the token, e.g. Authorization. The token is read from that header of a request to target"},
					"target":     {Type: "string", Description: "URL the token is read from when header is set"},
					"secret":     {Type: "string", Description: "HMAC secret of the issuer, used to verify an HS* signature and to judge its strength"},
					"public_key": {Type: "string", Description: "PEM RSA public key (or certificate) of the issuer, used to verify an RS* signature and to test the RS256 to HS256 confusion"},
					"timeout":    {Type: "integer", Description: "Per-request timeout in seconds (default 15, max 60)"},
				},
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
				Token     string `json:"token"`
				Header    string `json:"header"`
				Target    string `json:"target"`
				Secret    string `json:"secret"`
				PublicKey string `json:"public_key"`
				Timeout   int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			started := time.Now()
			callCtx := toolContext(ctx)

			token := strings.TrimSpace(input.Token)
			vector := "jwt:token"
			target := ""
			if token == "" {
				if input.Header == "" {
					return nil, &mcp.ErrorObj{Code: -32602, Message: "token is required (or header plus target)"}
				}
				if input.Target == "" {
					return nil, &mcp.ErrorObj{Code: -32602, Message: "target is required when the token is read from a header"}
				}
				validated, e := validateWebTargetWithToolContext(env, ctx, input.Target)
				if e != nil {
					return nil, e
				}
				target = validated
				resp, err := vectorFetch(callCtx, env.Client(), "GET", target, nil, "", vectorTimeout(input.Timeout))
				if err != nil {
					return nil, &mcp.ErrorObj{Code: -32603, Message: "cannot read the token from the target: " + err.Error()}
				}
				raw := resp.Headers.Get(input.Header)
				extracted, ok := jwtExtract(raw)
				if !ok {
					return nil, &mcp.ErrorObj{Code: -32602, Message: fmt.Sprintf("the %s header of the target does not carry a JWT", input.Header)}
				}
				token = extracted
				vector = "header:" + input.Header
			} else {
				if extracted, ok := jwtExtract(token); ok {
					token = extracted
				}
			}

			parsed, err := parseJWT(token)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "cannot parse the token: " + err.Error()}
			}

			analysis, err := analyzeJWT(parsed, input.Secret, input.PublicKey, time.Now())
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: err.Error()}
			}

			fs, truncated := capFindings(analysis.findings)
			fs = attachJwtPocs(fs, target, token)
			res := vectorResult("web.jwt", target, started)
			if target == "" {
				res["target"] = parsed.audienceOrHost()
			}
			res["vector"] = vector
			res["algorithm"] = parsed.Alg
			res["signature"] = analysis.signature
			res["claims"] = parsed.Claims
			res["header"] = parsed.Header
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d JWT issues detected", len(fs))
			return res, nil
		},
	)
}

// attachJwtPocs builds the proof of concept of every JWT finding: the request
// that replays the token and the matcher that checks whether the endpoint
// still accepts it.
//
// The matcher is the status: while the endpoint answers 200 the token is
// still accepted, so the weakness is still there. A token analysed offline
// (no target) has no PoC: there is nothing to replay.
func attachJwtPocs(fs []Finding, target, token string) []Finding {
	if strings.TrimSpace(target) == "" || strings.TrimSpace(token) == "" {
		return fs
	}
	for i := range fs {
		if fs[i].Evidence == nil {
			fs[i].Evidence = map[string]any{}
		}
		attachPoc(fs[i].Evidence, &pocRecord{
			Kind:    "jwt",
			Method:  http.MethodGet,
			URL:     target,
			Headers: map[string]string{"Authorization": "Bearer " + token},
			Payload: token,
			Matcher: pocMatcherStatus(http.StatusOK),
		})
	}
	return fs
}

// parsedJWT is the decoded content of a JWS compact serialization.
type parsedJWT struct {
	Raw          string
	Header       map[string]any
	Claims       map[string]any
	Signature    string
	SigningInput string
	Alg          string
}

// audienceOrHost returns a stable target label for a token analysed offline.
func (p *parsedJWT) audienceOrHost() string {
	if aud, ok := p.Claims["aud"].(string); ok && aud != "" {
		return aud
	}
	if iss, ok := p.Claims["iss"].(string); ok && iss != "" {
		return iss
	}
	return "jwt"
}

// jwtExtract pulls the JWT out of a header value.
//
// The value can be a bare token or a scheme prefixed one ("Bearer eyJ..."),
// and a proxy can append several values to the same header.
func jwtExtract(raw string) (string, bool) {
	for _, field := range strings.Fields(raw) {
		candidate := strings.TrimSpace(field)
		if candidate == "" {
			continue
		}
		if parts := strings.Split(candidate, "."); len(parts) == 3 && parts[0] != "" && parts[1] != "" {
			return candidate, true
		}
	}
	return "", false
}

// parseJWT decodes the header and the payload of a JWS compact serialization.
func parseJWT(token string) (*parsedJWT, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("the token is not a JWS compact serialization: %d segments", len(parts))
	}
	header, err := jwtDecodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid header: %w", err)
	}
	claims, err := jwtDecodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}
	alg, _ := header["alg"].(string)
	return &parsedJWT{
		Raw:          token,
		Header:       header,
		Claims:       claims,
		Signature:    parts[2],
		SigningInput: parts[0] + "." + parts[1],
		Alg:          alg,
	}, nil
}

// jwtDecodeSegment decodes one base64url segment of a token.
func jwtDecodeSegment(segment string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(segment)
		if err != nil {
			return nil, fmt.Errorf("invalid base64url segment: %w", err)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON segment: %w", err)
	}
	return doc, nil
}

// jwtAlgorithms are the algorithms a server is expected to accept.
var jwtAlgorithms = map[string]bool{
	"none": true, "HS256": true, "HS384": true, "HS512": true,
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"PS256": true, "PS384": true, "PS512": true,
}

// jwtHMACAlgorithms are the symmetric algorithms: they are the ones that open
// the RS256 to HS256 confusion.
var jwtHMACAlgorithms = map[string]bool{
	"HS256": true, "HS384": true, "HS512": true,
}

// jwtWeakSecrets are the secrets a JWT issuer is commonly found with.
var jwtWeakSecrets = []string{
	"secret", "secretkey", "secretkey123", "supersecret", "mysecret", "mysecretkey",
	"password", "passwd", "changeme", "change-me", "test", "testing", "dev",
	"key", "privatekey", "private-key", "jwt-secret", "jwtsecret", "jwt_secret",
	"your-256-bit-secret", "your_jwt_secret", "s3cr3t", "qwerty", "123456",
	"12345678", "abc123", "default", "none", "null", "undefined",
}

// jwtSensitiveClaims are the claims that must never travel inside a token:
// they are credentials, not authorization data.
var jwtSensitiveClaims = []string{
	"password", "passwd", "pwd", "secret", "client_secret", "api_key", "apikey",
	"access_key", "private_key", "refresh_token", "credit_card", "card_number",
	"cvv", "ssn", "social_security", "pin",
}

// jwtPrivilegeClaims are the claims the client can edit to escalate: the
// signature does not protect them when the server does not re-check them.
var jwtPrivilegeClaims = []string{
	"role", "roles", "is_admin", "admin", "is_superuser", "superuser",
	"permissions", "groups", "is_staff", "privilege_level", "access_level",
}

// jwtAnalysis is the outcome of the analysis of one token.
type jwtAnalysis struct {
	findings  []Finding
	signature map[string]any
}

// analyzeJWT inspects a decoded token and reports every issue it can prove
// from the token itself.
func analyzeJWT(parsed *parsedJWT, secret, publicKey string, now time.Time) (*jwtAnalysis, error) {
	analysis := &jwtAnalysis{signature: map[string]any{
		"algorithm": parsed.Alg,
		"verified":  false,
		"method":    "none",
	}}

	var pemSecrets [][]byte
	if strings.TrimSpace(publicKey) != "" {
		key, der, err := jwtParsePublicKey(publicKey)
		if err != nil {
			return nil, err
		}
		// The confusion attack signs with the public key as the shared
		// secret. Depending on the implementation the secret is the PEM
		// text or the DER bytes, so both spellings are tried.
		pemSecrets = append(pemSecrets, []byte(publicKey), der)
		analysis.signature["method"] = "RS256"
		analysis.signature["key_source"] = "public_key"
		if jwtVerifyRS256(parsed, key) {
			analysis.signature["verified"] = true
		}
	}

	hasSecret := strings.TrimSpace(secret) != ""
	if hasSecret {
		analysis.signature["method"] = "HS256"
		analysis.signature["key_source"] = "secret"
		if jwtVerifyHS256(parsed, []byte(secret)) {
			analysis.signature["verified"] = true
		}
	}
	if !hasSecret && len(pemSecrets) == 0 {
		analysis.signature["method"] = "not-verified"
		analysis.signature["reason"] = "no key was supplied: the signature was not verified and is not assumed valid"
	}

	fs := []Finding{}
	fs = append(fs, jwtAlgorithmFindings(parsed, pemSecrets)...)
	fs = append(fs, jwtKeyReferenceFindings(parsed)...)
	fs = append(fs, jwtLifetimeFindings(parsed, now)...)
	fs = append(fs, jwtAudienceFindings(parsed)...)
	fs = append(fs, jwtClaimFindings(parsed)...)
	if hasSecret {
		fs = append(fs, jwtSecretStrengthFinding(parsed, secret)...)
	}

	analysis.findings = fs
	return analysis, nil
}

// jwtAlgorithmFindings reports the issues of the signature algorithm.
func jwtAlgorithmFindings(parsed *parsedJWT, pemSecrets [][]byte) []Finding {
	var fs []Finding
	alg := strings.TrimSpace(parsed.Alg)
	evidence := map[string]any{
		"algorithm": parsed.Alg,
		"header":    parsed.Header,
	}

	switch {
	case alg == "":
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:missing-alg",
			Title:      "JWT without alg header: the verification algorithm is undefined",
			Severity:   SeverityHigh,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-347",
			OWASP:      []string{"A02:2021"},
			Target:     parsed.audienceOrHost(),
			Vector:     "jwt:header.alg",
			Evidence:   evidence,
			Remediation: "Require the algorithm to be present and to be one of the accepted ones; " +
				"never fall back to a default when the header does not declare it.",
			Tags: []string{"jwt", "broken-authentication"},
		})
	case strings.EqualFold(alg, "none"):
		evidence["signature"] = parsed.Signature
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:alg-none",
			Title:      "JWT signed with alg=none: the token is accepted without any signature verification",
			Severity:   SeverityCritical,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-347",
			OWASP:      []string{"A02:2021"},
			Target:     parsed.audienceOrHost(),
			Vector:     "jwt:header.alg",
			Evidence:   evidence,
			Remediation: "Reject every token whose alg is none (or any algorithm outside the allow-list of the issuer) " +
				"before the signature verification step.",
			Tags: []string{"jwt", "alg-none"},
			CVSS: &CVSSVector{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"},
		})
	case !jwtAlgorithms[alg]:
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:unsupported-alg",
			Title:       "JWT with an unsupported signing algorithm: " + alg,
			Severity:    SeverityHigh,
			Confidence:  ConfidenceConfirmed,
			CWE:         "CWE-347",
			OWASP:       []string{"A02:2021"},
			Target:      parsed.audienceOrHost(),
			Vector:      "jwt:header.alg",
			Evidence:    evidence,
			Remediation: "Pin the accepted algorithms on the server side and reject everything outside the allow-list.",
			Tags:        []string{"jwt", "broken-authentication"},
		})
	}

	// The RS256 to HS256 confusion: the issuer verifies with an RSA key and
	// the server accepts an HMAC signature verified with the public key as
	// the shared secret.
	if jwtHMACAlgorithms[alg] && len(pemSecrets) > 0 {
		if jwtVerifyAnyHS256(parsed, pemSecrets) {
			evidence["confusion"] = "the HS* signature validates with the RSA public key of the issuer as the HMAC secret"
			fs = append(fs, Finding{
				Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:alg-confusion",
				Title:      "JWT algorithm confusion: the RS256 issuer accepts an HMAC signature verified with its own public key",
				Severity:   SeverityCritical,
				Confidence: ConfidenceConfirmed,
				CWE:        "CWE-347",
				OWASP:      []string{"A02:2021"},
				Target:     parsed.audienceOrHost(),
				Vector:     "jwt:header.alg",
				Evidence:   evidence,
				Remediation: "Bind the verification algorithm to the key type of the issuer (RS* for RSA keys, HS* for shared secrets) " +
					"instead of trusting the alg header of the token.",
				Tags: []string{"jwt", "broken-authentication"},
				CVSS: &CVSSVector{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"},
			})
		}
	}

	if parsed.Signature == "" && alg != "" && !strings.EqualFold(alg, "none") {
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:empty-signature",
			Title:       "JWT with an empty signature: the token was crafted without a signing key",
			Severity:    SeverityMedium,
			Confidence:  ConfidencePossible,
			CWE:         "CWE-347",
			OWASP:       []string{"A02:2021"},
			Target:      parsed.audienceOrHost(),
			Vector:      "jwt:signature",
			Evidence:    evidence,
			Remediation: "Reject tokens whose signature segment is empty.",
			Tags:        []string{"jwt", "broken-authentication"},
		})
	}
	return fs
}

// jwtKeyReferenceFindings reports the key references the token controls.
func jwtKeyReferenceFindings(parsed *parsedJWT) []Finding {
	var fs []Finding
	header := parsed.Header

	if kid, ok := header["kid"].(string); ok && strings.TrimSpace(kid) != "" {
		if jwtSuspiciousKeyID(kid) {
			fs = append(fs, Finding{
				Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:kid-injection",
				Title:      "JWT kid header carries a path or an injection payload: the key lookup is attacker controlled",
				Severity:   SeverityHigh,
				Confidence: ConfidenceProbable,
				CWE:        "CWE-22",
				OWASP:      []string{"A02:2021"},
				Target:     parsed.audienceOrHost(),
				Vector:     "jwt:header.kid",
				Evidence: map[string]any{
					"kid":    kid,
					"header": header,
				},
				Remediation: "Resolve the kid against an allow-list of key identifiers instead of using it to build a file path " +
					"or a query, and reject any value outside that allow-list.",
				Tags: []string{"jwt", "path-traversal"},
			})
		}
	}

	for _, name := range []string{"jku", "x5u"} {
		value, ok := header[name].(string)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		confidence := ConfidencePossible
		severity := SeverityMedium
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "http://") {
			confidence = ConfidenceProbable
			severity = SeverityHigh
		}
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:remote-key-" + name,
			Title:      "JWT " + name + " header points to a remote key: the issuer fetches the verification key from the token",
			Severity:   severity,
			Confidence: confidence,
			CWE:        "CWE-918",
			OWASP:      []string{"A02:2021"},
			Target:     parsed.audienceOrHost(),
			Vector:     "jwt:header." + name,
			Evidence: map[string]any{
				name:     value,
				"header": header,
			},
			Remediation: "Do not resolve the verification key from a URL carried by the token; use the keys of the issuer " +
				"that are already configured and trusted.",
			Tags: []string{"jwt", "ssrf"},
		})
	}
	return fs
}

// jwtSuspiciousKeyID reports whether the kid header looks like an injection
// payload instead of a key identifier.
func jwtSuspiciousKeyID(kid string) bool {
	lower := strings.ToLower(kid)
	for _, marker := range []string{"/", "\\", "..", "%2f", "%5c", "http://", "https://", "=", "'", "\"", ";", "$", "`", "\x00"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// jwtLifetimeFindings reports the issues of the temporal claims.
func jwtLifetimeFindings(parsed *parsedJWT, now time.Time) []Finding {
	var fs []Finding
	claims := parsed.Claims

	exp, hasExp := jwtNumericClaim(claims, "exp")
	if !hasExp {
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:no-exp",
			Title:      "JWT without exp claim: the token never expires",
			Severity:   SeverityMedium,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-613",
			OWASP:      []string{"A07:2021"},
			Target:     parsed.audienceOrHost(),
			Vector:     "jwt:claims.exp",
			Evidence: map[string]any{
				"claims": claims,
			},
			Remediation: "Always issue the exp claim and reject the tokens that do not carry one.",
			Tags:        []string{"jwt", "broken-authentication"},
		})
	} else if time.Unix(int64(exp), 0).Before(now) {
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:expired",
			Title:      "JWT expired: the token is past its exp claim",
			Severity:   SeverityMedium,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-613",
			OWASP:      []string{"A07:2021"},
			Target:     parsed.audienceOrHost(),
			Vector:     "jwt:claims.exp",
			Evidence: map[string]any{
				"exp":        exp,
				"exp_iso":    time.Unix(int64(exp), 0).UTC().Format(time.RFC3339),
				"now_iso":    now.UTC().Format(time.RFC3339),
				"expired_by": int64(now.Sub(time.Unix(int64(exp), 0)).Seconds()),
			},
			Remediation: "Validate the exp claim on every request and reject the expired tokens.",
			Tags:        []string{"jwt", "token"},
		})
	}

	if nbf, ok := jwtNumericClaim(claims, "nbf"); ok && time.Unix(int64(nbf), 0).After(now) {
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:not-yet-valid",
			Title:      "JWT not valid yet: the nbf claim is in the future",
			Severity:   SeverityLow,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-613",
			OWASP:      []string{"A07:2021"},
			Target:     parsed.audienceOrHost(),
			Vector:     "jwt:claims.nbf",
			Evidence: map[string]any{
				"nbf":     nbf,
				"nbf_iso": time.Unix(int64(nbf), 0).UTC().Format(time.RFC3339),
				"now_iso": now.UTC().Format(time.RFC3339),
			},
			Remediation: "Validate the nbf claim together with exp and keep the clock skew tolerance small.",
			Tags:        []string{"jwt", "token"},
		})
	}
	return fs
}

// jwtAudienceFindings reports the issues of the issuer and the audience.
func jwtAudienceFindings(parsed *parsedJWT) []Finding {
	var fs []Finding
	claims := parsed.Claims

	iss, hasIss := claims["iss"].(string)
	if !hasIss || strings.TrimSpace(iss) == "" {
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:no-iss",
			Title:       "JWT without iss claim: the issuer cannot be validated",
			Severity:    SeverityLow,
			Confidence:  ConfidencePossible,
			CWE:         "CWE-345",
			OWASP:       []string{"A07:2021"},
			Target:      parsed.audienceOrHost(),
			Vector:      "jwt:claims.iss",
			Evidence:    map[string]any{"claims": claims},
			Remediation: "Issue the iss claim and compare it with the expected issuer on every request.",
			Tags:        []string{"jwt", "broken-authentication"},
		})
	}

	aud, hasAud := claims["aud"]
	if !hasAud {
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:no-aud",
			Title:       "JWT without aud claim: the audience cannot be validated",
			Severity:    SeverityMedium,
			Confidence:  ConfidencePossible,
			CWE:         "CWE-345",
			OWASP:       []string{"A07:2021"},
			Target:      parsed.audienceOrHost(),
			Vector:      "jwt:claims.aud",
			Evidence:    map[string]any{"claims": claims},
			Remediation: "Issue the aud claim and compare it with the audience expected by the resource that receives the token.",
			Tags:        []string{"jwt", "broken-authentication"},
		})
		return fs
	}

	for _, audience := range jwtAudienceList(aud) {
		if audience == "*" {
			fs = append(fs, Finding{
				Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:aud-wildcard",
				Title:      "JWT with a wildcard audience: the token is valid for every resource",
				Severity:   SeverityMedium,
				Confidence: ConfidenceConfirmed,
				CWE:        "CWE-345",
				OWASP:      []string{"A07:2021"},
				Target:     parsed.audienceOrHost(),
				Vector:     "jwt:claims.aud",
				Evidence: map[string]any{
					"aud": aud,
				},
				Remediation: "Never accept a wildcard audience and pin the audience of every token to the resource that consumes it.",
				Tags:        []string{"jwt", "broken-access-control"},
			})
			break
		}
	}
	return fs
}

// jwtClaimFindings reports the claims that must not travel inside a token.
func jwtClaimFindings(parsed *parsedJWT) []Finding {
	var fs []Finding
	claims := parsed.Claims

	sensitive := jwtMatchingClaims(claims, jwtSensitiveClaims)
	if len(sensitive) > 0 {
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:sensitive-claims",
			Title:      "JWT carries sensitive claims: " + strings.Join(sensitive, ", "),
			Severity:   SeverityMedium,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-200",
			OWASP:      []string{"A02:2021"},
			Target:     parsed.audienceOrHost(),
			Vector:     "jwt:claims",
			Evidence: map[string]any{
				"claims":           claims,
				"sensitive_claims": sensitive,
			},
			Remediation: "Never put credentials or personal data inside a token: the payload of a JWT is readable by the client.",
			Tags:        []string{"jwt", "information-disclosure"},
		})
	}

	mutable := jwtMatchingClaims(claims, jwtPrivilegeClaims)
	if len(mutable) > 0 {
		fs = append(fs, Finding{
			Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:mutable-privilege-claims",
			Title:      "JWT carries mutable privilege claims: " + strings.Join(mutable, ", "),
			Severity:   SeverityHigh,
			Confidence: ConfidenceConfirmed,
			CWE:        "CWE-269",
			OWASP:      []string{"A01:2021"},
			Target:     parsed.audienceOrHost(),
			Vector:     "jwt:claims",
			Evidence: map[string]any{
				"claims":                   claims,
				"mutable_privilege_claims": mutable,
			},
			Remediation: "Derive the privileges from the server side session and never trust the role claims carried by the token; " +
				"if the token has to carry them, re-check them against the account on every privileged operation.",
			Tags: []string{"jwt", "privilege-escalation"},
		})
	}
	return fs
}

// jwtSecretStrengthFinding reports a weak HMAC secret.
func jwtSecretStrengthFinding(parsed *parsedJWT, secret string) []Finding {
	trimmed := strings.TrimSpace(secret)
	weak := false
	for _, candidate := range jwtWeakSecrets {
		if strings.EqualFold(trimmed, candidate) {
			weak = true
			break
		}
	}
	if !weak && len(trimmed) < 16 {
		weak = true
	}
	if !weak {
		return nil
	}
	return []Finding{{
		Source: "web.jwt", SourceTool: "web.jwt", RuleID: "jwt:weak-secret",
		Title:      "JWT signed with a weak shared secret: the signature can be forged offline",
		Severity:   SeverityHigh,
		Confidence: ConfidenceConfirmed,
		CWE:        "CWE-798",
		OWASP:      []string{"A02:2021"},
		Target:     parsed.audienceOrHost(),
		Vector:     "jwt:signature",
		Evidence: map[string]any{
			"secret_length":    len(trimmed),
			"secret_is_common": jwtSecretIsCommon(trimmed),
			"signature":        parsed.Signature,
		},
		Remediation: "Use a random secret of at least 32 bytes and rotate it; never reuse a password or a default value as the signing key.",
		Tags:        []string{"jwt", "hardcoded-credentials"},
	}}
}

// jwtSecretIsCommon reports whether the secret is one of the well known ones.
func jwtSecretIsCommon(secret string) bool {
	for _, candidate := range jwtWeakSecrets {
		if strings.EqualFold(secret, candidate) {
			return true
		}
	}
	return false
}

// jwtMatchingClaims returns the claim names of the list that the token
// carries, sorted so the evidence is stable.
func jwtMatchingClaims(claims map[string]any, names []string) []string {
	var out []string
	for name := range claims {
		lower := strings.ToLower(name)
		for _, candidate := range names {
			if lower == candidate || strings.Contains(lower, candidate) {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// jwtAudienceList normalizes the aud claim, which can be a string or a list.
func jwtAudienceList(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{strings.TrimSpace(typed)}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

// jwtNumericClaim reads a numeric claim, accepting the JSON number and the
// numeric string spellings.
func jwtNumericClaim(claims map[string]any, name string) (float64, bool) {
	raw, ok := claims[name]
	if !ok {
		return 0, false
	}
	switch typed := raw.(type) {
	case float64:
		return typed, true
	case json.Number:
		value, err := typed.Float64()
		return value, err == nil
	case string:
		var value float64
		if _, err := fmt.Sscanf(strings.TrimSpace(typed), "%g", &value); err == nil {
			return value, true
		}
	}
	return 0, false
}

// jwtVerifyHS256 verifies an HMAC SHA-256 signature.
func jwtVerifyHS256(parsed *parsedJWT, secret []byte) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parsed.SigningInput))
	expected := mac.Sum(nil)
	actual, err := base64.RawURLEncoding.DecodeString(parsed.Signature)
	if err != nil {
		actual, err = base64.URLEncoding.DecodeString(parsed.Signature)
		if err != nil {
			return false
		}
	}
	return hmac.Equal(expected, actual)
}

// jwtVerifyRS256 verifies an RSASSA-PKCS1-v1_5 SHA-256 signature.
func jwtVerifyRS256(parsed *parsedJWT, key *rsa.PublicKey) bool {
	actual, err := base64.RawURLEncoding.DecodeString(parsed.Signature)
	if err != nil {
		actual, err = base64.URLEncoding.DecodeString(parsed.Signature)
		if err != nil {
			return false
		}
	}
	digest := sha256.Sum256([]byte(parsed.SigningInput))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], actual) == nil
}

// jwtParsePublicKey reads an RSA public key out of a PEM block and returns
// the DER bytes of the key, which is one of the spellings an implementation
// uses as the shared secret of the algorithm confusion attack.
func jwtParsePublicKey(pemText string) (*rsa.PublicKey, []byte, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, nil, errors.New("the public key is not PEM encoded")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, nil, errors.New("the supplied key is not an RSA public key")
		}
		return rsaKey, block.Bytes, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, block.Bytes, nil
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, nil, errors.New("the supplied certificate does not carry an RSA public key")
		}
		return rsaKey, block.Bytes, nil
	}
	return nil, nil, errors.New("cannot parse the RSA public key: expected a PKIX public key, a PKCS#1 public key or a certificate")
}

// jwtVerifyAnyHS256 verifies the signature against every candidate secret.
func jwtVerifyAnyHS256(parsed *parsedJWT, secrets [][]byte) bool {
	for _, secret := range secrets {
		if jwtVerifyHS256(parsed, secret) {
			return true
		}
	}
	return false
}
