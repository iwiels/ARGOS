package tools

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"
)

// jwtTestToken builds a JWS compact serialization out of a header and claims.
func jwtTestToken(t *testing.T, header map[string]any, claims map[string]any, signature string) string {
	t.Helper()
	encode := func(value map[string]any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("cannot encode the segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return encode(header) + "." + encode(claims) + "." + signature
}

// jwtHasRule reports whether the findings carry the rule.
func jwtHasRule(findings []Finding, rule string) bool {
	for _, finding := range findings {
		if finding.RuleID == rule {
			return true
		}
	}
	return false
}

func TestJWTAlgNoneIsDetected(t *testing.T) {
	token := jwtTestToken(t,
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{"sub": "1", "role": "admin"},
		"",
	)
	parsed, err := parseJWT(token)
	if err != nil {
		t.Fatalf("cannot parse the token: %v", err)
	}
	analysis, err := analyzeJWT(parsed, "", "", time.Now())
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	if !jwtHasRule(analysis.findings, "jwt:alg-none") {
		t.Fatalf("expected the alg:none finding, got %+v", analysis.findings)
	}
	for _, finding := range analysis.findings {
		if finding.RuleID == "jwt:alg-none" {
			if finding.Confidence != ConfidenceConfirmed {
				t.Errorf("alg:none confidence = %q, want confirmed", finding.Confidence)
			}
			if finding.CWE != "CWE-347" {
				t.Errorf("alg:none cwe = %q, want CWE-347", finding.CWE)
			}
			if finding.Severity != SeverityCritical {
				t.Errorf("alg:none severity = %q, want critical", finding.Severity)
			}
		}
	}
}

func TestJWTSaneTokenProducesNoFindings(t *testing.T) {
	now := time.Now()
	token := jwtTestToken(t,
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": "key-2026-01"},
		map[string]any{
			"sub": "42",
			"iss": "https://issuer.example",
			"aud": "my-service",
			"iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(),
		},
		"c2lnbmF0dXJlLXBsYWNlaG9sZGVy",
	)
	parsed, err := parseJWT(token)
	if err != nil {
		t.Fatalf("cannot parse the token: %v", err)
	}
	analysis, err := analyzeJWT(parsed, "", "", now)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	if len(analysis.findings) != 0 {
		t.Fatalf("expected no findings for a sane token, got %d: %+v", len(analysis.findings), analysis.findings)
	}
}

func TestJWTExpiredTokenIsDetected(t *testing.T) {
	now := time.Now()
	token := jwtTestToken(t,
		map[string]any{"alg": "RS256", "typ": "JWT"},
		map[string]any{
			"sub": "42",
			"iss": "https://issuer.example",
			"aud": "my-service",
			"exp": now.Add(-time.Hour).Unix(),
		},
		"c2lnbmF0dXJlLXBsYWNlaG9sZGVy",
	)
	parsed, err := parseJWT(token)
	if err != nil {
		t.Fatalf("cannot parse the token: %v", err)
	}
	analysis, err := analyzeJWT(parsed, "", "", now)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	if !jwtHasRule(analysis.findings, "jwt:expired") {
		t.Fatalf("expected the expired finding, got %+v", analysis.findings)
	}
}

func TestJWTAlgorithmConfusionIsDetected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate the RSA key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
	})

	now := time.Now()
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "1",
		"iss": "https://issuer.example",
		"aud": "my-service",
		"exp": now.Add(time.Hour).Unix(),
	}
	encode := func(value map[string]any) string {
		raw, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := encode(header) + "." + encode(claims)

	// The confusion attack signs with the public key of the issuer as the
	// shared secret.
	mac := hmac.New(sha256.New, publicPEM)
	mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	parsed, err := parseJWT(signingInput + "." + signature)
	if err != nil {
		t.Fatalf("cannot parse the token: %v", err)
	}
	analysis, err := analyzeJWT(parsed, "", string(publicPEM), now)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	if !jwtHasRule(analysis.findings, "jwt:alg-confusion") {
		t.Fatalf("expected the algorithm confusion finding, got %+v", analysis.findings)
	}
}

func TestJWTSignatureIsVerifiedWithTheSuppliedSecret(t *testing.T) {
	secret := "a-very-long-and-random-shared-secret"
	now := time.Now()
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{
		"sub": "1",
		"iss": "https://issuer.example",
		"aud": "my-service",
		"exp": now.Add(time.Hour).Unix(),
	}
	encode := func(value map[string]any) string {
		raw, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := encode(header) + "." + encode(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	parsed, err := parseJWT(signingInput + "." + signature)
	if err != nil {
		t.Fatalf("cannot parse the token: %v", err)
	}
	analysis, err := analyzeJWT(parsed, secret, "", now)
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	if verified, _ := analysis.signature["verified"].(bool); !verified {
		t.Fatalf("expected the signature to be verified, got %+v", analysis.signature)
	}
	if len(analysis.findings) != 0 {
		t.Fatalf("expected no findings for a properly signed token, got %+v", analysis.findings)
	}
}

func TestJWTWithoutKeyDoesNotClaimTheSignatureIsValid(t *testing.T) {
	token := jwtTestToken(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "1", "iss": "https://issuer.example", "aud": "svc", "exp": time.Now().Add(time.Hour).Unix()},
		"c2lnbmF0dXJlLXBsYWNlaG9sZGVy",
	)
	parsed, err := parseJWT(token)
	if err != nil {
		t.Fatalf("cannot parse the token: %v", err)
	}
	analysis, err := analyzeJWT(parsed, "", "", time.Now())
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	if verified, _ := analysis.signature["verified"].(bool); verified {
		t.Fatal("the signature must not be reported as verified without a key")
	}
	if method, _ := analysis.signature["method"].(string); method != "not-verified" {
		t.Fatalf("signature method = %q, want not-verified", method)
	}
}
