package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

func RegisterTls(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.tls",
			Description: "TLS/SSL cipher suites, certificate validation, and protocol insecurity analysis powered by tlsx.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":  {Type: "string", Description: "Target host or URL, e.g. https://example.com:443"},
					"fast":    {Type: "boolean", Description: "Run in fast mode (skip slower vulnerability tests, default false)"},
					"timeout": {Type: "integer", Description: "Execution timeout in seconds (default 180, max 300)"},
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
				Target  string `json:"target"`
				Fast    bool   `json:"fast"`
				Timeout int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}

			timeout := clampTimeout(input.Timeout, 180)

			bin, installed, e := env.Binary(toolContext(ctx), "tlsx")
			if e != nil {
				return nil, e
			}

			args := []string{"-u", target, "-san", "-cn", "-tls-version", "-cipher", "-resp", "-json"}
			if input.Fast {
				args = []string{"-u", target, "-tls-version", "-cipher", "-json"}
			}

			r := run(toolContext(ctx), bin, runOptions{
				Args:    args,
				Timeout: time.Duration(timeout) * time.Second,
			})

			var fs []Finding
			if r.Output != "" {
				fs = parseTlsxJSON([]byte(r.Output), target)
			}
			if len(fs) == 0 && r.Output != "" {
				fs = parseTestsslJSON([]byte(r.Output), target)
			}

			fs, truncated := capFindings(fs)
			res := baseResult("web.tls", target, r)
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d TLS issues", len(fs))
			if installed {
				res["installed"] = "tlsx " + env.Spec("tlsx").Version
			}
			// Igual que en web.probe: la request y la response quedan en el
			// store de tráfico para que el auditor pueda reenviarlas y
			// compararlas (solo con la captura encendida).
			if exchange, ok := captureTrafficExchange(ctx, env, "web.tls", trafficProbeURL(input.Target)); ok {
				res["exchange_id"] = exchange.ID
			}
			return res, nil
		},
	)
}

type tlsxResponse struct {
	Timestamp           string   `json:"timestamp"`
	Host                string   `json:"host"`
	Port                string   `json:"port"`
	ProbeStatus         bool     `json:"probe_status"`
	Version             string   `json:"tls_version"`
	Cipher              string   `json:"cipher"`
	SubjectCN           string   `json:"subject_cn"`
	SubjectAN           []string `json:"subject_an"`
	IssuerCN            string   `json:"issuer_cn"`
	IssuerOrg           []string `json:"issuer_org"`
	Expired             bool     `json:"expired"`
	SelfSigned          bool     `json:"self_signed"`
	Misconfigured       bool     `json:"misconfigured"`
	Revoked             bool     `json:"revoked"`
	Untrusted           bool     `json:"untrusted"`
	WildcardCertificate bool     `json:"wildcard_certificate"`
}

func parseTlsxJSON(data []byte, target string) []Finding {
	var entries []tlsxResponse
	if err := json.Unmarshal(data, &entries); err != nil {
		lines := strings.Split(string(data), "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" || !strings.HasPrefix(l, "{") {
				continue
			}
			var single tlsxResponse
			if err := json.Unmarshal([]byte(l), &single); err == nil && (single.Host != "" || single.Version != "") {
				entries = append(entries, single)
			}
		}
	}

	var fs []Finding
	for _, e := range entries {
		host := e.Host
		if host == "" {
			host = target
		}
		certEvidence := func(extra map[string]any) map[string]any {
			evidence := map[string]any{
				"subject_cn": e.SubjectCN,
				"issuer_cn":  e.IssuerCN,
				"protocol":   e.Version,
				"cipher":     e.Cipher,
			}
			for key, value := range extra {
				evidence[key] = value
			}
			return evidence
		}
		if e.Expired {
			fs = append(fs, Finding{
				Source:     "web.tls",
				SourceTool: "web.tls",
				RuleID:     "tlsx:expired-certificate",
				Title:      "Expired SSL/TLS Certificate",
				Severity:   SeverityHigh,
				Confidence: ConfidenceConfirmed,
				Target:     host,
				Evidence:   certEvidence(map[string]any{"expired": true}),
				Tags:       []string{"tls", "invalid-cert"},
			})
		}
		if e.Revoked {
			fs = append(fs, Finding{
				Source:     "web.tls",
				SourceTool: "web.tls",
				RuleID:     "tlsx:revoked-certificate",
				Title:      "Revoked SSL/TLS Certificate",
				Severity:   SeverityHigh,
				Confidence: ConfidenceConfirmed,
				Target:     host,
				Evidence:   certEvidence(map[string]any{"revoked": true}),
				Tags:       []string{"tls", "invalid-cert"},
			})
		}
		if e.SelfSigned {
			fs = append(fs, Finding{
				Source:     "web.tls",
				SourceTool: "web.tls",
				RuleID:     "tlsx:self-signed-certificate",
				Title:      "Self-Signed SSL/TLS Certificate",
				Severity:   SeverityMedium,
				Confidence: ConfidenceConfirmed,
				Target:     host,
				Evidence:   certEvidence(map[string]any{"self_signed": true}),
				Tags:       []string{"tls", "self-signed"},
			})
		}
		if e.Misconfigured || e.Untrusted {
			fs = append(fs, Finding{
				Source:     "web.tls",
				SourceTool: "web.tls",
				RuleID:     "tlsx:untrusted-certificate",
				Title:      "Untrusted or Misconfigured SSL/TLS Certificate",
				Severity:   SeverityMedium,
				Confidence: ConfidenceConfirmed,
				Target:     host,
				Evidence:   certEvidence(map[string]any{"misconfigured": e.Misconfigured, "untrusted": e.Untrusted}),
				Tags:       []string{"tls", "invalid-cert"},
			})
		}
		v := strings.ToLower(e.Version)
		if v != "" {
			if strings.Contains(v, "ssl") || v == "tls10" || v == "tls1.0" {
				fs = append(fs, Finding{
					Source:     "web.tls",
					SourceTool: "web.tls",
					RuleID:     "tlsx:deprecated-protocol",
					Title:      fmt.Sprintf("Deprecated TLS Protocol: %s", e.Version),
					Severity:   SeverityHigh,
					Confidence: ConfidenceConfirmed,
					Target:     host,
					Evidence:   certEvidence(map[string]any{"protocol": e.Version}),
					Tags:       []string{"tls", "weak-crypto"},
				})
			} else if v == "tls11" || v == "tls1.1" {
				fs = append(fs, Finding{
					Source:     "web.tls",
					SourceTool: "web.tls",
					RuleID:     "tlsx:deprecated-protocol",
					Title:      fmt.Sprintf("Deprecated TLS Protocol: %s", e.Version),
					Severity:   SeverityMedium,
					Confidence: ConfidenceConfirmed,
					Target:     host,
					Evidence:   certEvidence(map[string]any{"protocol": e.Version}),
					Tags:       []string{"tls", "weak-crypto"},
				})
			}
		}
		c := strings.ToUpper(e.Cipher)
		if c != "" {
			if strings.Contains(c, "RC4") || strings.Contains(c, "DES") || strings.Contains(c, "MD5") || strings.Contains(c, "NULL") || strings.Contains(c, "EXPORT") {
				fs = append(fs, Finding{
					Source:     "web.tls",
					SourceTool: "web.tls",
					RuleID:     "tlsx:weak-cipher",
					Title:      fmt.Sprintf("Weak Cipher Suite: %s", e.Cipher),
					Severity:   SeverityHigh,
					Confidence: ConfidenceConfirmed,
					Target:     host,
					Evidence:   certEvidence(map[string]any{"cipher": e.Cipher}),
					Tags:       []string{"tls", "weak-cipher"},
				})
			} else if strings.Contains(c, "CBC") {
				fs = append(fs, Finding{
					Source:     "web.tls",
					SourceTool: "web.tls",
					RuleID:     "tlsx:cbc-cipher",
					Title:      fmt.Sprintf("CBC Cipher Suite: %s", e.Cipher),
					Severity:   SeverityLow,
					Confidence: ConfidenceConfirmed,
					Target:     host,
					Evidence:   certEvidence(map[string]any{"cipher": e.Cipher}),
					Tags:       []string{"tls", "weak-cipher"},
				})
			}
		}
	}
	return fs
}

type testsslEntry struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	Cve      string `json:"cve,omitempty"`
}

func mapTestsslSeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "high"
	case "WARN", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "info"
	}
}

func parseTestsslJSON(data []byte, target string) []Finding {
	var entries []testsslEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		lines := strings.Split(string(data), "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" || !strings.HasPrefix(l, "{") {
				continue
			}
			var single testsslEntry
			if err := json.Unmarshal([]byte(l), &single); err == nil && single.ID != "" {
				entries = append(entries, single)
			}
		}
	}

	var fs []Finding
	for _, e := range entries {
		sevUpper := strings.ToUpper(e.Severity)
		if sevUpper == "OK" || e.Finding == "" || e.Severity == "" {
			continue
		}
		sev := mapTestsslSeverity(e.Severity)
		title := fmt.Sprintf("TLS Issue (%s): %s", e.ID, e.Finding)
		evidence := map[string]any{
			"check":   e.ID,
			"finding": e.Finding,
			"raw":     e.Severity,
		}
		if e.Cve != "" {
			evidence["cve"] = e.Cve
		}
		fs = append(fs, Finding{
			Source:     "web.tls",
			SourceTool: "web.tls",
			RuleID:     "testssl:" + e.ID,
			Title:      title,
			Severity:   sev,
			Confidence: ConfidenceConfirmed,
			Target:     target,
			Evidence:   evidence,
			Tags:       testsslTags(e.ID),
		})
	}
	return fs
}

// testsslTags maps a testssl check id onto the canonical crypto vocabulary.
func testsslTags(id string) []string {
	switch strings.ToLower(id) {
	case "SSLv2", "SSLv3", "TLS1_0", "TLS1_1", "TLS1_2", "TLS1_3":
		return []string{"tls"}
	case "cipher_order", "cipher_strength":
		return []string{"tls", "weak-cipher"}
	case "cert_chain_of_trust", "cert_expiration", "cert_trust":
		return []string{"tls", "invalid-cert"}
	}
	return []string{"tls"}
}
