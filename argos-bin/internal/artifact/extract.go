package artifact

import (
	"regexp"
	"strings"

	"github.com/iwiels/argos-auditor/argos-bin/internal/beautify"
)

type SecretFinding struct {
	Type  string `json:"type"`
	Match string `json:"match"`
	Line  int    `json:"line"`
}

type ExtractedIntelligence struct {
	Endpoints []string        `json:"endpoints"`
	Secrets   []SecretFinding `json:"secrets"`
	SourceMap string          `json:"sourcemap,omitempty"`
}

var (
	endpointRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)["'\x60](/(api|v[0-9]+|rest|graphql|admin|auth|oauth|users|login|logout|upload|download)/[a-zA-Z0-9_\-\./]+)["'\x60]`),
		regexp.MustCompile(`(?i)(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.ajax|\$\.get|\$\.post)\s*\(\s*["'\x60]([^"'\x60\s]+)["'\x60]`),
	}

	secretPatterns = []struct {
		Name  string
		Regex *regexp.Regexp
	}{
		{"AWS Access Key ID", regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)},
		{"Google API Key", regexp.MustCompile(`\b(AIza[0-9A-Za-z-_]{35})\b`)},
		{"GitHub Token", regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36})\b`)},
		{"Stripe API Key", regexp.MustCompile(`\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,})\b`)},
		{"Slack Token", regexp.MustCompile(`\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b`)},
		{"JWT Token", regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)\b`)},
		{"Generic Bearer Token", regexp.MustCompile(`(?i)\bBearer\s+([a-zA-Z0-9_\-\.]{25,})\b`)},
		{"Private Key", regexp.MustCompile(`(-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP|PRIVATE) KEY-----)`)},
	}

	sourceMapRegex = regexp.MustCompile(`(?i)(?://|/\*)[#@]\s*sourceMappingURL=([^\s\*]+)`)
)

func Extract(content string, _ beautify.Language) ExtractedIntelligence {
	endpointsMap := make(map[string]bool)
	var endpoints []string
	var secrets []SecretFinding

	lines := strings.Split(content, "\n")
	var sourceMap string

	for lineNum, line := range lines {
		// Endpoints
		for _, re := range endpointRegexes {
			matches := re.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				if len(m) > 1 {
					ep := m[1]
					if len(ep) > 1 && !endpointsMap[ep] && !isNoiseEndpoint(ep) {
						endpointsMap[ep] = true
						endpoints = append(endpoints, ep)
					}
				}
			}
		}

		// Secrets
		for _, sp := range secretPatterns {
			matches := sp.Regex.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				if len(m) > 1 {
					val := m[1]
					secrets = append(secrets, SecretFinding{
						Type:  sp.Name,
						Match: maskSecret(val),
						Line:  lineNum + 1,
					})
				}
			}
		}

		// SourceMap
		if sourceMap == "" {
			if sm := sourceMapRegex.FindStringSubmatch(line); len(sm) > 1 {
				sourceMap = strings.TrimSuffix(sm[1], "*/")
				sourceMap = strings.TrimSpace(sourceMap)
			}
		}
	}

	return ExtractedIntelligence{
		Endpoints: endpoints,
		Secrets:   secrets,
		SourceMap: sourceMap,
	}
}

func isNoiseEndpoint(ep string) bool {
	lower := strings.ToLower(ep)
	if strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".svg") || strings.HasSuffix(lower, ".ico") || strings.HasSuffix(lower, ".woff2") {
		return true
	}
	return false
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "******"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
