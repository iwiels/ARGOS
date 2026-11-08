package tools

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/iwiels/argos-auditor/argos-bin/cmd/web/tools/rules"
)

func parseJSONL(out string, fn func(map[string]interface{})) {
	for _, l := range lines(out) {
		var m map[string]interface{}
		if json.Unmarshal([]byte(l), &m) == nil {
			fn(m)
		}
	}
}

// parseNuclei reads the nuclei JSONL output.
//
// The JSONL carries far more than the template name: the classification
// block declares the CWE, the CVE, the CVSS vector and the OWASP category of
// the template, and the info block declares its severity, its tags, its
// remediation and its references. Everything the registry knows about the
// template is used as a fallback, so a finding leaves the scanner with a
// complete taxonomy instead of a title and a URL.
func parseNuclei(out, target, sourceTool string) []Finding {
	var fs []Finding
	parseJSONL(out, func(m map[string]interface{}) {
		info, _ := m["info"].(map[string]interface{})
		name := mapString(info, "name")
		templateID := mapString(m, "template-id")
		matched := mapString(m, "matched-at")
		if matched == "" {
			matched = target
		}
		classification, _ := info["classification"].(map[string]interface{})
		metadata := infoMetadata(info)

		ruleID := ""
		if templateID != "" {
			ruleID = "nuclei:" + templateID
		}
		registryRule, hasRegistry := rules.Lookup(ruleID)

		tags := nucleiTags(info, registryRule, hasRegistry)
		severity := nucleiSeverity(classification, info, registryRule, hasRegistry)
		cwe := nucleiCWE(classification, registryRule, hasRegistry, tags)

		evidence := map[string]any{}
		if templateID != "" {
			evidence["template"] = templateID
		}
		for _, key := range []string{"type", "host", "ip", "matcher-name"} {
			if value := mapString(m, key); value != "" {
				evidence[strings.ReplaceAll(key, "-", "_")] = value
			}
		}
		if extracted, ok := m["extracted-results"]; ok {
			evidence["extracted_results"] = extracted
		}
		if cve := mapString(classification, "cve-id"); cve != "" {
			evidence["cve"] = cve
		}
		if score, ok := nucleiCvssScore(classification); ok {
			evidence["cvss_score"] = score
		}
		// Argos metadata of the bundled packs: the pack that produced the
		// finding, what evidence it expects and whether the probe needs a
		// session to be conclusive. It travels with the finding so the report
		// never has to infer it.
		if pack := mapString(metadata, "argos-pack"); pack != "" {
			evidence["pack"] = pack
		}
		if expected := mapString(metadata, "argos-evidence"); expected != "" {
			evidence["expected_evidence"] = expected
		}
		if requires := mapString(metadata, "argos-requires-auth"); requires != "" {
			evidence["requires_auth"] = requires == "true"
		}

		references := stringList(info["reference"])

		owasp := stringList(classification["owasp"])
		if len(owasp) == 0 {
			if category := mapString(metadata, "argos-owasp"); category != "" {
				owasp = []string{category}
			}
		}

		fs = append(fs, Finding{
			Source:      sourceTool,
			SourceTool:  sourceTool,
			RuleID:      ruleID,
			Title:       name,
			Severity:    severity,
			Confidence:  nucleiConfidence(m, severity, registryRule, hasRegistry),
			CWE:         cwe,
			OWASP:       owasp,
			Target:      target,
			Vector:      matched,
			Evidence:    evidence,
			Remediation: mapString(info, "remediation"),
			CVSS:        parseCvssVectorString(mapString(classification, "cvss-metrics")),
			Tags:        tags,
			References:  references,
		})
	})
	return fs
}

// infoMetadata returns the metadata block of a nuclei info object.
func infoMetadata(info map[string]any) map[string]any {
	metadata, _ := info["metadata"].(map[string]interface{})
	return metadata
}

// firstCWE reads the CWE declared by a nuclei template classification. The
// field may hold a single id or a list of them.
func firstCWE(classification map[string]any) string {
	if classification == nil {
		return ""
	}
	values := stringList(classification["cwe-id"])
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// nucleiCvssScore reads the CVSS base score a template declares.
func nucleiCvssScore(classification map[string]any) (float64, bool) {
	if classification == nil {
		return 0, false
	}
	switch value := classification["cvss-score"].(type) {
	case float64:
		return value, true
	case string:
		var score float64
		if _, err := fmt.Sscanf(value, "%g", &score); err == nil {
			return score, true
		}
	}
	return 0, false
}

// nucleiSeverity resolves the severity of a nuclei finding.
//
// The order matters and never invents a level:
//  1. the CVSS score the template declares — it is the only value that maps
//     onto a CVSS severity band;
//  2. the severity the classification declares;
//  3. the floor the registry guarantees for the rule;
//  4. the severity the template declares;
//  5. "info" as the last resort.
//
// The registry floor is a floor, not a cap: it may raise a severity that the
// template understates, never lower one it declares.
func nucleiSeverity(classification, info map[string]any, rule rules.Rule, hasRule bool) string {
	floor := ""
	if hasRule {
		floor = rule.SeverityFloor
	}
	// The Argos packs declare their own floor. It is a floor like the registry
	// one: it can raise a severity the template understates, never lower one it
	// declares.
	if raw := mapString(infoMetadata(info), "argos-severity-floor"); raw != "" {
		candidate := normalizeSeverity(raw)
		if floor == "" || severityRank(candidate) > severityRank(floor) {
			floor = candidate
		}
	}

	resolved := ""
	cvssScore, hasCvssScore := nucleiCvssScore(classification)
	switch {
	case hasCvssScore:
		resolved = severityFromCvssScore(cvssScore)
	case mapString(classification, "severity") != "":
		resolved = normalizeSeverity(mapString(classification, "severity"))
	case floor != "":
		resolved = floor
	case mapString(info, "severity") != "":
		resolved = normalizeSeverity(mapString(info, "severity"))
	default:
		resolved = SeverityInfo
	}

	if floor != "" && severityRank(resolved) < severityRank(floor) {
		resolved = floor
	}
	return resolved
}

// severityFromCvssScore maps a CVSS base score onto the canonical severity.
func severityFromCvssScore(score float64) string {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// severityRank orders the canonical severities so a floor can be compared
// against a declared severity.
func severityRank(severity string) int {
	switch severity {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// nucleiCWE resolves the CWE of a nuclei finding. The template classification
// wins, then the registry, then the CWE the canonical tags imply. When none
// of them knows, the CWE stays empty: an invented identifier would make the
// compliance and ATT&CK engines match a finding that does not exist.
func nucleiCWE(classification map[string]any, rule rules.Rule, hasRule bool, tags []string) string {
	if cwe := normalizeCWE(firstCWE(classification)); cwe != "" {
		return cwe
	}
	if hasRule {
		for _, candidate := range rule.CWE {
			if cwe := normalizeCWE(candidate); cwe != "" {
				return cwe
			}
		}
	}
	for _, tag := range tags {
		if cwe := normalizeCWE(rules.CWEForTag(tag)); cwe != "" {
			return cwe
		}
	}
	return ""
}

// nucleiConfidence resolves the confidence of a nuclei finding.
//
// "confirmed" means the tool asserted the condition deterministically: it
// extracted the matched content, or the template matched an explicit word,
// regex or dsl assertion on the response. A match on the status code alone
// is "probable". An informational finding with no content confirmation is
// "possible" — an exposure without a demonstrated impact.
func nucleiConfidence(m map[string]interface{}, severity string, rule rules.Rule, hasRule bool) string {
	if extracted, ok := m["extracted-results"].([]interface{}); ok && len(extracted) > 0 {
		return ConfidenceConfirmed
	}
	if severity == SeverityInfo {
		return ConfidencePossible
	}
	if hasRule && rule.Matcher == "content" {
		return ConfidenceConfirmed
	}
	return ConfidenceProbable
}

// nucleiTags merges the tags of the template with the ones the registry
// declares for the rule. The template tags are filtered against the canonical
// vocabulary: a tag the compliance and ATT&CK engines do not know would
// never match anything.
func nucleiTags(info map[string]any, rule rules.Rule, hasRule bool) []string {
	raw, _ := info["tags"].([]any)
	tags := stringList(raw)

	out := make([]string, 0, len(tags)+len(rule.Tags))
	for _, tag := range tags {
		lowered := strings.ToLower(strings.TrimSpace(tag))
		if rules.IsCanonicalTag(lowered) {
			out = append(out, lowered)
		}
	}
	if hasRule {
		out = append(out, rule.Tags...)
	}
	return dedupeTags(out)
}

// httpx (JSONL): url, status_code, title, tech, webserver
type httpxResult struct {
	URL         string   `json:"url"`
	StatusCode  int      `json:"status_code"`
	Title       string   `json:"title"`
	Tech        []string `json:"tech"`
	Webserver   string   `json:"webserver"`
	FinalURL    string   `json:"final_url"`
	ContentType string   `json:"content_type"`
}

func parseHttpx(out string) []httpxResult {
	var res []httpxResult
	parseJSONL(out, func(m map[string]interface{}) {
		raw, err := json.Marshal(m)
		if err != nil {
			return
		}
		var r httpxResult
		if json.Unmarshal(raw, &r) == nil && r.URL != "" {
			res = append(res, r)
		}
	})
	return res
}

// ffuf (JSONL): input.FUZZ, status, length, url
type ffufResult struct {
	Input  map[string]string `json:"input"`
	Status int               `json:"status"`
	Length int               `json:"length"`
	URL    string            `json:"url"`
}

func parseFfuf(out string) []ffufResult {
	var res []ffufResult
	parseJSONL(out, func(m map[string]interface{}) {
		raw, err := json.Marshal(m)
		if err != nil {
			return
		}
		var r ffufResult
		if json.Unmarshal(raw, &r) == nil && r.URL != "" {
			if fuzz, ok := r.Input["FUZZ"]; ok {
				// ffuf -json base64-encodes input values
				r.Input["FUZZ"] = decodeFfufInput(fuzz)
			}
			res = append(res, r)
		}
	})
	return res
}

// extractJSONObject returns the balanced JSON object starting at start, or "".
func extractJSONObject(s string, start int) string {
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// decodeFfufInput decodes the base64 value ffuf emits for wordlist entries;
// plain strings are returned unchanged.
func decodeFfufInput(s string) string {
	if s == "" {
		return s
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b)
	}
	return s
}

// subfinder (JSONL): host, source
type subfinderResult struct {
	Host   string `json:"host"`
	Source string `json:"source"`
}

func parseSubfinder(out string) []subfinderResult {
	var res []subfinderResult
	parseJSONL(out, func(m map[string]interface{}) {
		raw, err := json.Marshal(m)
		if err != nil {
			return
		}
		var r subfinderResult
		if json.Unmarshal(raw, &r) == nil && r.Host != "" {
			res = append(res, r)
		}
	})
	return res
}

// dnsx (JSONL): host, a, aaaa, cname
func parseDnsx(out string) map[string][]string {
	res := map[string][]string{}
	parseJSONL(out, func(m map[string]interface{}) {
		host, _ := m["host"].(string)
		if host == "" {
			return
		}
		if a, ok := m["a"].(string); ok && a != "" {
			res[host] = append(res[host], a)
		}
		if arr, ok := m["a"].([]interface{}); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok && s != "" {
					res[host] = append(res[host], s)
				}
			}
		}
	})
	return res
}

// katana (JSONL): request.endpoint, response.status_code
func parseKatana(out string) []httpxResult {
	var res []httpxResult
	parseJSONL(out, func(m map[string]interface{}) {
		req, _ := m["request"].(map[string]interface{})
		resp, _ := m["response"].(map[string]interface{})
		endpoint, _ := req["endpoint"].(string)
		if endpoint == "" {
			return
		}
		status, _ := resp["status_code"].(float64)
		res = append(res, httpxResult{URL: endpoint, StatusCode: int(status)})
	})
	return res
}

// dalfoxFinding is one entry of the v3 `--format json` output:
// { "findings": [ {...} ] }
type dalfoxFinding struct {
	Type             string `json:"type"`
	TypeDescription  string `json:"type_description"`
	Severity         string `json:"severity"`
	Confidence       string `json:"confidence"`
	ConfidenceReason string `json:"confidence_reason"`
	CWE              string `json:"cwe"`
	Data             string `json:"data"`
	Payload          string `json:"payload"`
	Param            string `json:"param"`
	Method           string `json:"method"`
	InjectType       string `json:"inject_type"`
	DetectionMethod  string `json:"detection_method"`
}

// parseDalfox handles both dalfox v3 (`{"findings":[...]}`) and the legacy
// JSONL shape (`{"type":...,"data":{...}}`).
func parseDalfox(out, target string) []Finding {
	var v3 struct {
		Findings []dalfoxFinding `json:"findings"`
	}
	if json.Unmarshal([]byte(out), &v3) != nil {
		// v3 object may be preceded/followed by non-JSON (stats, warnings):
		// scan for the findings object instead of failing wholesale
		if i := strings.Index(out, `{"findings"`); i >= 0 {
			if candidate := extractJSONObject(out, i); candidate != "" {
				if json.Unmarshal([]byte(candidate), &v3) != nil {
					v3.Findings = nil
				}
			}
		}
	}
	if len(v3.Findings) > 0 {
		var fs []Finding
		for _, f := range v3.Findings {
			sev := f.Severity
			if sev == "" {
				sev = "info"
			}
			url := f.Data
			if url == "" {
				url = target
			}
			evidence := map[string]any{}
			for key, value := range map[string]string{
				"param":             f.Param,
				"payload":           f.Payload,
				"method":            f.Method,
				"inject_type":       f.InjectType,
				"detection_method":  f.DetectionMethod,
				"confidence":        f.Confidence,
				"confidence_reason": f.ConfidenceReason,
				"type":              f.Type,
			} {
				if value != "" {
					evidence[key] = value
				}
			}
			fs = append(fs, Finding{
				Source:     "web.xss",
				SourceTool: "web.xss",
				RuleID:     dalfoxRuleID(f.Type),
				Title:      "XSS: " + f.Type,
				Severity:   normalizeSeverity(sev),
				Confidence: dalfoxConfidence(f.Type),
				CWE:        normalizeCWE(f.CWE),
				Target:     url,
				Vector:     f.Param,
				Evidence:   evidence,
				Tags:       []string{"xss"},
			})
		}
		return fs
	}
	// legacy JSONL: type, data{type,severity,payload,url,cwe,param}
	var fs []Finding
	parseJSONL(out, func(m map[string]interface{}) {
		data, _ := m["data"].(map[string]interface{})
		sev := mapString(data, "severity")
		fType := mapString(data, "type")
		if sev == "" {
			sev = "info"
		}
		url := mapString(data, "url")
		if url == "" {
			url = target
		}
		evidence := map[string]any{}
		if payload := mapString(data, "payload"); payload != "" {
			evidence["payload"] = truncateStr(payload, 200)
		}
		if param := mapString(data, "param"); param != "" {
			evidence["param"] = param
		}
		fs = append(fs, Finding{
			Source:     "web.xss",
			SourceTool: "web.xss",
			RuleID:     dalfoxRuleID(fType),
			Title:      "XSS: " + fType,
			Severity:   normalizeSeverity(sev),
			Confidence: dalfoxConfidence(fType),
			CWE:        normalizeCWE(mapString(data, "cwe")),
			Target:     url,
			Vector:     mapString(data, "param"),
			Evidence:   evidence,
			Tags:       []string{"xss"},
		})
	})
	return fs
}

// dalfoxConfidence reflects dalfox's own verdict: type "V" means the payload
// was verified as executable, the other types are unverified reflections.
func dalfoxConfidence(findingType string) string {
	if strings.EqualFold(strings.TrimSpace(findingType), "V") {
		return normalizeConfidence(ConfidenceConfirmed)
	}
	return normalizeConfidence(ConfidenceProbable)
}

// dalfoxRuleID keeps dalfox's finding type as a stable rule identifier.
func dalfoxRuleID(findingType string) string {
	findingType = strings.TrimSpace(findingType)
	if findingType == "" {
		return ""
	}
	return "dalfox:" + findingType
}

// gau: one URL per line
func parseGau(out string, limit int) []string {
	urls := lines(out)
	if len(urls) > limit {
		urls = urls[:limit]
	}
	return urls
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
