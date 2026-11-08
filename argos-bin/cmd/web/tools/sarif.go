package tools

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SARIF v2.1.0 — the subset the scanners emit, plus the parts that carry the
// signal the backend needs (code flows, fingerprints, taxonomies,
// suppressions). Anything the parser does not know about is ignored instead
// of failing the scan: a scanner adding a field must not break ingestion.

const (
	// sarifMaxTitleChars bounds the title taken from the engine message; the
	// canonical contract caps it at 512 characters.
	sarifMaxTitleChars = 512
	// sarifMaxSnippetChars bounds the source snippet kept as evidence.
	sarifMaxSnippetChars = 512
	// sarifMaxReferences bounds the reference list of a finding.
	sarifMaxReferences = 16
)

type SarifReport struct {
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version,omitempty"`
	Rules   []SarifRule `json:"rules,omitempty"`
}

type SarifRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name,omitempty"`
	ShortDescription     *SarifMessage    `json:"shortDescription,omitempty"`
	FullDescription      *SarifMessage    `json:"fullDescription,omitempty"`
	HelpURI              string           `json:"helpUri,omitempty"`
	DefaultConfiguration *SarifRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties           *SarifProperties `json:"properties,omitempty"`
}

type SarifRuleConfig struct {
	Level string `json:"level,omitempty"`
}

type SarifResult struct {
	RuleID              string              `json:"ruleId"`
	RuleIndex           int                 `json:"ruleIndex,omitempty"`
	Level               string              `json:"level,omitempty"`
	Kind                string              `json:"kind,omitempty"`
	Message             SarifMessage        `json:"message"`
	Locations           []SarifLocation     `json:"locations,omitempty"`
	RelatedLocations    []SarifLocation     `json:"relatedLocations,omitempty"`
	CodeFlows           []SarifCodeFlow     `json:"codeFlows,omitempty"`
	Fingerprints        map[string]string   `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string   `json:"partialFingerprints,omitempty"`
	Suppressions        []SarifSuppression  `json:"suppressions,omitempty"`
	Fixes               []SarifFix          `json:"fixes,omitempty"`
	Taxonomies          []SarifTaxonomy     `json:"taxonomies,omitempty"`
	Relationships       []SarifRelationship `json:"relationships,omitempty"`
	Properties          *SarifProperties    `json:"properties,omitempty"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

// SarifProperties carries the engine-specific metadata (semgrep rule tags,
// trivy precision, the numeric security score) that decides how much the
// result can be trusted.
type SarifProperties struct {
	Tags             []string        `json:"tags,omitempty"`
	Precision        string          `json:"precision,omitempty"`
	SecuritySeverity json.RawMessage `json:"security-severity,omitempty"`
	CvssScore        json.RawMessage `json:"cvssScore,omitempty"`
	CvssVector       string          `json:"cvssVector,omitempty"`
	Cwe              []string        `json:"cwe,omitempty"`
	Owasp            []string        `json:"owasp,omitempty"`
	References       []string        `json:"references,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation *SarifPhysicalLocation `json:"physicalLocation,omitempty"`
	Message          *SarifMessage          `json:"message,omitempty"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation *SarifArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *SarifRegion           `json:"region,omitempty"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int                   `json:"startLine,omitempty"`
	EndLine   int                   `json:"endLine,omitempty"`
	Snippet   *SarifArtifactContent `json:"snippet,omitempty"`
}

type SarifArtifactContent struct {
	Text string `json:"text"`
}

// SarifCodeFlow is the taint path of a result: the ordered source →
// propagators → sink chain that explains why the engine flagged it.
type SarifCodeFlow struct {
	Message     SarifMessage      `json:"message,omitempty"`
	ThreadFlows []SarifThreadFlow `json:"threadFlows,omitempty"`
}

type SarifThreadFlow struct {
	Locations []SarifThreadFlowLocation `json:"locations,omitempty"`
}

type SarifThreadFlowLocation struct {
	Location   *SarifLocation `json:"location,omitempty"`
	Importance string         `json:"importance,omitempty"`
}

// SarifSuppression marks a result as a known false positive.
type SarifSuppression struct {
	Kind          string `json:"kind,omitempty"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type SarifFix struct {
	Description     *SarifMessage         `json:"description,omitempty"`
	ArtifactChanges []SarifArtifactChange `json:"artifactChanges,omitempty"`
}

type SarifArtifactChange struct {
	ArtifactLocation *SarifArtifactLocation `json:"artifactLocation,omitempty"`
	Replacements     []SarifReplacement     `json:"replacements,omitempty"`
}

type SarifReplacement struct {
	DeletedRegion   *SarifRegion          `json:"deletedRegion,omitempty"`
	InsertedContent *SarifArtifactContent `json:"insertedContent,omitempty"`
}

type SarifTaxonomy struct {
	ID             string              `json:"id,omitempty"`
	Name           string              `json:"name,omitempty"`
	ToolComponent  *SarifToolComponent `json:"toolComponent,omitempty"`
	InformationURI string              `json:"informationUri,omitempty"`
}

type SarifToolComponent struct {
	Name string `json:"name,omitempty"`
	Guid string `json:"guid,omitempty"`
}

// SarifRelationship links a result with another object of the same run
// (typically the CWE taxonomy rule the result maps to).
type SarifRelationship struct {
	TargetObjectID      int                 `json:"targetObjectId,omitempty"`
	TargetToolComponent *SarifToolComponent `json:"targetToolComponent,omitempty"`
	Kinds               []string            `json:"kinds,omitempty"`
}

var (
	// cwePattern matches the CWE identifier inside a tag, a taxonomy id or a
	// rule name ("CWE-89", "CWE-89: Improper Neutralization…").
	cwePattern = regexp.MustCompile(`(?i)cwe[-_ ]?(\d{1,6})`)
	// owaspPattern matches the OWASP identifier of a tag ("OWASP-A03:2021").
	owaspPattern = regexp.MustCompile(`(?i)owasp[^a-z0-9]*(a\d{2}(?::\d{4})?)`)
	// owaspIDPattern matches a bare OWASP identifier ("A03:2021").
	owaspIDPattern = regexp.MustCompile(`(?i)^(a\d{2}:\d{4})$`)
)

// parseSarifReport normalizes a SARIF v2.1.0 document into canonical
// findings. Every run and every result of the document is read: the previous
// parser only looked at runs[0].results[0].locations[0] and dropped the
// taint flow, the fingerprints, the taxonomies and the suppressions.
func parseSarifReport(data []byte, sourceTool string) ([]Finding, error) {
	var report SarifReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decode sarif report: %w", err)
	}

	engine := "semgrep"
	if sourceTool == "code.deps" {
		engine = "trivy"
	}

	var findings []Finding
	for _, run := range report.Runs {
		rules := run.Tool.Driver.Rules
		for _, res := range run.Results {
			// A suppressed result is a result the engine itself already
			// discarded (semgrep keeps the `# nosemgrep` matches in the
			// output). Reporting it again on every run is noise.
			if sarifSuppressed(res) {
				continue
			}
			findings = append(findings, sarifFinding(run, res, rules, engine, sourceTool))
		}
	}
	return findings, nil
}

// sarifFinding converts one SARIF result into a canonical finding.
func sarifFinding(run SarifRun, res SarifResult, rules []SarifRule, engine, sourceTool string) Finding {
	rule := sarifResolveRule(rules, res)
	related := sarifRelatedRules(rules, res)

	locations := sarifLocations(res.Locations)
	primary := ""
	line := 0
	if len(locations) > 0 {
		primary, _ = locations[0]["file"].(string)
		line, _ = locations[0]["line"].(int)
	}

	level := res.Level
	if level == "" && rule != nil && rule.DefaultConfiguration != nil {
		// Semgrep does not repeat the level on every result: it lives in the
		// rule descriptor. Without this fallback every semgrep finding would
		// degrade to "info".
		level = rule.DefaultConfiguration.Level
	}

	score, hasScore := sarifSecurityScore(res, rule)
	severity := sarifSeverity(score, hasScore, level)
	confidence := sarifConfidence(hasScore, sarifPrecision(res, rule))

	title := sarifCleanText(res.Message.Text, sarifMaxTitleChars)
	if title == "" {
		title = res.RuleID
	}

	evidence := map[string]any{
		"rule": res.RuleID,
	}
	if toolName := run.Tool.Driver.Name; toolName != "" {
		evidence["tool"] = toolName
	}
	if res.Message.Text != "" {
		evidence["message"] = res.Message.Text
	}
	if primary != "" {
		evidence["file"] = primary
	}
	if line > 0 {
		evidence["line"] = line
	}
	if len(locations) > 0 {
		evidence["locations"] = locations
	}
	if dataflow := sarifDataflow(res.CodeFlows); len(dataflow) > 0 {
		evidence["dataflow"] = dataflow
	}
	if fingerprints := sarifFingerprints(res); len(fingerprints) > 0 {
		evidence["partialFingerprints"] = fingerprints
	}
	if precision := sarifPrecision(res, rule); precision != "" {
		evidence["precision"] = precision
	}
	if rule != nil && rule.Properties != nil && len(rule.Properties.Tags) > 0 {
		evidence["ruleTags"] = rule.Properties.Tags
	}
	if hasScore {
		evidence["securitySeverity"] = score
	}

	return Finding{
		Source:      sourceTool,
		SourceTool:  sourceTool,
		RuleID:      engine + ":" + res.RuleID,
		Title:       title,
		Severity:    severity,
		Confidence:  confidence,
		CWE:         sarifCwe(res, rule, related),
		OWASP:       sarifOwasp(res, rule, related),
		Target:      primary,
		Vector:      sarifVector(primary, line),
		Evidence:    evidence,
		Remediation: sarifRemediation(res.Fixes),
		CVSS:        sarifCvss(res, rule),
		Tags:        sarifTags(res, sourceTool),
		References:  sarifReferences(res, rule, related),
	}
}

// sarifSuppressed reports whether the engine marked the result as a
// suppressed false positive.
func sarifSuppressed(res SarifResult) bool {
	for _, sup := range res.Suppressions {
		switch strings.ToLower(strings.TrimSpace(sup.Kind)) {
		case "insource", "external":
			return true
		}
	}
	return false
}

// sarifResolveRule finds the descriptor of the rule that produced the
// result: semgrep points at it by id, other engines by index.
func sarifResolveRule(rules []SarifRule, res SarifResult) *SarifRule {
	if res.RuleIndex >= 0 && res.RuleIndex < len(rules) {
		if rules[res.RuleIndex].ID == res.RuleID || res.RuleID == "" {
			return &rules[res.RuleIndex]
		}
	}
	for i := range rules {
		if rules[i].ID == res.RuleID {
			return &rules[i]
		}
	}
	return nil
}

// sarifRelatedRules resolves the objects a result points at through its
// relationships (GitHub encodes the CWE taxonomy that way).
func sarifRelatedRules(rules []SarifRule, res SarifResult) []SarifRule {
	var out []SarifRule
	for _, rel := range res.Relationships {
		if rel.TargetObjectID < 0 || rel.TargetObjectID >= len(rules) {
			continue
		}
		out = append(out, rules[rel.TargetObjectID])
	}
	return out
}

// sarifLocations normalizes every physical location of a result.
func sarifLocations(locations []SarifLocation) []map[string]any {
	var out []map[string]any
	for _, loc := range locations {
		entry := sarifLocationEntry(loc.PhysicalLocation)
		if entry == nil {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// sarifDataflow flattens the code flows into the ordered steps of the taint
// path (source → propagators → sink).
func sarifDataflow(flows []SarifCodeFlow) []map[string]any {
	var steps []map[string]any
	for _, flow := range flows {
		for _, thread := range flow.ThreadFlows {
			for _, loc := range thread.Locations {
				if loc.Location == nil {
					continue
				}
				entry := sarifLocationEntry(loc.Location.PhysicalLocation)
				if entry == nil {
					continue
				}
				if loc.Location.Message != nil && loc.Location.Message.Text != "" {
					entry["message"] = loc.Location.Message.Text
				}
				if loc.Importance != "" {
					entry["importance"] = loc.Importance
				}
				steps = append(steps, entry)
			}
		}
	}
	return steps
}

func sarifLocationEntry(phys *SarifPhysicalLocation) map[string]any {
	if phys == nil {
		return nil
	}
	entry := map[string]any{}
	if phys.ArtifactLocation != nil && phys.ArtifactLocation.URI != "" {
		entry["file"] = phys.ArtifactLocation.URI
	}
	if phys.Region != nil {
		if phys.Region.StartLine > 0 {
			entry["line"] = phys.Region.StartLine
		}
		if phys.Region.EndLine > 0 {
			entry["endLine"] = phys.Region.EndLine
		}
		if phys.Region.Snippet != nil && phys.Region.Snippet.Text != "" {
			entry["snippet"] = truncateStr(phys.Region.Snippet.Text, sarifMaxSnippetChars)
		}
	}
	if len(entry) == 0 {
		return nil
	}
	return entry
}

// sarifFingerprints merges the stable identifiers of a result. Semgrep
// publishes them under "fingerprints" and the rest of the ecosystem under
// "partialFingerprints"; both are the deduplication key between runs.
func sarifFingerprints(res SarifResult) map[string]string {
	out := map[string]string{}
	for key, value := range res.PartialFingerprints {
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	for key, value := range res.Fingerprints {
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	return out
}

// sarifSecurityScore reads the numeric severity score of a result. The
// "security-severity" property is the CVSS base score for trivy and the
// declared score of a rule for semgrep; it is the only quantitative signal a
// SARIF document carries.
func sarifSecurityScore(res SarifResult, rule *SarifRule) (float64, bool) {
	if res.Properties != nil {
		if score, ok := sarifNumber(res.Properties.SecuritySeverity); ok {
			return score, true
		}
		if score, ok := sarifNumber(res.Properties.CvssScore); ok {
			return score, true
		}
	}
	if rule != nil && rule.Properties != nil {
		if score, ok := sarifNumber(rule.Properties.SecuritySeverity); ok {
			return score, true
		}
	}
	return 0, false
}

// sarifNumber reads a numeric property that engines publish either as a JSON
// number or as a string ("7.5").
func sarifNumber(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var number float64
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, true
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		parsed, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

// sarifPrecision reads the precision the engine declares for the result.
func sarifPrecision(res SarifResult, rule *SarifRule) string {
	if res.Properties != nil && res.Properties.Precision != "" {
		return res.Properties.Precision
	}
	if rule != nil && rule.Properties != nil && rule.Properties.Precision != "" {
		return rule.Properties.Precision
	}
	return ""
}

// sarifSeverity derives the canonical severity. The numeric score is
// authoritative when the engine publishes one (GitHub translates it the same
// way: >9 critical, 7-8.9 high, 4-6.9 medium, 0.1-3.9 low). Without a score
// the SARIF level is only a floor, so the result never claims more than its
// level.
func sarifSeverity(score float64, hasScore bool, level string) string {
	if hasScore {
		switch {
		case score >= 9:
			return SeverityCritical
		case score >= 7:
			return SeverityHigh
		case score >= 4:
			return SeverityMedium
		case score > 0:
			return SeverityLow
		default:
			return SeverityInfo
		}
	}
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	case "note":
		return SeverityLow
	}
	return SeverityInfo
}

// sarifConfidence decides how much the result can be trusted. Without a
// numeric score the level is the only signal and it is a floor, not a proof,
// so the finding stays "possible". With a score the declared precision of
// the engine decides.
func sarifConfidence(hasScore bool, precision string) string {
	if !hasScore {
		return ConfidencePossible
	}
	switch strings.ToLower(strings.TrimSpace(precision)) {
	case "very-high", "high":
		return ConfidenceConfirmed
	case "medium":
		return ConfidenceProbable
	case "low":
		return ConfidencePossible
	}
	return ConfidenceProbable
}

// sarifCwe extracts the CWE of a result out of the taxonomies, the rule
// descriptor and the relationships.
func sarifCwe(res SarifResult, rule *SarifRule, related []SarifRule) string {
	var candidates []string
	if res.Properties != nil {
		candidates = append(candidates, res.Properties.Cwe...)
	}
	for _, tax := range res.Taxonomies {
		candidates = append(candidates, tax.ID, tax.Name)
	}
	for _, rel := range related {
		candidates = append(candidates, rel.ID)
	}
	if rule != nil && rule.Properties != nil {
		candidates = append(candidates, rule.Properties.Cwe...)
		candidates = append(candidates, rule.Properties.Tags...)
	}
	for _, candidate := range candidates {
		if cwe := extractCwe(candidate); cwe != "" {
			return cwe
		}
	}
	return ""
}

// sarifOwasp extracts the OWASP categories of a result.
func sarifOwasp(res SarifResult, rule *SarifRule, related []SarifRule) []string {
	var candidates []string
	if res.Properties != nil {
		candidates = append(candidates, res.Properties.Owasp...)
	}
	for _, tax := range res.Taxonomies {
		candidates = append(candidates, tax.ID, tax.Name)
	}
	for _, rel := range related {
		candidates = append(candidates, rel.ID)
	}
	if rule != nil && rule.Properties != nil {
		candidates = append(candidates, rule.Properties.Owasp...)
		candidates = append(candidates, rule.Properties.Tags...)
	}

	var out []string
	for _, candidate := range candidates {
		if id := extractOwasp(candidate); id != "" {
			out = append(out, id)
		}
	}
	return dedupeStrings(out)
}

// dedupeStrings removes the repeated entries while preserving the case and the
// emission order: the OWASP identifiers are case sensitive ("A03:2021").
func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// extractCwe reads the CWE identifier out of a free-form string.
func extractCwe(raw string) string {
	match := cwePattern.FindStringSubmatch(raw)
	if len(match) < 2 {
		return ""
	}
	return normalizeCWE(match[1])
}

// extractOwasp reads the OWASP identifier out of a free-form string.
func extractOwasp(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if match := owaspIDPattern.FindStringSubmatch(trimmed); len(match) == 2 {
		return strings.ToUpper(match[1])
	}
	if match := owaspPattern.FindStringSubmatch(trimmed); len(match) == 2 {
		return strings.ToUpper(match[1])
	}
	return ""
}

// sarifReferences collects the documentation links of a result: the help URI
// of the rule, the taxonomy references and the explicit property list.
func sarifReferences(res SarifResult, rule *SarifRule, related []SarifRule) []string {
	var candidates []string
	if res.Properties != nil {
		candidates = append(candidates, res.Properties.References...)
	}
	for _, tax := range res.Taxonomies {
		candidates = append(candidates, tax.InformationURI)
	}
	if rule != nil {
		candidates = append(candidates, rule.HelpURI)
	}
	for _, rel := range related {
		candidates = append(candidates, rel.HelpURI)
	}

	var out []string
	seen := map[string]bool{}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
		if len(out) >= sarifMaxReferences {
			break
		}
	}
	return out
}

// sarifCvss reads the CVSS vector of a result. The backend computes the
// score from the vector, so only the eight base metrics travel.
func sarifCvss(res SarifResult, rule *SarifRule) *CVSSVector {
	if res.Properties != nil && res.Properties.CvssVector != "" {
		if vector := parseCvssVectorString(res.Properties.CvssVector); vector != nil {
			return vector
		}
	}
	if rule != nil && rule.Properties != nil && rule.Properties.CvssVector != "" {
		if vector := parseCvssVectorString(rule.Properties.CvssVector); vector != nil {
			return vector
		}
	}
	return nil
}

// sarifRemediation turns the fixes of a result into the remediation text of
// the finding: the description of the fix plus the patched content.
func sarifRemediation(fixes []SarifFix) string {
	var parts []string
	for _, fix := range fixes {
		if fix.Description != nil && strings.TrimSpace(fix.Description.Text) != "" {
			parts = append(parts, strings.TrimSpace(fix.Description.Text))
		}
		for _, change := range fix.ArtifactChanges {
			file := ""
			if change.ArtifactLocation != nil {
				file = change.ArtifactLocation.URI
			}
			for _, replacement := range change.Replacements {
				if replacement.InsertedContent == nil || replacement.InsertedContent.Text == "" {
					continue
				}
				content := truncateStr(replacement.InsertedContent.Text, 800)
				if file != "" {
					parts = append(parts, file+": "+content)
				} else {
					parts = append(parts, content)
				}
			}
		}
	}
	return strings.Join(parts, "\n")
}

// sarifCleanText normalizes a free-form engine message into a single line
// title.
func sarifCleanText(raw string, limit int) string {
	cleaned := strings.Join(strings.Fields(raw), " ")
	return truncateStr(cleaned, limit)
}

// sarifVector pins the finding to the exact source location.
func sarifVector(file string, line int) string {
	if file == "" {
		return ""
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", file, line)
	}
	return file
}

// sarifTags maps the rule identifier onto the canonical vocabulary. The rule
// id is the only signal a SARIF engine gives, so the mapping is a fixed
// keyword table instead of a guess.
func sarifTags(res SarifResult, sourceTool string) []string {
	var tags []string
	if res.Properties != nil {
		tags = append(tags, res.Properties.Tags...)
	}
	if sourceTool == "code.deps" {
		tags = append(tags, "dependency", "supply-chain")
	}
	lower := strings.ToLower(res.RuleID)
	switch {
	case strings.Contains(lower, "xss"):
		tags = append(tags, "xss")
	case strings.Contains(lower, "sqli") || strings.Contains(lower, "sql-injection"):
		tags = append(tags, "sqli")
	case strings.Contains(lower, "command-injection") || strings.Contains(lower, "os-command"):
		tags = append(tags, "command-injection")
	case strings.Contains(lower, "path-traversal") || strings.Contains(lower, "path-injection"):
		tags = append(tags, "path-traversal")
	case strings.Contains(lower, "code-injection"):
		tags = append(tags, "code-injection")
	case strings.Contains(lower, "deserialization"):
		tags = append(tags, "deserialization")
	case strings.Contains(lower, "ssrf"):
		tags = append(tags, "ssrf")
	case strings.Contains(lower, "xxe"):
		tags = append(tags, "xxe")
	case strings.Contains(lower, "open-redirect"):
		tags = append(tags, "open-redirect")
	case strings.Contains(lower, "idor") || strings.Contains(lower, "access-control"):
		tags = append(tags, "idor", "broken-access-control")
	case strings.Contains(lower, "jwt"):
		tags = append(tags, "jwt", "weak-auth")
	case strings.Contains(lower, "hardcoded") || strings.Contains(lower, "secret") || strings.Contains(lower, "credential") || strings.Contains(lower, "password") || strings.Contains(lower, "api-key"):
		tags = append(tags, "secret-exposure", "hardcoded-secret")
	case strings.Contains(lower, "crypto") || strings.Contains(lower, "cipher"):
		tags = append(tags, "weak-crypto")
	}
	return dedupeTags(tags)
}
