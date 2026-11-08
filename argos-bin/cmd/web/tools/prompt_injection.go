package tools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// RegisterPromptInjection registers the prompt injection detector.
//
// The tool automates the control that the web playbook states as a rule for
// the agent: the content of the target is data, and the attempts to redirect
// the model are reported as findings instead of being followed.
func RegisterPromptInjection(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.prompt_injection",
			Description: "Prompt injection detection in the content of a target: attempts to override the instructions of " +
				"the model, to replace its role, to reveal the system prompt or to disable its restrictions. The " +
				"content is only read, never followed.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":  {Type: "string", Description: "URL whose content is scanned"},
					"body":    {Type: "string", Description: "Content to scan instead of fetching it"},
					"timeout": {Type: "integer", Description: "Per-request timeout in seconds (default 15, max 60)"},
				},
				Required: []string{},
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
				Body    string `json:"body"`
				Timeout int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			started := time.Now()
			callCtx := toolContext(ctx)

			content := input.Body
			target := ""
			contentStatus := 0
			if strings.TrimSpace(content) == "" {
				if input.Target == "" {
					return nil, &mcp.ErrorObj{Code: -32602, Message: "target or body is required"}
				}
				validated, e := validateWebTargetWithToolContext(env, ctx, input.Target)
				if e != nil {
					return nil, e
				}
				target = validated
				resp, err := vectorFetch(callCtx, env.Client(), "GET", target, nil, "", vectorTimeout(input.Timeout))
				if err != nil {
					return nil, &mcp.ErrorObj{Code: -32603, Message: "cannot read the content of the target: " + err.Error()}
				}
				content = resp.Body
				contentStatus = resp.Status
			}

			report := detectPromptInjection(content, target)
			fs, truncated := capFindings(report.findings)
			fs = attachPromptInjectionPocs(fs, content, target, contentStatus)
			res := vectorResult("web.prompt_injection", target, started)
			res["matches"] = report.matches
			res["scanned_bytes"] = len(content)
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d prompt injection attempts detected", len(fs))
			return res, nil
		},
	)
}

// promptInjectionPattern is one family of prompt injection attempts.
type promptInjectionPattern struct {
	ID     string
	Label  string
	Regex  *regexp.Regexp
	Severe bool
}

// promptInjectionPatterns are the attempts to redirect the model.
//
// The families are the ones the OWASP LLM Top 10 lists: the direct override
// of the instructions, the replacement of the role, the exfiltration of the
// system prompt and the removal of the restrictions.
var promptInjectionPatterns = []promptInjectionPattern{
	{
		ID:    "instruction-override",
		Label: "override of the previous instructions",
		Regex: regexp.MustCompile(`(?i)\b(ignore|disregard|forget|discard|override)\b[^.\n]{0,40}\b(all\s+|any\s+|the\s+|your\s+|previous\s+|prior\s+|above\s+|earlier\s+|preceding\s+|system\s+)*(instruction|instructions|rules|prompts?|directives?|guidelines?|context)\b`),
	},
	{
		ID:    "instruction-override",
		Label: "override of the previous instructions (spanish)",
		Regex: regexp.MustCompile(`(?i)\b(ignor(?:a|á|é|e|o|ar|ars)|olvid(?:a|á|é|e|o)|desconsider(?:a|á|é|e|o)|descart(?:a|á|é|e|o))\b[^.\n]{0,40}\b(instruccion(?:es)?|reglas?|indicaciones?|directrices?|prompt)\b`),
	},
	{
		ID:    "role-replacement",
		Label: "replacement of the role of the model",
		Regex: regexp.MustCompile(`(?i)\byou\s+are\s+(now|no\s+longer|actually)\b|\bact\s+as\s+(a|an|the)?\s*\w*\s*(dan|unrestricted|unfiltered|uncensored|developer\s+mode|evil|malicious)\b|\bpretend\s+(that\s+)?you\s+(are|have|were)\b|\bfrom\s+now\s+on[, ]+you\b|\bnuevo\s+rol\b|\bahora\s+eres\b`),
	},
	{
		ID:    "system-prompt-exfiltration",
		Label: "exfiltration of the system prompt",
		Regex: regexp.MustCompile(`(?i)\b(reveal|show|print|repeat|output|display|dump|leak|disclose)\b[^.\n]{0,30}\b(system\s+prompt|initial\s+instructions|your\s+instructions|your\s+rules|hidden\s+prompt)\b|\bwhat\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions)\b`),
	},
	{
		ID:    "restriction-bypass",
		Label: "removal of the restrictions of the model",
		Regex: regexp.MustCompile(`(?i)\b(bypass|disable|remove|circumvent|evade|get\s+around|ignore)\b[^.\n]{0,30}\b(safety|safeguards?|security|content|moderation|restrictions?|filters?|guidelines?|policies|policy)\b|\bwithout\s+any\s+(restrictions?|limits?|filters?)\b|\bjailbreak\b|\bdo\s+anything\s+now\b|\bdeveloper\s+mode\b`),
	},
	{
		ID:    "new-instructions",
		Label: "injection of a new instruction block",
		Regex: regexp.MustCompile(`(?i)(^|\n)\s*(new\s+instructions?|updated\s+instructions?|system\s*:|assistant\s*:|<\s*system\s*>|\[\s*system\s*\]|important\s+instructions?\s*:)`),
	},
}

// promptInjectionReport is the outcome of the scan of one content.
type promptInjectionReport struct {
	findings []Finding
	matches  []map[string]any
}

// detectPromptInjection scans the content of the target for the attempts to
// redirect the model.
//
// The content is data: the tool reports what it finds and never follows the
// instruction it found.
func detectPromptInjection(content, target string) *promptInjectionReport {
	report := &promptInjectionReport{}
	if strings.TrimSpace(content) == "" {
		return report
	}

	hidden := promptHiddenRegions(content)

	for _, pattern := range promptInjectionPatterns {
		for _, location := range promptMatchLocations(pattern, content) {
			region := "visible"
			if promptInsideHidden(location.offset, hidden) {
				region = "hidden"
			}
			severity := SeverityMedium
			confidence := ConfidenceConfirmed
			if region == "hidden" {
				// An instruction hidden from the user is the deliberate
				// attempt to reach the model.
				severity = SeverityHigh
			}
			evidence := map[string]any{
				"pattern_id":    pattern.ID,
				"label":         pattern.Label,
				"region":        region,
				"snippet":       location.snippet,
				"offset":        location.offset,
				"scanned_bytes": len(content),
			}
			if target != "" {
				evidence["url"] = target
			}
			report.matches = append(report.matches, map[string]any{
				"pattern_id": pattern.ID,
				"label":      pattern.Label,
				"region":     region,
				"snippet":    location.snippet,
			})
			report.findings = append(report.findings, Finding{
				Source: "web.prompt_injection", SourceTool: "web.prompt_injection", RuleID: "prompt-injection:" + pattern.ID,
				Title:      "Prompt injection detected in the content of the target: " + pattern.Label,
				Severity:   severity,
				Confidence: confidence,
				CWE:        "CWE-1427",
				OWASP:      []string{"LLM01:2025"},
				Target:     target,
				Vector:     "content:" + pattern.ID,
				Evidence:   evidence,
				Remediation: "Treat every value that comes from the target as data: strip it before it reaches the prompt, " +
					"render it inside a delimited block and never let it change the instructions of the model.",
				Tags: []string{"code-injection"},
			})
		}
	}
	return report
}

// attachPromptInjectionPocs builds the proof of concept of every prompt
// injection finding: the request that reads the content and the matcher that
// checks whether the attempt is still there.
//
// The needle is the fragment of the attempt that matched: while the content
// carries it, the model still receives the instruction.
func attachPromptInjectionPocs(fs []Finding, content, target string, status int) []Finding {
	if strings.TrimSpace(target) == "" {
		return fs
	}
	for i := range fs {
		if fs[i].Evidence == nil {
			continue
		}
		snippet, _ := fs[i].Evidence["snippet"].(string)
		if strings.TrimSpace(snippet) == "" {
			continue
		}
		attachPoc(fs[i].Evidence, &pocRecord{
			Kind:     "prompt_injection",
			Method:   http.MethodGet,
			URL:      target,
			Payload:  snippet,
			Matcher:  pocMatcherBodyAbsent(snippet),
			Baseline: pocBaselineOf(status, content),
		})
	}
	return fs
}

// promptMatch is one occurrence of a pattern in the content.
type promptMatch struct {
	offset  int
	snippet string
}

// promptMatchLocations returns the occurrences of the pattern.
func promptMatchLocations(pattern promptInjectionPattern, content string) []promptMatch {
	var out []promptMatch
	for _, location := range pattern.Regex.FindAllStringIndex(content, -1) {
		start := location[0]
		end := location[1]
		if end-start > 300 {
			end = start + 300
		}
		out = append(out, promptMatch{
			offset:  start,
			snippet: strings.TrimSpace(content[start:end]),
		})
		if len(out) >= 20 {
			break
		}
	}
	return out
}

var (
	// promptHiddenStylePattern matches the elements that are hidden from the
	// user but still reach the model.
	promptHiddenStylePattern = regexp.MustCompile(`(?is)<(div|span|p|section|textarea|a|b|i)[^>]*style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*#?fff|left\s*:\s*-\d{3,})[^"']*["'][^>]*>`)
	// promptCommentPattern matches the HTML comments.
	promptCommentPattern = regexp.MustCompile(`(?is)<!--(.*?)-->`)
	// promptHiddenAttrPattern matches the elements hidden with the hidden
	// attribute or with a hidden type.
	promptHiddenAttrPattern = regexp.MustCompile(`(?is)<(div|span|p|section|textarea|a)\b[^>]*\b(hidden|type\s*=\s*["']hidden["'])\b[^>]*>`)
)

// promptHiddenRegions returns the ranges of the content that the user does
// not see.
//
// The region of a hidden element covers its content too: the instruction
// lives inside the element, not inside its opening tag.
func promptHiddenRegions(content string) []struct{ start, end int } {
	var out []struct{ start, end int }
	for _, location := range promptCommentPattern.FindAllStringIndex(content, -1) {
		out = append(out, struct{ start, end int }{location[0], location[1]})
	}
	for _, pattern := range []*regexp.Regexp{promptHiddenStylePattern, promptHiddenAttrPattern} {
		for _, match := range pattern.FindAllStringSubmatchIndex(content, -1) {
			start, end := match[0], match[1]
			tag := ""
			if len(match) > 3 && match[2] >= 0 {
				tag = content[match[2]:match[3]]
			}
			if tag != "" {
				if closing := promptClosingTag(content[end:], tag); closing > 0 {
					end = end + closing
				}
			}
			out = append(out, struct{ start, end int }{start, end})
		}
	}
	return out
}

// promptClosingTag returns the length of the closing tag of the element,
// counting from the beginning of the rest of the document.
//
// The value is zero when the element is not closed.
func promptClosingTag(rest, tag string) int {
	needle := "</" + tag
	index := strings.Index(strings.ToLower(rest), strings.ToLower(needle))
	if index < 0 {
		return 0
	}
	end := strings.Index(rest[index:], ">")
	if end < 0 {
		return 0
	}
	return index + end + 1
}

// promptInsideHidden reports whether the offset falls inside a hidden region.
func promptInsideHidden(offset int, hidden []struct{ start, end int }) bool {
	for _, region := range hidden {
		if offset >= region.start && offset < region.end {
			return true
		}
	}
	return false
}
