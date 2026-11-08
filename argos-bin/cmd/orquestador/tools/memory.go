package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/iwiels/ARGOS/argos-bin/internal/contract"
	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

type MemorySearchInput struct {
	Query string `json:"query"`
	Limit int    `json:"limit"`
}

type MemoryContextInput struct {
	Limit int `json:"limit"`
}

type MemorySaveInput struct {
	Title           string `json:"title"`
	Target          string `json:"target,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Status          string `json:"status,omitempty"`
	CWE             string `json:"cwe,omitempty"`
	Evidence        string `json:"evidence,omitempty"`
	AgentAssessment string `json:"agent_assessment,omitempty"`
	Impact          string `json:"impact,omitempty"`
	Vector          string `json:"vector,omitempty"`
	Session         string `json:"session,omitempty"`
	// ArgosSessionID es el Session ID real de Argos Desktop (ses_...),
	// distinto de `session` (una etiqueta de campaña legible). Sin este campo
	// no hay forma de reconciliar hallazgos de peer agents (que corren fuera
	// del tracking de la Session) de vuelta al panel — ver
	// packages/core/src/security/agent-findings-reconcile.ts.
	ArgosSessionID  string   `json:"argos_session_id,omitempty"`
	Agent           string   `json:"agent,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	NeedsFollowupBy []string `json:"needs_followup_by,omitempty"`
	Body            string   `json:"body,omitempty"`
	SourceTool      string   `json:"source_tool,omitempty"`
}

// argosSessionIDPrefix es el prefijo de un Session ID real de Argos
// Desktop. Sirve para distinguirlo de la etiqueta de campaña (`session`) y de
// los placeholders de las plantillas de agente.
const argosSessionIDPrefix = contract.SessionIDPrefix

// validateArgosSessionID rechaza un hallazgo que nunca podría reconciliarse
// con la UI.
//
// El backend reconcilia comparando este campo con el Session ID exacto (ver
// packages/core/src/security/agent-findings-reconcile.ts). Un valor ausente,
// un placeholder sin sustituir (`[ARGOS_SESSION_ID]`) o la etiqueta de
// campaña por error producen un archivo que se guarda bien pero que el panel
// nunca verá. Es preferible el error explícito.
//
// Sólo se aplica a `kind: "finding"`: notas y observaciones de memoria
// compartida entre campañas no se reconcilian con ninguna sesión.
func validateArgosSessionID(kind string, value string) *mcp.ErrorObj {
	if strings.ToLower(strings.TrimSpace(kind)) != "finding" {
		return nil
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return &mcp.ErrorObj{
			Code: -32602,
			Message: `Missing "argos_session_id". Copy it verbatim from your system context ` +
				`("Your Argos session ID is: ses_..."). Without it the finding is written to disk ` +
				`but never reaches the Hallazgos/Cumplimiento panels. It is NOT the same as "session", ` +
				`which is your campaign label.`,
		}
	}
	if !strings.HasPrefix(trimmed, argosSessionIDPrefix) {
		return &mcp.ErrorObj{
			Code: -32602,
			Message: fmt.Sprintf(
				`Invalid "argos_session_id": %q. It must be the real Argos Desktop Session ID `+
					`starting with %q, copied verbatim from your system context — not the campaign label `+
					`(that goes in "session") and not an unsubstituted placeholder.`,
				trimmed, argosSessionIDPrefix,
			),
		}
	}
	return nil
}

func validateMemoryFinding(input MemorySaveInput) *mcp.ErrorObj {
	kind := strings.ToLower(strings.TrimSpace(input.Kind))
	if kind == "" {
		return &mcp.ErrorObj{Code: -32602, Message: `Missing "kind". Set kind="finding" only after reviewing the scanner evidence; use "note" or "observation" for context that is not a verified security issue.`}
	}
	if kind != "finding" {
		return nil
	}
	if strings.TrimSpace(input.Title) == "" {
		return &mcp.ErrorObj{Code: -32602, Message: `A finding requires a non-empty "title".`}
	}
	if strings.TrimSpace(input.Target) == "" {
		return &mcp.ErrorObj{Code: -32602, Message: `A finding requires the exact affected "target".`}
	}
	evidence := strings.TrimSpace(input.Evidence)
	if utf8.RuneCountInString(evidence) < 24 {
		return &mcp.ErrorObj{Code: -32602, Message: `A finding requires concrete "evidence" observed by the agent. A scanner match, route, or status alone is not sufficient.`}
	}
	assessment := strings.TrimSpace(input.AgentAssessment)
	if !meaningfulAgentReviewText(assessment, 40) {
		return &mcp.ErrorObj{Code: -32602, Message: `A finding requires a substantive "agent_assessment" of at least 40 characters: explain what you independently checked and why the evidence confirms a security issue.`}
	}
	if !meaningfulAgentReviewText(input.Impact, 24) {
		return &mcp.ErrorObj{Code: -32602, Message: `A finding requires a concrete security consequence in "impact".`}
	}
	if strings.EqualFold(assessment, evidence) || strings.EqualFold(assessment, strings.TrimSpace(input.Title)) || strings.EqualFold(assessment, strings.TrimSpace(input.Impact)) {
		return &mcp.ErrorObj{Code: -32602, Message: `The "agent_assessment" must contain the agent's own analysis, not a copy of the evidence, title, or impact.`}
	}
	switch strings.ToLower(strings.TrimSpace(input.Severity)) {
	case "critical", "critico", "crítico", "high", "alto", "alta", "medium", "medio", "media", "moderate", "low", "bajo", "baja", "info", "informational", "informativo":
		return nil
	default:
		return &mcp.ErrorObj{Code: -32602, Message: `A finding requires an explicit severity: critical, high, medium, low, or info.`}
	}
}

func meaningfulAgentReviewText(value string, minimumLength int) bool {
	text := strings.TrimSpace(value)
	if utf8.RuneCountInString(text) < minimumLength {
		return false
	}
	switch strings.ToLower(strings.Trim(text, ".! \t\r\n")) {
	case "n/a", "na", "none", "unknown", "tbd", "pending", "unconfirmed", "not applicable", "not verified", "not assessed":
		return false
	default:
		return true
	}
}

// Finding es la forma en que una decisión explícita del agente queda en el
// store de memoria compartido (<memoryDir>/findings/*.json).
type Finding = contract.Record


func RegisterMemorySearch(s *mcp.Server) {
	readOnly := mcp.BoolPtr(true)
	idempotent := mcp.BoolPtr(true)

	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "memory.search",
			Description: "Search persisted findings stored in the memory directory. Returns matching observations by query string.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"query": {
						Type:        "string",
						Description: "Search query to match against finding titles, targets, and evidence",
					},
					"limit": {
						Type:        "integer",
						Description: "Maximum number of results to return (default 10)",
						Default:     10,
					},
				},
				Required: []string{"query"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   readOnly,
				IdempotentHint: idempotent,
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input MemorySearchInput
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid params: " + err.Error()}
			}
			if input.Limit <= 0 {
				input.Limit = 10
			}

			findingsDir := filepath.Join(ctx.MemoryDir, "findings")
			entries, err := os.ReadDir(findingsDir)
			if err != nil {
				return map[string]interface{}{"findings": []Finding{}, "total": 0, "message": "No findings directory yet"}, nil
			}

			queryLower := strings.ToLower(input.Query)
			queryTokens := make([]string, 0, 8)
			for _, tok := range strings.Fields(queryLower) {
				tok = strings.Trim(tok, ".,;:!?()[]\"'")
				if len(tok) >= 2 {
					queryTokens = append(queryTokens, tok)
					// If token has hyphens, also index components (e.g. "sistemasuni-2026-08-14" -> "sistemasuni")
					if strings.Contains(tok, "-") {
						for _, part := range strings.Split(tok, "-") {
							if len(part) >= 3 {
								queryTokens = append(queryTokens, part)
							}
						}
					}
					// If token has dots, also index domain suffixes/parts (e.g. "api.audit.example.org" -> "audit.example.org", "audit")
					if strings.Contains(tok, ".") {
						parts := strings.Split(tok, ".")
						for i := 0; i < len(parts); i++ {
							sub := strings.Join(parts[i:], ".")
							if len(sub) >= 3 && sub != tok {
								queryTokens = append(queryTokens, sub)
							}
							if len(parts[i]) >= 3 && parts[i] != tok {
								queryTokens = append(queryTokens, parts[i])
							}
						}
					}
				}
			}

			type scored struct {
				finding Finding
				score   int
			}
			var matched []scored

			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(findingsDir, entry.Name()))
				if err != nil {
					continue
				}
				var finding Finding
				if err := json.Unmarshal(data, &finding); err != nil {
					continue
				}
				if strings.TrimSpace(finding.Source) != "" {
					continue
				}

				haystack := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s",
					finding.Title,
					finding.Target,
					finding.Session,
					finding.Agent,
					finding.Kind,
					finding.Severity,
					finding.Status,
					finding.CWE,
					fmt.Sprint(finding.Evidence),
					finding.Vector,
					finding.SourceTool,
					finding.RuleID,
					finding.Confidence,
					finding.Remediation,
					strings.Join(finding.Tags, " "),
					strings.Join(finding.References, " "),
				))

				score := 0
				// Exact session match or target match gets highest priority
				if finding.Session != "" && strings.EqualFold(finding.Session, input.Query) {
					score += 50
				}
				if queryLower != "" && strings.Contains(haystack, queryLower) {
					score += 20
				}
				if finding.Session != "" && strings.Contains(queryLower, strings.ToLower(finding.Session)) {
					score += 15
				}
				if finding.Target != "" && (strings.Contains(queryLower, strings.ToLower(finding.Target)) || strings.Contains(strings.ToLower(finding.Target), queryLower)) {
					score += 15
				}
				if finding.Kind == "authorization" && (strings.Contains(queryLower, "authoriz") || strings.Contains(queryLower, "autoriz")) {
					score += 20
				}
				for _, tok := range queryTokens {
					cleanTok := tok
					if strings.HasSuffix(tok, "s") && len(tok) > 3 {
						cleanTok = strings.TrimSuffix(tok, "s")
					}
					if strings.Contains(haystack, tok) || strings.Contains(haystack, cleanTok) {
						score += 2
					}
					// Key:value syntax support (e.g. session:xyz, agent:web, kind:finding, severity:critical)
					if strings.HasPrefix(tok, "agent:") && strings.Contains(strings.ToLower(finding.Agent), strings.TrimPrefix(tok, "agent:")) {
						score += 10
					}
					if strings.HasPrefix(tok, "session:") && strings.Contains(strings.ToLower(finding.Session), strings.TrimPrefix(tok, "session:")) {
						score += 10
					}
					if strings.HasPrefix(tok, "kind:") && strings.Contains(strings.ToLower(finding.Kind), strings.TrimPrefix(tok, "kind:")) {
						score += 10
					}
					if strings.HasPrefix(tok, "severity:") && strings.Contains(strings.ToLower(finding.Severity), strings.TrimPrefix(tok, "severity:")) {
						score += 10
					}
				}
				if score > 0 {
					matched = append(matched, scored{finding: finding, score: score})
				}
			}

			sort.Slice(matched, func(i, j int) bool {
				if matched[i].score != matched[j].score {
					return matched[i].score > matched[j].score
				}
				return matched[i].finding.Timestamp > matched[j].finding.Timestamp
			})

			findings := make([]Finding, 0, len(matched))
			for _, m := range matched {
				findings = append(findings, m.finding)
			}
			if len(findings) > input.Limit {
				findings = findings[:input.Limit]
			}

			return map[string]interface{}{
				"findings": findings,
				"total":    len(findings),
				"query":    input.Query,
			}, nil
		},
	)
}

func RegisterMemoryContext(s *mcp.Server) {
	readOnly := mcp.BoolPtr(true)
	idempotent := mcp.BoolPtr(true)

	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "memory.context",
			Description: "Return recent memory context by listing the latest persisted findings",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"limit": {
						Type:        "integer",
						Description: "Number of recent entries to return (default 5)",
						Default:     5,
					},
				},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   readOnly,
				IdempotentHint: idempotent,
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input MemoryContextInput
			if err := json.Unmarshal(params, &input); err != nil {
				input.Limit = 5
			}
			if input.Limit <= 0 {
				input.Limit = 5
			}

			findingsDir := filepath.Join(ctx.MemoryDir, "findings")
			entries, err := os.ReadDir(findingsDir)
			if err != nil {
				return map[string]interface{}{"context": []Finding{}, "total": 0, "memory_dir": ctx.MemoryDir}, nil
			}

			var files []string
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
					files = append(files, entry.Name())
				}
			}

			sort.Sort(sort.Reverse(sort.StringSlice(files)))

			var findings []Finding
			for _, f := range files {
				data, err := os.ReadFile(filepath.Join(findingsDir, f))
				if err != nil {
					continue
				}
				var finding Finding
				if err := json.Unmarshal(data, &finding); err != nil {
					continue
				}
				if strings.TrimSpace(finding.Source) != "" {
					continue
				}
				findings = append(findings, finding)
				if len(findings) >= input.Limit {
					break
				}
			}

			if findings == nil {
				findings = []Finding{}
			}

			return map[string]interface{}{
				"context":    findings,
				"total":      len(findings),
				"memory_dir": ctx.MemoryDir,
			}, nil
		},
	)
}

func RegisterMemorySave(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "memory.save",
			Description: "Save a structured finding to the memory directory for persistence across sessions",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"title": {
						Type:        "string",
						Description: "Title of the finding",
					},
					"target": {
						Type:        "string",
						Description: "Target URL, host, or identifier",
					},
					"severity": {
						Type:        "string",
						Description: "Severity level: CRITICAL, HIGH, MEDIUM, LOW, or INFO",
					},
					"status": {
						Type:        "string",
						Description: "Finding status: observed, suspected, validated, blocked-by-policy",
					},
					"cwe": {
						Type:        "string",
						Description: "CWE identifier, e.g. CWE-79",
					},
					"evidence": {
						Type:        "string",
						Description: "Required for kind=finding: at least 24 characters of concrete response, behavior, or artifact observed by the agent. A scanner match, route, or status alone is not sufficient.",
					},
					"agent_assessment": {
						Type:        "string",
						Description: "Required for kind=finding: at least 40 characters describing the independent check, why the evidence confirms a security issue, and why this is not an expected behavior. Do not copy the title, evidence, or impact.",
					},
					"impact": {
						Type:        "string",
						Description: "Required for kind=finding: at least 24 characters describing a concrete consequence to a user, system, or data.",
					},
					"vector": {
						Type:        "string",
						Description: "Attack vector or exploitation path",
					},
					"session": {
						Type:        "string",
						Description: "Session identifier for grouping related findings",
					},
					"argos_session_id": {
						Type:        "string",
						Description: "The real Argos Desktop Session ID (starts with \"ses_\"), visible in your own system context. Required for this finding to be reconciled back into the app's Hallazgos panel — without it, the finding stays searchable via memory.search but never reaches the UI. Different from \"session\", which is a human-readable campaign label.",
					},
					"agent": {
						Type:        "string",
						Description: "Agent that generated the finding",
					},
					"tags": {
						Type:        "array",
						Description: "Tags for categorizing the finding",
						Items:       &mcp.Items{Type: "string"},
					},
					"kind": {
						Type:        "string",
						Description: "Required record kind. Use finding only after independently reviewing evidence and providing distinct agent_assessment and impact. Otherwise use observation or note.",
					},
					"needs_followup_by": {
						Type:        "array",
						Description: "List of agents that should follow up on this finding",
						Items:       &mcp.Items{Type: "string"},
					},
					"body": {
						Type:        "string",
						Description: "Additional body text or description",
					},
					"source_tool": {
						Type:        "string",
						Description: "Identifier of the actual scanning tool/skill that produced this finding, e.g. 'lan.port_scan', 'web.probe', 'recon.dns_enum'. Used for compliance and ATT&CK technique mapping — see packages/core/src/compliance/derive.ts and packages/core/src/threat-intel/attack.ts for the expected vocabulary.",
					},
				},
				Required: []string{"title", "kind"},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input MemorySaveInput
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid params: " + err.Error()}
			}
			input.Kind = strings.ToLower(strings.TrimSpace(input.Kind))
			if err := validateMemoryFinding(input); err != nil {
				return nil, err
			}

			agent := strings.TrimSpace(input.Agent)
			if agent == "" {
				agent = "security-orchestrator"
			}
			session := input.Session
			if session == "" {
				session = "default"
			}

			// Falla ruidosamente en vez de escribir un hallazgo que nunca se podrá
			// reconciliar. El agente recibe el error y puede reintentar con el
			// valor correcto; antes, el hallazgo se perdía sin que nadie lo notara.
			sessionID := strings.TrimSpace(input.ArgosSessionID)
			if ctx.SessionID != "" && input.Kind == "finding" {
				sessionID = ctx.SessionID
			}
			if err := validateArgosSessionID(input.Kind, sessionID); err != nil {
				return nil, err
			}

			finding := Finding{
				Kind:            input.Kind,
				Agent:           agent,
				Session:         session,
				ArgosSessionID:  sessionID,
				Title:           input.Title,
				Target:          input.Target,
				Severity:        input.Severity,
				Status:          input.Status,
				CWE:             input.CWE,
				AgentAssessment: strings.TrimSpace(input.AgentAssessment),
				Impact:          strings.TrimSpace(input.Impact),
				Vector:          input.Vector,
				Tags:            input.Tags,
				NeedsFollowupBy: input.NeedsFollowupBy,
				SourceTool:      input.SourceTool,
				Timestamp:       time.Now().UTC().Format(time.RFC3339),
			}
			if strings.TrimSpace(input.Evidence) != "" {
				finding.Evidence = input.Evidence
			}

			findingsDir := filepath.Join(ctx.MemoryDir, "findings")
			path, err := contract.WriteRecord(findingsDir, finding)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "Failed to write finding: " + err.Error()}
			}

			ctx.Log("Memory saved: %s (session=%s, kind=%s)", filepath.Base(path), session, finding.Kind)

			return map[string]interface{}{
				"status":   "saved",
				"path":     path,
				"filename": filepath.Base(path),
				"finding":  finding,
			}, nil
		},
	)
}
