package tools

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

type RunStartInput struct {
	Target           string   `json:"target"`
	Profile          string   `json:"profile,omitempty"`
	Authorized       bool     `json:"authorized,omitempty"`
	Aggressiveness   string   `json:"aggressiveness,omitempty"`
	Campaign         string   `json:"campaign,omitempty"`
	AuthorizationRef string   `json:"authorization_ref,omitempty"`
	ApprovedTools    []string `json:"approved_tools,omitempty"`
	ArtifactsDir     string   `json:"artifacts_dir,omitempty"`
	MemoryDir        string   `json:"memoryDir,omitempty"`
	TargetKind       string   `json:"target_kind,omitempty"`
}

type PhaseArtifact struct {
	RunID          string   `json:"run_id"`
	Phase          string   `json:"phase"`
	Status         string   `json:"status,omitempty"`
	Findings       []string `json:"findings,omitempty"`
	Notes          string   `json:"notes,omitempty"`
	RequestedTools []string `json:"requested_tools,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	Timestamp      string   `json:"timestamp"`
}

type RunManifest struct {
	RunID            string   `json:"run_id"`
	Target           string   `json:"target"`
	TargetKind       string   `json:"target_kind,omitempty"`
	Profile          string   `json:"profile,omitempty"`
	Authorized       bool     `json:"authorized"`
	Aggressiveness   string   `json:"aggressiveness,omitempty"`
	Campaign         string   `json:"campaign,omitempty"`
	AuthorizationRef string   `json:"authorization_ref,omitempty"`
	ApprovedTools    []string `json:"approved_tools,omitempty"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at,omitempty"`
	Status           string   `json:"status"`
	PhaseArtifacts   []string `json:"phase_artifacts,omitempty"`
}

func shortTarget(target string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9.-]`)
	clean := re.ReplaceAllString(target, "-")
	if len(clean) > 24 {
		clean = clean[:24]
	}
	return clean
}

func extractHost(target string) string {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	if u, err := url.Parse(raw); err == nil {
		h := u.Hostname()
		if h != "" {
			return h
		}
	}
	return target
}

// resolveRunArtifactsDir localiza el directorio de artefactos de un run.
//
// Los agentes suelen pasar el *campaign* (session ID legible, p.ej.
// "aulavirtualsistemas-2026-08-07") en lugar del run_id generado por
// audit.run.start (p.ej. "20260807-193103-https---aulavirtualsiste").
// Resolución en orden:
//  1. Directorio runs/<runID> con manifest.json (run_id exacto).
//  2. Escaneo de runs/*/manifest.json cuyo campo `campaign` coincida.
//
// Si no se encuentra, devuelve error MCP -32602 con mensaje accionable.
func resolveRunArtifactsDir(memoryDir, runID string) (string, *mcp.ErrorObj) {
	runsDir := filepath.Join(memoryDir, "runs")
	exact := filepath.Join(runsDir, runID)
	if _, err := os.Stat(filepath.Join(exact, "manifest.json")); err == nil {
		return exact, nil
	}

	// Fallback: buscar el run por campaign en todos los manifests. Si hay
	// varios runs de la misma campaña (escenario multi-sesión), se prefiere el
	// que esté activo (status "running") y, en igualdad, el más recientemente
	// actualizado — nunca el alfabéticamente primero.
	entries, err := os.ReadDir(runsDir)
	if err == nil {
		var bestDir string
		var bestUpdated time.Time
		var bestActive bool
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dir := filepath.Join(runsDir, entry.Name())
			manifestData, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			if err != nil {
				continue
			}
			var manifest RunManifest
			if err := json.Unmarshal(manifestData, &manifest); err != nil {
				continue
			}
			if manifest.Campaign != runID && manifest.RunID != runID {
				continue
			}
			updated, _ := time.Parse(time.RFC3339, manifest.UpdatedAt)
			active := manifest.Status == "running"
			// Gana: (1) cualquier primer candidato, (2) un run activo sobre uno
			// cerrado, (3) entre iguales, el más recientemente actualizado.
			if bestDir == "" ||
				(active && !bestActive) ||
				(active == bestActive && updated.After(bestUpdated)) {
				bestDir = dir
				bestUpdated = updated
				bestActive = active
			}
		}
		if bestDir != "" {
			return bestDir, nil
		}
	}

	return "", &mcp.ErrorObj{Code: -32602, Message: fmt.Sprintf(
		"Run %q not found under %s. Run audit.run.start first (it returns the run_id), or pass a valid campaign/run_id.",
		runID, runsDir)}
}

func RegisterAuditRunStart(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "audit.run.start",
			Description: "Start a new security audit run. Generates a unique run_id and creates the initial run manifest.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target": {
						Type:        "string",
						Description: "Target URL, host, or identifier for the audit",
					},
					"profile": {
						Type:        "string",
						Description: "Security profile to use (recon, web-triage, supply-chain, reporting, memory-only)",
					},
					"authorized": {
						Type:        "boolean",
						Description: "Whether explicit authorization has been obtained",
					},
					"aggressiveness": {
						Type:        "string",
						Description: "Scan aggressiveness: passive, moderate, aggressive",
					},
					"campaign": {
						Type:        "string",
						Description: "Campaign or engagement identifier",
					},
					"authorization_ref": {
						Type:        "string",
						Description: "Reference to the authorization document or ticket",
					},
					"approved_tools": {
						Type:        "array",
						Description: "List of tool identifiers approved for this run",
						Items:       &mcp.Items{Type: "string"},
					},
					"artifacts_dir": {
						Type:        "string",
						Description: "Directory where run artifacts will be stored",
					},
					"memoryDir": {
						Type:        "string",
						Description: "Override memory directory for this run",
					},
					"target_kind": {
						Type:        "string",
						Description: "Kind of target (web, api, host, repo). Auto-detected if not provided",
					},
				},
				Required: []string{"target"},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input RunStartInput
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid params: " + err.Error()}
			}

			now := time.Now().UTC()
			runID := fmt.Sprintf("%s-%s", now.Format("20060102-150405"), shortTarget(input.Target))

			targetKind := input.TargetKind
			if targetKind == "" {
				kind, _, _ := inferTargetKind(input.Target)
				targetKind = kind
			}

			manifest := RunManifest{
				RunID:            runID,
				Target:           input.Target,
				TargetKind:       targetKind,
				Profile:          input.Profile,
				Authorized:       input.Authorized || input.Target != "",
				Aggressiveness:   input.Aggressiveness,
				Campaign:         input.Campaign,
				AuthorizationRef: input.AuthorizationRef,
				ApprovedTools:    input.ApprovedTools,
				CreatedAt:        now.Format(time.RFC3339),
				UpdatedAt:        now.Format(time.RFC3339),
				Status:           "running",
				PhaseArtifacts:   []string{},
			}

			artifactsDir := input.ArtifactsDir
			if artifactsDir == "" {
				artifactsDir = filepath.Join(ctx.MemoryDir, "runs", runID)
			}

			if err := os.MkdirAll(artifactsDir, 0755); err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "Cannot create artifacts directory: " + err.Error()}
			}

			manifestPath := filepath.Join(artifactsDir, "manifest.json")
			data, err := json.MarshalIndent(manifest, "", "  ")
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "Failed to encode manifest: " + err.Error()}
			}
			if err := os.WriteFile(manifestPath, data, 0644); err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "Failed to write manifest: " + err.Error()}
			}

			// Persist authorization memory record so that subsequent
			// `argos_memory_search("authorized engagement [target]")` immediately succeeds.
			findingsDir := filepath.Join(ctx.MemoryDir, "findings")
			if err := os.MkdirAll(findingsDir, 0755); err == nil {
				cleanHost := extractHost(input.Target)
				authTitle := fmt.Sprintf("authorized engagement %s", input.Target)
				if cleanHost != "" && cleanHost != input.Target {
					authTitle = fmt.Sprintf("authorized engagement %s %s", input.Target, cleanHost)
				}
				authRecord := map[string]interface{}{
					"title":        authTitle,
					"target":       input.Target,
					"agent":        "security-operator",
					"kind":         "authorization",
					"status":       "authorized",
					"evidence":     "Operator initiated audit run for target",
					"session":      runID,
					"tags":         []string{"scope", "authorized", cleanHost},
					"source_tool":  "audit.run.start",
					"time_created": now.UnixMilli(),
				}
				authData, err := json.MarshalIndent(authRecord, "", "  ")
				if err == nil {
					targetSlug := shortTarget(input.Target)
					_ = os.WriteFile(filepath.Join(findingsDir, fmt.Sprintf("auth-%s.json", targetSlug)), authData, 0644)
					if cleanHost != "" && cleanHost != input.Target {
						hostSlug := shortTarget(cleanHost)
						_ = os.WriteFile(filepath.Join(findingsDir, fmt.Sprintf("auth-%s.json", hostSlug)), authData, 0644)
					}
				}
			}

			ctx.Log("Audit run started: %s (target=%s, kind=%s)", runID, input.Target, targetKind)

			return map[string]interface{}{
				"run_id":          runID,
				"status":          "running",
				"target":          input.Target,
				"target_kind":     targetKind,
				"artifacts_dir":   artifactsDir,
				"manifest_path":   manifestPath,
				"created_at":      manifest.CreatedAt,
				"phase_artifacts": []string{},
			}, nil
		},
	)
}

func RegisterAuditRunPhase(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "audit.run.phase",
			Description: "Record a phase artifact in an active audit run. Each phase captures findings, notes, and requested tools.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"run_id": {
						Type:        "string",
						Description: "Audit run identifier returned by audit.run.start",
					},
					"phase": {
						Type:        "string",
						Description: "Phase name (e.g. reconnaissance, scanning, exploitation, reporting)",
					},
					"status": {
						Type:        "string",
						Description: "Phase status: pending, running, completed, failed, skipped",
					},
					"findings": {
						Type:        "array",
						Description: "List of finding identifiers or descriptions from this phase",
						Items:       &mcp.Items{Type: "string"},
					},
					"notes": {
						Type:        "string",
						Description: "Free-form notes about this phase",
					},
					"requested_tools": {
						Type:        "array",
						Description: "Tools requested or used during this phase",
						Items:       &mcp.Items{Type: "string"},
					},
					"summary": {
						Type:        "string",
						Description: "Brief summary of phase results",
					},
					"artifacts_dir": {
						Type:        "string",
						Description: "Override artifacts directory for this run",
					},
					"memoryDir": {
						Type:        "string",
						Description: "Override memory directory",
					},
				},
				Required: []string{"run_id", "phase"},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				RunID          string   `json:"run_id"`
				Phase          string   `json:"phase"`
				Status         string   `json:"status,omitempty"`
				Findings       []string `json:"findings,omitempty"`
				Notes          string   `json:"notes,omitempty"`
				RequestedTools []string `json:"requested_tools,omitempty"`
				Summary        string   `json:"summary,omitempty"`
				ArtifactsDir   string   `json:"artifacts_dir,omitempty"`
				MemoryDir      string   `json:"memoryDir,omitempty"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid params: " + err.Error()}
			}

			if input.Status == "" {
				input.Status = "completed"
			}

			artifactsDir := input.ArtifactsDir
			if artifactsDir == "" {
				dir, errObj := resolveRunArtifactsDir(ctx.MemoryDir, input.RunID)
				if errObj != nil {
					return nil, errObj
				}
				artifactsDir = dir
			}

			manifestPath := filepath.Join(artifactsDir, "manifest.json")
			manifestData, err := os.ReadFile(manifestPath)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: fmt.Sprintf("Run %s not found at %s", input.RunID, manifestPath)}
			}

			var manifest RunManifest
			if err := json.Unmarshal(manifestData, &manifest); err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "Failed to parse manifest: " + err.Error()}
			}
			// El artefacto y la respuesta usan el run_id canónico del manifest,
			// no el identificador (campaign o run_id) que pasó el agente.
			canonicalRunID := manifest.RunID

			phaseArtifact := PhaseArtifact{
				RunID:          canonicalRunID,
				Phase:          input.Phase,
				Status:         input.Status,
				Findings:       input.Findings,
				Notes:          input.Notes,
				RequestedTools: input.RequestedTools,
				Summary:        input.Summary,
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
			}

			phaseFilename := fmt.Sprintf("phase-%s.json", input.Phase)
			phasePath := filepath.Join(artifactsDir, phaseFilename)
			phaseData, err := json.MarshalIndent(phaseArtifact, "", "  ")
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "Failed to encode phase artifact: " + err.Error()}
			}
			if err := os.WriteFile(phasePath, phaseData, 0644); err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "Failed to write phase artifact: " + err.Error()}
			}

			manifest.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			manifest.Status = "running"
			manifest.PhaseArtifacts = append(manifest.PhaseArtifacts, phaseFilename)
			updatedManifest, _ := json.MarshalIndent(manifest, "", "  ")
			os.WriteFile(manifestPath, updatedManifest, 0644)

			ctx.Log("Phase artifact written: run=%s phase=%s status=%s", canonicalRunID, input.Phase, input.Status)

			return map[string]interface{}{
				"run_id":               canonicalRunID,
				"run_id_resolved_from": input.RunID,
				"artifacts_dir":        artifactsDir,
				"phase":                input.Phase,
				"status":               input.Status,
				"phase_path":           phasePath,
				"timestamp":            phaseArtifact.Timestamp,
			}, nil
		},
	)
}

func RegisterAuditRunInspect(s *mcp.Server) {
	readOnly := mcp.BoolPtr(true)

	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "audit.run.inspect",
			Description: "Inspect a completed or in-progress audit run. Returns the full run manifest and all phase artifacts.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"run_id": {
						Type:        "string",
						Description: "Audit run identifier to inspect",
					},
					"artifacts_dir": {
						Type:        "string",
						Description: "Override artifacts directory for this run",
					},
				},
				Required: []string{"run_id"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: readOnly,
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				RunID        string `json:"run_id"`
				ArtifactsDir string `json:"artifacts_dir,omitempty"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid params: " + err.Error()}
			}

			artifactsDir := input.ArtifactsDir
			if artifactsDir == "" {
				dir, errObj := resolveRunArtifactsDir(ctx.MemoryDir, input.RunID)
				if errObj != nil {
					return nil, errObj
				}
				artifactsDir = dir
			}

			manifestPath := filepath.Join(artifactsDir, "manifest.json")
			manifestData, err := os.ReadFile(manifestPath)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: fmt.Sprintf("Run %s not found at %s", input.RunID, manifestPath)}
			}

			var manifest RunManifest
			if err := json.Unmarshal(manifestData, &manifest); err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "Failed to parse manifest: " + err.Error()}
			}

			phases := []PhaseArtifact{}
			entries, err := os.ReadDir(artifactsDir)
			if err == nil {
				for _, entry := range entries {
					if entry.IsDir() || !strings.HasPrefix(entry.Name(), "phase-") {
						continue
					}
					data, err := os.ReadFile(filepath.Join(artifactsDir, entry.Name()))
					if err != nil {
						continue
					}
					var phase PhaseArtifact
					if err := json.Unmarshal(data, &phase); err != nil {
						continue
					}
					phases = append(phases, phase)
				}
			}

			if phases == nil {
				phases = []PhaseArtifact{}
			}

			return map[string]interface{}{
				"manifest":             manifest,
				"phases":               phases,
				"run_id":               manifest.RunID,
				"run_id_resolved_from": input.RunID,
				"status":               manifest.Status,
			}, nil
		},
	)
}

type CorrelatedResult struct {
	CWE         string `json:"cwe"`
	Count       int    `json:"count"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type CorrelateOutput struct {
	RunID      string             `json:"run_id"`
	Campaign   string             `json:"campaign,omitempty"`
	Total      int                `json:"total_findings"`
	Deduped    int                `json:"deduplicated"`
	OutOfScope int                `json:"out_of_scope_skipped"`
	ByCWE      []CorrelatedResult `json:"by_cwe"`
	BySeverity map[string]int     `json:"by_severity"`
	OWASPTop10 []string           `json:"owasp_top10_related,omitempty"`
}

// normalizeDedupKey construye la clave de deduplicación.
//
// La clave anterior (`título | target | cwe` en crudo) no decía QUÉ es un
// bug: dos agentes que describían el MISMO hallazgo con distinta prosa
// contaban como dos, y en un run real dio `deduplicated: 0` sobre 180
// entradas con duplicados evidentes.
//
// Ahora la identidad es taxonómica — (CWE, target normalizado, vector
// normalizado) — la misma que usa el backend para el fingerprint v2
// (packages/core/src/security/ingest.ts), para que la deduplicación
// funcione también entre agentes.
//
// SPEC COMPARTIDA CON TS: la normalización de target y vector está
// implementada en packages/core/src/security/ingest.ts
// (normalizeTargetIdentity / normalizeVectorIdentity). Si se cambia una,
// hay que cambiar la otra: la deduplicación cross-agente depende de que
// ambos digan exactamente lo mismo.
func normalizeDedupKey(title, target, cwe, vector string) string {
	normalizedCWE := normalizeCWE(cwe)
	t := normalizeTargetIdentity(target)
	v := normalizeVectorIdentity(vector)
	if normalizedCWE != "" && t != "" && v != "" {
		return "v2|" + normalizedCWE + "|" + t + "|" + v
	}
	// Sin vector explícito no se fusiona por (CWE + target): eso mezclaría,
	// por ejemplo, dos parámetros vulnerables del mismo endpoint.
	return "v1|" + normalizedCWE + "|" + normalizeIdentityText(title) + "|" + t + "|" + v
}

// normalizeIdentityText: trim + lowercase + colapso de los espacios internos.
func normalizeIdentityText(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

// normalizeTargetIdentity reduce un target a su identidad canónica:
// sin esquema, sin query string, sin fragment, sin puerto por defecto y sin
// barras finales. Un servicio en :8080 conserva el puerto — es otro target.
//
// SPEC COMPARTIDA CON TS — packages/core/src/security/ingest.ts.
func normalizeTargetIdentity(value string) string {
	text := normalizeIdentityText(value)
	if text == "" {
		return ""
	}
	if i := strings.Index(text, "#"); i >= 0 {
		text = text[:i]
	}
	if i := strings.Index(text, "?"); i >= 0 {
		text = text[:i]
	}
	if i := strings.Index(text, "://"); i >= 0 {
		text = text[i+3:]
	}
	authority := text
	rest := ""
	if i := strings.Index(text, "/"); i >= 0 {
		authority = text[:i]
		rest = text[i:]
	}
	host := authority
	if i := strings.LastIndex(authority, ":"); i > 0 {
		port := authority[i+1:]
		name := authority[:i]
		if name != "" && (port == "80" || port == "443") {
			host = name
		}
	}
	return strings.TrimRight(host+rest, "/")
}

// normalizeVectorIdentity conserva los nombres de los parámetros de query,
// pero elimina sus valores variables para distinguir parámetros sin crear
// una identidad distinta por cada payload. Conserva esquema y puerto.
//
// SPEC COMPARTIDA CON TS — packages/core/src/security/ingest.ts.
func normalizeVectorIdentity(value string) string {
	text := normalizeIdentityText(value)
	if text == "" {
		return ""
	}
	if i := strings.Index(text, "#"); i >= 0 {
		text = text[:i]
	}
	queryIndex := strings.Index(text, "?")
	path := text
	query := ""
	if queryIndex >= 0 {
		path = text[:queryIndex]
		query = text[queryIndex+1:]
	}
	parameters := make([]string, 0)
	for _, parameter := range strings.Split(query, "&") {
		name := strings.TrimSpace(strings.SplitN(parameter, "=", 2)[0])
		if name != "" {
			parameters = append(parameters, name)
		}
	}
	sort.Strings(parameters)
	normalizedPath := strings.TrimRight(path, "/")
	if len(parameters) == 0 {
		return normalizedPath
	}
	return normalizedPath + "?" + strings.Join(parameters, "&")
}

// normalizeCWE normaliza un identificador CWE a la forma canónica "CWE-NNN".
// Acepta "CWE-89", "cwe 89" y el "89" pelado; devuelve "" cuando el valor no
// parsea (un CWE inventado es peor que un CWE ausente).
//
// SPEC COMPARTIDA CON TS — normalizeContractCwe en
// packages/core/src/security/contract.ts.
func normalizeCWE(value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return ""
	}
	upper := strings.ToUpper(raw)
	digits := upper
	if strings.HasPrefix(upper, "CWE") {
		digits = strings.TrimLeft(upper[3:], "-_ \t\r\n")
	}
	if digits == "" || len(digits) > 6 {
		return ""
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return "CWE-" + digits
}

var cweDescription = map[string]string{
	"CWE-79":  "Improper Neutralization of Input During Web Page Generation (XSS)",
	"CWE-89":  "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
	"CWE-22":  "Path Traversal",
	"CWE-352": "Cross-Site Request Forgery (CSRF)",
	"CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
	"CWE-287": "Improper Authentication",
	"CWE-434": "Unrestricted Upload of File with Dangerous Type",
	"CWE-78":  "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
	"CWE-918": "Server-Side Request Forgery (SSRF)",
	"CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
}

var cweToOWASP = map[string]string{
	"CWE-79":  "A7 - Cross-Site Scripting (XSS)",
	"CWE-89":  "A3 - Injection",
	"CWE-22":  "A5 - Security Misconfiguration",
	"CWE-352": "A1 - Broken Access Control",
	"CWE-200": "A1 - Broken Access Control",
	"CWE-287": "A7 - Identification and Authentication Failures",
	"CWE-434": "A5 - Security Misconfiguration",
	"CWE-78":  "A3 - Injection",
	"CWE-918": "A10 - Server-Side Request Forgery (SSRF)",
	"CWE-611": "A5 - Security Misconfiguration",
}

var severityOrder = map[string]string{
	"CRITICAL": "CRITICAL",
	"HIGH":     "HIGH",
	"MEDIUM":   "MEDIUM",
	"LOW":      "LOW",
	"INFO":     "INFO",
}

func RegisterAuditRunCorrelate(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "audit.run.correlate",
			Description: "Correlate findings across all phases of an audit run. Deduplicates and enriches with CWE descriptions and OWASP Top 10 mappings.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"run_id": {
						Type:        "string",
						Description: "Audit run identifier to correlate",
					},
					"artifacts_dir": {
						Type:        "string",
						Description: "Override artifacts directory for this run",
					},
					"memoryDir": {
						Type:        "string",
						Description: "Override memory directory for findings lookup",
					},
				},
				Required: []string{"run_id"},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				RunID        string `json:"run_id"`
				ArtifactsDir string `json:"artifacts_dir,omitempty"`
				MemoryDir    string `json:"memoryDir,omitempty"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid params: " + err.Error()}
			}

			artifactsDir := input.ArtifactsDir
			if artifactsDir == "" {
				dir, errObj := resolveRunArtifactsDir(ctx.MemoryDir, input.RunID)
				if errObj != nil {
					return nil, errObj
				}
				artifactsDir = dir
			}

			manifestPath := filepath.Join(artifactsDir, "manifest.json")
			manifestData, err := os.ReadFile(manifestPath)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: fmt.Sprintf("Run %s not found at %s", input.RunID, manifestPath)}
			}

			var manifest RunManifest
			if err := json.Unmarshal(manifestData, &manifest); err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "Failed to parse manifest: " + err.Error()}
			}

			findingsDir := filepath.Join(ctx.MemoryDir, "findings")
			allFindings := []Finding{}
			seen := map[string]bool{}
			dedupCount := 0
			outOfScope := 0

			// El store de memoria es COMPARTIDO entre campañas. Antes se leía
			// entero sin filtrar, así que la correlación de un run mezclaba
			// hallazgos de otros engagements (CWEs de targets que ni siquiera
			// estaban en alcance) y las cifras no significaban nada. El manifiesto
			// declara su `campaign`, que es exactamente el valor que los agentes
			// escriben en el campo `session` de cada hallazgo: se usa para acotar.
			//
			// Si el run no declara campaña no se puede acotar; en ese caso se
			// mantiene el comportamiento anterior en vez de devolver vacío, pero
			// el resultado expone `out_of_scope_skipped: 0` para que quede claro
			// que no hubo filtrado.
			campaign := strings.TrimSpace(manifest.Campaign)

			entries, err := os.ReadDir(findingsDir)
			if err == nil {
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
					if finding.Kind != "" && finding.Kind != "finding" {
						continue
					}
					if campaign != "" && !strings.EqualFold(strings.TrimSpace(finding.Session), campaign) {
						outOfScope++
						continue
					}
					dedupKey := normalizeDedupKey(finding.Title, finding.Target, finding.CWE, finding.Vector)
					if seen[dedupKey] {
						dedupCount++
						continue
					}
					seen[dedupKey] = true
					allFindings = append(allFindings, finding)
				}
			}

			cweGroups := map[string][]Finding{}
			severityCounts := map[string]int{}
			owaspSet := map[string]bool{}

			for _, f := range allFindings {
				cwe := f.CWE
				if cwe == "" {
					cwe = "CWE-NONE"
				}
				cweGroups[cwe] = append(cweGroups[cwe], f)

				sev := f.Severity
				if _, ok := severityOrder[sev]; !ok {
					sev = "INFO"
				}
				severityCounts[sev]++

				if owasp, ok := cweToOWASP[cwe]; ok {
					owaspSet[owasp] = true
				}
			}

			byCWE := []CorrelatedResult{}
			for cwe, findings := range cweGroups {
				desc := cweDescription[cwe]
				if desc == "" {
					desc = "Security finding"
				}
				highest := "INFO"
				for _, f := range findings {
					fs := f.Severity
					switch fs {
					case "CRITICAL":
						highest = "CRITICAL"
					case "HIGH":
						if highest != "CRITICAL" {
							highest = "HIGH"
						}
					case "MEDIUM":
						if highest != "CRITICAL" && highest != "HIGH" {
							highest = "MEDIUM"
						}
					case "LOW":
						if highest != "CRITICAL" && highest != "HIGH" && highest != "MEDIUM" {
							highest = "LOW"
						}
					}
				}
				byCWE = append(byCWE, CorrelatedResult{
					CWE:         cwe,
					Count:       len(findings),
					Severity:    highest,
					Description: desc,
				})
			}

			owaspList := []string{}
			for o := range owaspSet {
				owaspList = append(owaspList, o)
			}

			if byCWE == nil {
				byCWE = []CorrelatedResult{}
			}
			if severityCounts == nil {
				severityCounts = map[string]int{}
			}
			if owaspList == nil {
				owaspList = []string{}
			}

			result := CorrelateOutput{
				RunID:      manifest.RunID,
				Campaign:   campaign,
				Total:      len(allFindings) + dedupCount,
				Deduped:    dedupCount,
				OutOfScope: outOfScope,
				ByCWE:      byCWE,
				BySeverity: severityCounts,
				OWASPTop10: owaspList,
			}

			return result, nil
		},
	)
}
