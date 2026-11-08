package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/contract"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/traffic"
)

// maxTrafficBodyChars is how much of a body the tools return.
//
// El store en disco tiene el body completo: la tool lo trunca para que el
// agente no se coma un dump de 2 MB por exchange.
const maxTrafficBodyChars = 4000

// maxTrafficHistoryEntries is how many exchanges `web.history` returns.
const maxTrafficHistoryEntries = 500

// RegisterTraffic registers the HTTP traffic tools of the session.
//
// Son las tres piezas que Burp Pro llama Repeater, Comparer e historial, y
// que Argos no tenía: sin un store de tráfico el auditor no puede re-ver la
// request exacta que una tool emitió, ni compararla con una segunda
// respuesta, ni reenviarla con una modificación.
func RegisterTraffic(s *mcp.Server, env *Env) {
	registerTrafficHistory(s, env)
	registerTrafficReplay(s, env)
	registerTrafficCompare(s, env)
}

// trafficStore returns the traffic store of the session, bound to the
// scope-bound client of the engagement.
//
// El cliente es SIEMPRE env.Client(): un http.Client propio se saltaría el
// IP-pinning, el rate limit y el audit log encadenado del ScopeGuard.
func trafficStore(ctx mcp.ToolContext, env *Env) *traffic.Store {
	var validator traffic.ScopeValidator
	if env != nil && env.Scope != nil {
		validator = env.Scope
	}
	return traffic.NewStoreWithScope(ctx.MemoryDir, env.Client(), validator)
}

// trafficSessionID resolves the session the tools work on.
//
// El store de tráfico es por sesión: sin Session ID no hay forma de saber a
// qué sesión pertenece un exchange.
func trafficSessionID(ctx mcp.ToolContext) (string, error) {
	sessionID := strings.TrimSpace(ctx.SessionID)
	if sessionID == "" {
		return "", fmt.Errorf("no session id: the traffic store is per session")
	}
	if !contract.IsSessionID(sessionID) {
		return "", fmt.Errorf("invalid session context for the traffic store")
	}
	return sessionID, nil
}

// exchangeSummary renders an exchange for the tool response.
func exchangeSummary(ex traffic.Exchange) map[string]interface{} {
	return map[string]interface{}{
		"id":                   ex.ID,
		"timestamp":            ex.Timestamp.UTC().Format(time.RFC3339),
		"method":               ex.Method,
		"url":                  ex.URL,
		"host":                 traffic.HostOf(ex),
		"status":               ex.Status,
		"duration_ms":          ex.DurationMs,
		"source_tool":          ex.SourceTool,
		"target":               ex.Target,
		"scope_allowed":        ex.ScopeAllowed,
		"request_headers":      ex.Headers,
		"response_headers":     ex.ResponseHeaders,
		"request_body":         truncateTrafficBody(ex.RequestBody),
		"response_body":        truncateTrafficBody(ex.ResponseBody),
		"request_body_size":    len(ex.RequestBody),
		"response_body_size":   len(ex.ResponseBody),
		"response_body_sha256": traffic.BodyHash(ex.ResponseBody),
	}
}

// truncateTrafficBody truncates a body for the tool response.
func truncateTrafficBody(body []byte) string {
	if len(body) <= maxTrafficBodyChars {
		return string(body)
	}
	return string(body[:maxTrafficBodyChars]) + "\n... (truncated)"
}

// captureTrafficExchange records one scope-bound probe of the target in the
// traffic store.
//
// Solo corre cuando el operador encendió la captura
// (ARGOS_TRAFFIC_CAPTURE=1): por defecto la tool no emite nada extra ni
// escribe a disco. Es el patrón para las tools que no tienen la request y la
// response a mano porque delegan en un binario externo (httpx, tlsx): la
// tool hace su trabajo con su binario y, aparte, deja en el store una
// request reproducible que el auditor puede reenviar y comparar.
func captureTrafficExchange(ctx mcp.ToolContext, env *Env, sourceTool, target string) (traffic.Exchange, bool) {
	if !traffic.CaptureEnabled() {
		return traffic.Exchange{}, false
	}
	traffic.WarnCaptureEnabled()
	sessionID, err := trafficSessionID(ctx)
	if err != nil {
		return traffic.Exchange{}, false
	}
	store := trafficStore(ctx, env)
	exchange, err := traffic.Probe(toolContext(ctx), store, env.Client(), target, traffic.Meta{
		SessionID:  sessionID,
		SourceTool: sourceTool,
		Target:     target,
	})
	if err != nil {
		ctx.Log("warning: cannot capture the traffic of %s: %v", target, err)
		return traffic.Exchange{}, false
	}
	return exchange, true
}

// trafficProbeURL derives the URL of the probe request from a target.
func trafficProbeURL(target string) string {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	return "https://" + raw
}

// registerTrafficHistory registers `web.history`.
func registerTrafficHistory(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.history",
			Description: "List the HTTP exchanges captured during the session, with filters by host, method, status and source tool. Returns a summary table (bodies truncated).",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"host":   {Type: "string", Description: "Filter by host (substring match)"},
					"method": {Type: "string", Description: "Filter by HTTP method (GET, POST, ...)"},
					"status": {Type: "string", Description: "Filter by status code or class (404, 4xx)"},
					"tool":   {Type: "string", Description: "Filter by the tool that produced the traffic (web.probe, web.tls, ...)"},
					"limit":  {Type: "integer", Description: "Maximum number of exchanges to return (default 100, max 500)"},
				},
			},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			scopedEnv, releaseScope, scopeError := scopedToolEnvironment(env, ctx)
			if scopeError != nil {
				return nil, scopeError
			}
			defer releaseScope()
			env := scopedEnv
			var input struct {
				Host   string `json:"host"`
				Method string `json:"method"`
				Status string `json:"status"`
				Tool   string `json:"tool"`
				Limit  int    `json:"limit"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			sessionID, err := trafficSessionID(ctx)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: err.Error()}
			}
			limit := input.Limit
			if limit <= 0 {
				limit = 100
			}
			if limit > maxTrafficHistoryEntries {
				limit = maxTrafficHistoryEntries
			}

			store := trafficStore(ctx, env)
			exchanges, total := store.List(sessionID, traffic.Filter{
				Host:       input.Host,
				Method:     input.Method,
				Status:     input.Status,
				SourceTool: input.Tool,
			})

			// Lo más reciente primero: el exchange que el auditor acaba de
			// provocar es el que está arriba.
			if len(exchanges) > limit {
				exchanges = exchanges[len(exchanges)-limit:]
			}
			summaries := make([]map[string]interface{}, 0, len(exchanges))
			for i := len(exchanges) - 1; i >= 0; i-- {
				summaries = append(summaries, exchangeSummary(exchanges[i]))
			}

			return map[string]interface{}{
				"status":     "completed",
				"session_id": sessionID,
				"total":      total,
				"count":      len(summaries),
				"exchanges":  summaries,
				"summary":    fmt.Sprintf("%d exchanges (of %d in the session)", len(summaries), total),
			}, nil
		},
	)
}

// registerTrafficReplay registers `web.replay`.
func registerTrafficReplay(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.replay",
			Description: "Re-send a captured HTTP exchange, optionally overriding the method, URL, headers or body. " +
				"Returns the new status, headers, truncated body and the structural diff against the original. " +
				"The request goes through the scope-bound client: an override that leaves the authorized scope is rejected before any request is emitted.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"exchange_id": {Type: "string", Description: "Exchange ID (from web.history)"},
					"method":      {Type: "string", Description: "Override the HTTP method"},
					"url":         {Type: "string", Description: "Override the URL (must stay inside the authorized scope)"},
					"headers":     {Type: "object", Description: "Headers to set or override, as name/value pairs"},
					"body":        {Type: "string", Description: "Override the request body"},
				},
				Required: []string{"exchange_id"},
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
				ExchangeID string            `json:"exchange_id"`
				Method     string            `json:"method"`
				URL        string            `json:"url"`
				Headers    map[string]string `json:"headers"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			if strings.TrimSpace(input.ExchangeID) == "" {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "exchange_id is required"}
			}
			sessionID, err := trafficSessionID(ctx)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: err.Error()}
			}

			overrides := traffic.Overrides{
				Method:  input.Method,
				URL:     input.URL,
				Headers: input.Headers,
			}
			// Un body vacío puede ser un override legítimo (una request sin
			// payload), así que la presencia se decide por el JSON crudo.
			if raw, ok := rawBody(params); ok {
				overrides.Body = []byte(raw)
			}

			store := trafficStore(ctx, env)
			original, ok := store.Get(sessionID, input.ExchangeID)
			if !ok {
				return nil, &mcp.ErrorObj{Code: -32602, Message: fmt.Sprintf("exchange %q not found in session %s", input.ExchangeID, sessionID)}
			}

			replayed, err := store.Replay(toolContext(ctx), sessionID, input.ExchangeID, overrides)
			if err != nil {
				// Un target fuera de scope no es un fallo de la tool: es un
				// veredicto del guard. El mensaje lo dice explícitamente.
				if strings.Contains(err.Error(), "SCOPE ENFORCEMENT") {
					return nil, &mcp.ErrorObj{Code: -32600, Message: err.Error()}
				}
				return nil, &mcp.ErrorObj{Code: -32603, Message: err.Error()}
			}

			diff, err := store.Diff(sessionID, original.ID, replayed.ID)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: err.Error()}
			}

			return map[string]interface{}{
				"status":           "completed",
				"session_id":       sessionID,
				"exchange_id":      replayed.ID,
				"original_id":      original.ID,
				"method":           replayed.Method,
				"url":              replayed.URL,
				"status_code":      replayed.Status,
				"duration_ms":      replayed.DurationMs,
				"response_headers": replayed.ResponseHeaders,
				"response_body":    truncateTrafficBody(replayed.ResponseBody),
				"changed":          !diff.Identical,
				"diff":             diff,
				"summary": fmt.Sprintf(
					"replayed %s -> %d (%s)",
					replayed.URL,
					replayed.Status,
					map[bool]string{true: "changed", false: "identical"}[!diff.Identical],
				),
			}, nil
		},
	)
}

// rawBody reports whether the caller sent a `body` field, and its value.
//
// La presencia importa: `body: ""` es un override legítimo (una request sin
// payload) y no puede confundirse con "no lo mandaste".
func rawBody(params json.RawMessage) (string, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(params, &raw); err != nil {
		return "", false
	}
	value, ok := raw["body"]
	if !ok {
		return "", false
	}
	var text string
	if err := json.Unmarshal(value, &text); err != nil {
		return "", false
	}
	return text, true
}

// registerTrafficCompare registers `web.compare`.
func registerTrafficCompare(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.compare",
			Description: "Compare two captured HTTP exchanges: status, headers added/removed/changed and a unified diff of the response bodies.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"a_id": {Type: "string", Description: "First exchange ID (from web.history)"},
					"b_id": {Type: "string", Description: "Second exchange ID (from web.history)"},
				},
				Required: []string{"a_id", "b_id"},
			},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			scopedEnv, releaseScope, scopeError := scopedToolEnvironment(env, ctx)
			if scopeError != nil {
				return nil, scopeError
			}
			defer releaseScope()
			env := scopedEnv
			var input struct {
				AID string `json:"a_id"`
				BID string `json:"b_id"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			if strings.TrimSpace(input.AID) == "" || strings.TrimSpace(input.BID) == "" {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "a_id and b_id are required"}
			}
			sessionID, err := trafficSessionID(ctx)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: err.Error()}
			}

			store := trafficStore(ctx, env)
			diff, err := store.Diff(sessionID, input.AID, input.BID)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: err.Error()}
			}

			return map[string]interface{}{
				"status":     "completed",
				"session_id": sessionID,
				"diff":       diff,
				"summary": fmt.Sprintf(
					"%s: status %d -> %d, %d headers changed, %d body lines added",
					map[bool]string{true: "changed", false: "identical"}[!diff.Identical],
					diff.StatusA,
					diff.StatusB,
					len(diff.HeadersChanged)+len(diff.HeadersAdded)+len(diff.HeadersRemoved),
					diff.BodyLinesAdded,
				),
			}, nil
		},
	)
}
