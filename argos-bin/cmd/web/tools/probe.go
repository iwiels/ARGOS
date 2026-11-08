package tools

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

func RegisterProbe(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.probe",
			Description: "Probe live hosts/URLs with httpx: status, title, tech detection, and optional screenshot.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":     {Type: "string", Description: "Target URL, e.g. https://example.com"},
					"screenshot": {Type: "boolean", Description: "Take a headless screenshot (default false)"},
					"timeout":    {Type: "integer", Description: "Probe timeout in seconds (default 60, max 300)"},
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
				Target     string `json:"target"`
				Screenshot bool   `json:"screenshot"`
				Timeout    int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			timeout := clampTimeout(input.Timeout, 60)

			bin, installed, e := env.Binary(toolContext(ctx), "httpx")
			if e != nil {
				return nil, e
			}
			args := []string{"-u", target, "-json", "-silent", "-no-color",
				"-status-code", "-title", "-tech-detect", "-follow-redirects"}
			if input.Screenshot {
				args = append(args, "-screenshot")
			}
			r := run(toolContext(ctx), bin, runOptions{Args: args, Timeout: time.Duration(timeout) * time.Second})
			endpoints := parseHttpx(r.Output)

			res := baseResult("web.probe", target, r)
			res["endpoints"] = endpoints
			res["summary"] = fmt.Sprintf("%d hosts responden", len(endpoints))
			if installed {
				res["installed"] = "httpx " + env.Spec("httpx").Version
			}
			// El store de tráfico necesita la request y la response a mano:
			// httpx las tiene dentro de su propio proceso, así que la tool
			// deja una request reproducible en el store (solo cuando el
			// operador encendió la captura).
			if exchange, ok := captureTrafficExchange(ctx, env, "web.probe", target); ok {
				res["exchange_id"] = exchange.ID
			}
			return res, nil
		},
	)
}

func RegisterTech(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.tech",
			Description: "Technology fingerprinting with httpx -tech-detect.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":  {Type: "string", Description: "Target URL, e.g. https://example.com"},
					"timeout": {Type: "integer", Description: "Probe timeout in seconds (default 60, max 300)"},
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
				Timeout int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			timeout := clampTimeout(input.Timeout, 60)

			bin, installed, e := env.Binary(toolContext(ctx), "httpx")
			if e != nil {
				return nil, e
			}
			r := run(toolContext(ctx), bin, runOptions{
				Args:    []string{"-u", target, "-json", "-silent", "-no-color", "-tech-detect", "-status-code", "-title"},
				Timeout: time.Duration(timeout) * time.Second,
			})
			endpoints := parseHttpx(r.Output)

			res := baseResult("web.tech", target, r)
			res["endpoints"] = endpoints
			var techs []string
			if len(endpoints) > 0 {
				techs = endpoints[0].Tech
			}
			res["technologies"] = techs
			res["summary"] = fmt.Sprintf("%d tecnologías detectadas", len(techs))
			if installed {
				res["installed"] = "httpx " + env.Spec("httpx").Version
			}
			return res, nil
		},
	)
}
