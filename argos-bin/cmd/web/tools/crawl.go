package tools

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

func RegisterCrawl(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.crawl",
			Description: "Crawl the target with katana (supports headless for SPA/JS-rendered apps).",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":   {Type: "string", Description: "Target URL, e.g. https://example.com"},
					"depth":    {Type: "integer", Description: "Crawl depth (default 3)"},
					"headless": {Type: "boolean", Description: "Use headless browser for JS-heavy sites (default false)"},
					"timeout":  {Type: "integer", Description: "Crawl timeout in seconds (default 120, max 300)"},
				},
				Required: []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Target   string `json:"target"`
				Depth    int    `json:"depth"`
				Headless bool   `json:"headless"`
				Timeout  int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			depth := input.Depth
			if depth <= 0 {
				depth = 3
			}
			timeout := clampTimeout(input.Timeout, 120)

			bin, installed, e := env.Binary(toolContext(ctx), "katana")
			if e != nil {
				return nil, e
			}
			args := []string{"-u", target, "-d", fmt.Sprintf("%d", depth), "-jsonl", "-silent", "-no-color"}
			if input.Headless {
				args = append(args, "-headless")
			}
			r := run(toolContext(ctx), bin, runOptions{Args: args, Timeout: time.Duration(timeout) * time.Second})
			endpoints := parseKatana(r.Output)
			if len(endpoints) > 500 {
				endpoints = endpoints[:500]
			}

			res := baseResult("web.crawl", target, r)
			res["endpoints"] = endpoints
			res["summary"] = fmt.Sprintf("%d endpoints descubiertos", len(endpoints))
			if installed {
				res["installed"] = "katana " + env.Spec("katana").Version
			}
			return res, nil
		},
	)
}
