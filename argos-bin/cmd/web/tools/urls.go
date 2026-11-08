package tools

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

func RegisterUrls(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.urls",
			Description: "Discover historical URLs for a domain with gau (wayback/urlscan/commoncrawl/otx).",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"domain":  {Type: "string", Description: "Root domain, e.g. example.com"},
					"limit":   {Type: "integer", Description: "Max URLs to return (default 200)"},
					"timeout": {Type: "integer", Description: "Gau timeout in seconds (default 60, max 300)"},
				},
				Required: []string{"domain"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Domain  string `json:"domain"`
				Limit   int    `json:"limit"`
				Timeout int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			domain, e := validateDomainWithEnv(env, input.Domain)
			if e != nil {
				return nil, e
			}
			limit := input.Limit
			if limit <= 0 {
				limit = 200
			}
			timeout := clampTimeout(input.Timeout, 60)

			bin, installed, e := env.Binary(toolContext(ctx), "gau")
			if e != nil {
				return nil, e
			}
			r := run(toolContext(ctx), bin, runOptions{
				Args:    []string{"--threads", "3", "--timeout", "10", domain},
				Timeout: time.Duration(timeout) * time.Second,
			})
			urls := parseGau(r.Output, limit)

			res := baseResult("web.urls", domain, r)
			res["urls"] = urls
			res["summary"] = fmt.Sprintf("%d URLs históricas", len(urls))
			if installed {
				res["installed"] = "gau " + env.Spec("gau").Version
			}
			return res, nil
		},
	)
}
