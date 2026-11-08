package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

func RegisterSubdomains(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.subdomains",
			Description: "Enumerate subdomains with subfinder (passive) and optionally resolve them with dnsx.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"domain":  {Type: "string", Description: "Root domain, e.g. example.com"},
					"resolve": {Type: "boolean", Description: "Resolve subdomains to IPs with dnsx (default true)"},
					"timeout": {Type: "integer", Description: "Enumeration timeout in seconds (default 90, max 300)"},
				},
				Required: []string{"domain"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Domain  string `json:"domain"`
				Resolve *bool  `json:"resolve"`
				Timeout int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			domain, e := validateDomainWithEnv(env, input.Domain)
			if e != nil {
				return nil, e
			}
			resolve := input.Resolve == nil || *input.Resolve
			timeout := clampTimeout(input.Timeout, 90)

			subBin, installed, e := env.Binary(toolContext(ctx), "subfinder")
			if e != nil {
				return nil, e
			}
			sr := run(toolContext(ctx), subBin, runOptions{
				Args:    []string{"-d", domain, "-silent", "-json"},
				Timeout: time.Duration(timeout) * time.Second,
			})
			subs := parseSubfinder(sr.Output)

			seen := map[string]bool{}
			for _, s := range subs {
				seen[s.Host] = true
			}
			hosts := make([]string, 0, len(seen))
			for h := range seen {
				hosts = append(hosts, h)
			}
			subdomains := make([]map[string]interface{}, 0, len(hosts))
			for _, h := range hosts {
				subdomains = append(subdomains, map[string]interface{}{"host": h})
			}

			ips := map[string][]string{}
			if resolve && len(hosts) > 0 {
				dnsBin, _, dnsErr := env.Binary(toolContext(ctx), "dnsx")
				if dnsErr == nil {
					dr := run(toolContext(ctx), dnsBin, runOptions{
						Args:    []string{"-a", "-silent", "-json"},
						Stdin:   strings.Join(hosts, "\n") + "\n",
						Timeout: time.Duration(timeout) * time.Second,
					})
					ips = parseDnsx(dr.Output)
				}
				for i := range subdomains {
					host := subdomains[i]["host"].(string)
					if v, ok := ips[host]; ok {
						subdomains[i]["ips"] = v
					}
				}
			}

			truncated := false
			if len(subdomains) > 300 {
				subdomains = subdomains[:300]
				truncated = true
			}
			res := baseResult("web.subdomains", domain, sr)
			res["subdomains"] = subdomains
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d subdominios (%d resueltos)", len(subdomains), len(ips))
			if installed {
				res["installed"] = "subfinder " + env.Spec("subfinder").Version
			}
			return res, nil
		},
	)
}
