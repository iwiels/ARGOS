package tools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

func RegisterXSS(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.xss",
			Description: "Automated XSS detection with dalfox (reflected/DOM, payload verification).",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":  {Type: "string", Description: "Target URL with parameter, e.g. https://example.com/search?q=1"},
					"timeout": {Type: "integer", Description: "Scan timeout in seconds (default 120, max 300)"},
				},
				Required: []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
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
			timeout := clampTimeout(input.Timeout, 120)

			bin, installed, e := env.Binary(toolContext(ctx), "dalfox")
			if e != nil {
				return nil, e
			}
			// dalfox v3 uses subcommands and dropped --no-spinner: `dalfox scan <target>`
			r := run(toolContext(ctx), bin, runOptions{
				Args:    []string{"scan", target, "--format", "json", "--silence", "--timeout", "15"},
				Timeout: time.Duration(timeout) * time.Second,
			})
			fs := parseDalfox(r.Output, target)
			fs = attachXssPocs(fs)
			fs, truncated := capFindings(fs)

			res := baseResult("web.xss", target, r)
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d posibles XSS", len(fs))
			if installed {
				res["installed"] = "dalfox " + env.Spec("dalfox").Version
			}
			return res, nil
		},
	)
}

// attachXssPocs builds the proof of concept of every XSS finding: the request
// that reproduces the reflection and the matcher that checks whether the
// payload is still reflected.
//
// dalfox does not expose the body of the response it found, so the PoC
// travels without baseline: the re-test can still tell whether the payload
// is reflected anymore, but with less confidence than a comparison against
// the original response.
func attachXssPocs(fs []Finding) []Finding {
	for i := range fs {
		evidence := fs[i].Evidence
		if evidence == nil {
			continue
		}
		payload, _ := evidence["payload"].(string)
		if strings.TrimSpace(payload) == "" {
			continue
		}
		method, _ := evidence["method"].(string)
		if strings.TrimSpace(method) == "" {
			method = http.MethodGet
		}
		attachPoc(evidence, &pocRecord{
			Kind:    "xss",
			Method:  strings.ToUpper(method),
			URL:     fs[i].Target,
			Payload: payload,
			Matcher: pocMatcherBodyAbsent(payload),
		})
	}
	return fs
}
