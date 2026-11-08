package tools

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

func evaluateCMSExecution(tech string, force bool) (map[string]interface{}, bool) {
	if force {
		return nil, false
	}
	t := strings.ToLower(tech)
	if !strings.Contains(t, "wordpress") && !strings.Contains(t, "wp") {
		return map[string]interface{}{
			"status":      "skipped",
			"skip_reason": fmt.Sprintf("Technology '%s' does not match WordPress. Use force: true to override.", tech),
		}, true
	}
	return nil, false
}

func parseWpscanJSON(data []byte, target string) []Finding {
	var report map[string]interface{}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil
	}

	var fs []Finding
	// Parse version vulnerabilities
	if version, ok := report["version"].(map[string]interface{}); ok {
		if vulns, ok := version["vulnerabilities"].([]interface{}); ok {
			for _, v := range vulns {
				if vm, ok := v.(map[string]interface{}); ok {
					title, _ := vm["title"].(string)
					fs = append(fs, Finding{
						Source:     "web.cms",
						SourceTool: "web.cms",
						RuleID:     "wpscan:core",
						Title:      "WordPress Core: " + title,
						Severity:   SeverityHigh,
						Confidence: ConfidenceProbable,
						Target:     target,
						Evidence: map[string]any{
							"component": "core",
							"version":   fmt.Sprintf("%v", version["number"]),
							"title":     title,
						},
						Tags: []string{"dependency"},
					})
				}
			}
		}
	}

	// Parse plugins vulnerabilities
	if plugins, ok := report["plugins"].(map[string]interface{}); ok {
		for plugName, plugData := range plugins {
			if pm, ok := plugData.(map[string]interface{}); ok {
				if vulns, ok := pm["vulnerabilities"].([]interface{}); ok {
					for _, v := range vulns {
						if vm, ok := v.(map[string]interface{}); ok {
							title, _ := vm["title"].(string)
							fs = append(fs, Finding{
								Source:     "web.cms",
								SourceTool: "web.cms",
								RuleID:     "wpscan:plugin:" + plugName,
								Title:      fmt.Sprintf("WordPress Plugin '%s': %s", plugName, title),
								Severity:   SeverityHigh,
								Confidence: ConfidenceProbable,
								Target:     target,
								Evidence: map[string]any{
									"component": "plugin",
									"plugin":    plugName,
									"title":     title,
								},
								Tags: []string{"dependency", "supply-chain"},
							})
						}
					}
				}
			}
		}
	}
	return fs
}

func RegisterCMS(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.cms",
			Description: "Targeted CMS auditing (WordPress, plugins, themes, users) with WPScan and automatic Nuclei WordPress fallback.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":  {Type: "string", Description: "Target URL to inspect (e.g. https://example.com/blog)"},
					"tech":    {Type: "string", Description: "Detected technologies (from web.tech or web.probe)"},
					"force":   {Type: "boolean", Description: "Force scan even if WordPress wasn't detected in tech stack (default false)"},
					"timeout": {Type: "integer", Description: "Timeout in seconds (default 180, max 300)"},
				},
				Required: []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Target  string `json:"target"`
				Tech    string `json:"tech"`
				Force   bool   `json:"force"`
				Timeout int    `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}

			if skipRes, skip := evaluateCMSExecution(input.Tech, input.Force); skip {
				skipRes["tool"] = "web.cms"
				skipRes["target"] = target
				return skipRes, nil
			}

			timeout := clampTimeout(input.Timeout, 180)

			// Check if native wpscan executable is available
			wpscanBin, wpscanErr := exec.LookPath("wpscan")
			if wpscanErr == nil {
				args := []string{"--url", target, "--format", "json", "--stealthy", "--disable-tls-checks"}
				r := run(toolContext(ctx), wpscanBin, runOptions{
					Args:    args,
					Timeout: time.Duration(timeout) * time.Second,
				})
				fs := parseWpscanJSON([]byte(r.Output), target)
				fs, truncated := capFindings(fs)
				res := baseResult("web.cms", target, r)
				res["engine"] = "wpscan"
				env.publishFindings(res, fs)
				res["truncated"] = truncated
				res["summary"] = fmt.Sprintf("%d CMS vulnerabilities detected via WPScan", len(fs))
				return res, nil
			}

			// Fallback to Nuclei WordPress templates
			bin, installed, e := env.Binary(toolContext(ctx), "nuclei")
			if e != nil {
				return nil, e
			}

			args := []string{"-u", target, "-tags", "wordpress,wp-plugin", "-jsonl", "-silent", "-no-color"}
			r := run(toolContext(ctx), bin, runOptions{
				Args:    args,
				Timeout: time.Duration(timeout) * time.Second,
			})
			fs := parseNuclei(r.Output, target, "web.cms")
			fs, truncated := capFindings(fs)
			res := baseResult("web.cms", target, r)
			res["engine"] = "nuclei-wordpress-fallback"
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d CMS findings detected via Nuclei WordPress suite", len(fs))
			if installed {
				res["installed"] = "nuclei " + env.Spec("nuclei").Version
			}
			return res, nil
		},
	)
}
