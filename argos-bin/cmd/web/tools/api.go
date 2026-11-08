package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

func RegisterApi(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.api",
			Description: "REST API testing and fuzzing powered by schemathesis against OpenAPI/Swagger specs (OWASP API Top 10: IDOR/BOLA, BFLA, status conformance).",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"schema":      {Type: "string", Description: "URL or local path to OpenAPI/Swagger specification"},
					"base_url":    {Type: "string", Description: "Base URL of the target API"},
					"auth_header": {Type: "string", Description: "Authorization header (e.g. 'Bearer <token>')"},
					"checks": {
						Type:        "array",
						Description: "Checks to enable (default: not_a_server_error, status_code_conformance)",
						Items:       &mcp.Items{Type: "string"},
					},
					"timeout": {Type: "integer", Description: "Execution timeout in seconds (default 120, max 300)"},
				},
				Required: []string{"schema"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Schema     string   `json:"schema"`
				BaseURL    string   `json:"base_url"`
				AuthHeader string   `json:"auth_header"`
				Checks     []string `json:"checks"`
				Timeout    int      `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			if input.Schema == "" {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "schema parameter is required"}
			}

			targetForScope := input.BaseURL
			if targetForScope == "" && strings.HasPrefix(input.Schema, "http") {
				targetForScope = input.Schema
			}
			if targetForScope != "" {
				if _, e := validateWebTargetWithToolContext(env, ctx, targetForScope); e != nil {
					return nil, e
				}
			}

			timeout := clampTimeout(input.Timeout, 120)

			bin, installed, e := env.Binary(toolContext(ctx), "schemathesis")
			if e != nil {
				return nil, e
			}
		schemaTarget, sourceRoot, remoteSchema, err := schemathesisSchemaTarget(input.Schema)
		if err != nil {
			return nil, invalidParams(err)
		}
		if remoteSchema {
			sourceRoot, err = os.MkdirTemp("", "argos-schemathesis-source-")
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "failed to create isolated API source directory: " + err.Error()}
			}
			defer os.RemoveAll(sourceRoot)
		}
		artifactDir, err := os.MkdirTemp("", "argos-schemathesis-artifacts-")
		if err != nil {
			return nil, &mcp.ErrorObj{Code: -32603, Message: "failed to create API report directory: " + err.Error()}
		}
		defer os.RemoveAll(artifactDir)
		if pathsOverlapLocal(sourceRoot, artifactDir) {
			return nil, &mcp.ErrorObj{Code: -32603, Message: "API report directory must be outside the read-only schema source; configure the system temporary directory outside the project"}
		}
		reportPath := filepath.Join(artifactDir, "schemathesis-report.json")

			args := []string{"run", schemaTarget}
			if input.BaseURL != "" {
				args = append(args, "--base-url", input.BaseURL)
			}
			if input.AuthHeader != "" {
				header := input.AuthHeader
				if !strings.Contains(header, ":") {
					header = "Authorization: " + header
				}
				args = append(args, "-H", header)
			}
			if len(input.Checks) > 0 {
				for _, c := range input.Checks {
					args = append(args, "--checks", c)
				}
			} else {
				args = append(args, "--checks", "not_a_server_error", "--checks", "status_code_conformance")
			}

			r := run(toolContext(ctx), bin, schemathesisRunOptions(args, sourceRoot, reportPath, time.Duration(timeout)*time.Second))

			target := input.BaseURL
			if target == "" {
				target = input.Schema
			}

			reportData, reportErr := os.ReadFile(reportPath)
			fs, parseErr := parseSchemathesisReport(reportData, target)
			if reportErr != nil {
				parseErr = fmt.Errorf("read Schemathesis report: %w", reportErr)
			}
			if parseErr != nil {
				markRunIncomplete(r, parseErr.Error())
				fs = nil
			}

			fs, truncated := capFindings(fs)
			res := baseResult("web.api", target, r)
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			if r.ExitCode == 0 {
				res["summary"] = fmt.Sprintf("%d API findings", len(fs))
			} else {
				res["summary"] = "API scan incomplete; no valid Schemathesis report was available"
			}
			if installed {
				res["installed"] = "schemathesis " + env.Spec("schemathesis").Version
			}
			return res, nil
		},
	)
}

func schemathesisSchemaTarget(schema string) (string, string, bool, error) {
	lower := strings.ToLower(strings.TrimSpace(schema))
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return schema, "", true, nil
	}
	absPath, err := filepath.Abs(schema)
	if err != nil {
		return "", "", false, fmt.Errorf("resolve API schema path: %w", err)
	}
	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", "", false, fmt.Errorf("API schema is unavailable: %w", err)
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return "", "", false, fmt.Errorf("inspect API schema: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", false, fmt.Errorf("API schema path must be a regular file")
	}
	return resolvedPath, filepath.Dir(resolvedPath), false, nil
}

func schemathesisRunOptions(args []string, sourceRoot, reportPath string, timeout time.Duration) runOptions {
	return runOptions{
		Args:        append(append([]string(nil), args...), "--report-v2-file", reportPath),
		Timeout:     timeout,
		Dir:         sourceRoot,
		ArtifactDir: filepath.Dir(reportPath),
	}
}

func parseSchemathesisReport(data []byte, target string) ([]Finding, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("Schemathesis report is empty")
	}
	var items []schemathesisItem
	if err := json.Unmarshal(data, &items); err == nil {
		for _, item := range items {
			if strings.TrimSpace(item.Check) == "" {
				return nil, fmt.Errorf("Schemathesis report contains an unsupported result")
			}
		}
		return parseSchemathesisJSON(data, target), nil
	}
	itemCount := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var item schemathesisItem
		if err := json.Unmarshal([]byte(line), &item); err != nil || strings.TrimSpace(item.Check) == "" {
			return nil, fmt.Errorf("Schemathesis report contains an unsupported result")
		}
		itemCount++
	}
	if itemCount == 0 {
		return nil, fmt.Errorf("Schemathesis report contains no recognized results")
	}
	return parseSchemathesisJSON(data, target), nil
}

type schemathesisItem struct {
	Check    string `json:"check"`
	Status   string `json:"status"`
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
	Response struct {
		StatusCode int    `json:"status_code"`
		Body       string `json:"body"`
	} `json:"response"`
	Message string `json:"message,omitempty"`
}

func parseSchemathesisJSON(data []byte, target string) []Finding {
	var items []schemathesisItem
	if err := json.Unmarshal(data, &items); err != nil {
		lines := strings.Split(string(data), "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" || !strings.HasPrefix(l, "{") {
				continue
			}
			var single schemathesisItem
			if err := json.Unmarshal([]byte(l), &single); err == nil && single.Check != "" {
				items = append(items, single)
			}
		}
	}
	var fs []Finding
	for _, it := range items {
		if strings.ToLower(it.Status) != "failure" && strings.ToLower(it.Status) != "error" {
			continue
		}
		check := strings.ToLower(it.Check)
		sev := SeverityMedium
		tags := []string{}
		if strings.Contains(check, "auth") || strings.Contains(check, "bola") || strings.Contains(check, "bfla") || strings.Contains(check, "idor") {
			sev = SeverityHigh
			tags = []string{"auth", "broken-access-control", "idor"}
		}
		title := fmt.Sprintf("API Violation (%s): %s %s", it.Check, it.Method, it.Endpoint)
		evidence := map[string]any{
			"check":       it.Check,
			"method":      it.Method,
			"endpoint":    it.Endpoint,
			"status_code": it.Response.StatusCode,
		}
		if it.Response.Body != "" {
			evidence["body"] = truncateStr(it.Response.Body, 2000)
			if leaksErrorDetails(it.Response.Body) {
				tags = append(tags, "information-disclosure")
			}
		}
		if it.Message != "" {
			evidence["message"] = it.Message
		}
		fs = append(fs, Finding{
			Source:     "web.api",
			SourceTool: "web.api",
			RuleID:     "schemathesis:" + it.Check,
			Title:      title,
			Severity:   sev,
			Confidence: ConfidenceConfirmed,
			Target:     target + it.Endpoint,
			Vector:     it.Method + " " + it.Endpoint,
			Evidence:   evidence,
			Tags:       dedupeTags(tags),
		})
	}
	return fs
}

// leaksErrorDetails reports whether a captured error body carries stack trace
// or database markers — the deterministic signal of an information disclosure.
func leaksErrorDetails(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{
		"traceback (most recent call last)",
		"stack trace",
		"exception",
		"sqlstate",
		"ora-",
		"panic:",
		"fatal error",
		"at com.",
		"org.springframework",
		"microsoft .net framework",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
