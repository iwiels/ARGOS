package tools

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

type ScoutInput struct {
	Target string `json:"target"`
}

type ScoutResult struct {
	Target   string          `json:"target"`
	Kind     string          `json:"kind"`
	Stack    []string        `json:"detected_stack,omitempty"`
	Method   string          `json:"recommended_methodology"`
	Indicators map[string]interface{} `json:"indicators,omitempty"`
}

func inferTargetKind(target string) (string, string, map[string]interface{}) {
	indicators := map[string]interface{}{}

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil {
			return "web", "General web application assessment", indicators
		}

		indicators["host"] = u.Hostname()
		indicators["scheme"] = u.Scheme

		if u.Port() != "" {
			indicators["port"] = u.Port()
		}

		ext := filepath.Ext(u.Path)
		if ext != "" {
			indicators["extension"] = ext
		}

		port := u.Port()
		switch port {
		case "443", "8443":
			return "web", "HTTPS web application assessment with TLS validation", indicators
		case "80", "8080":
			return "web", "HTTP web application assessment (note: unencrypted)", indicators
		case "9090", "3000", "5000":
			return "api", "API endpoint assessment with REST/GraphQL methodology", indicators
		case "22":
			return "host", "SSH service assessment — banner grab and auth enumeration", indicators
		case "21":
			return "host", "FTP service assessment — anonymous access and file enumeration", indicators
		case "3306":
			return "host", "MySQL database exposure assessment", indicators
		case "5432":
			return "host", "PostgreSQL database exposure assessment", indicators
		case "27017":
			return "host", "MongoDB exposure assessment", indicators
		case "6379":
			return "host", "Redis exposure assessment", indicators
		case "9200":
			return "api", "Elasticsearch API assessment", indicators
		}

		if strings.Contains(target, "api") || strings.Contains(target, "graphql") || strings.Contains(target, "rest") {
			return "api", "API endpoint assessment with REST/GraphQL methodology", indicators
		}

		if ext == ".php" || ext == ".asp" || ext == ".aspx" || ext == ".jsp" {
			return "web", "Legacy web application assessment (server-side scripting)", indicators
		}

		return "web", "General web application assessment", indicators
	}

	if strings.HasPrefix(target, "git@") || strings.HasPrefix(target, "https://github.com") || strings.HasPrefix(target, "https://gitlab") {
		return "repo", "Repository security assessment — secret scanning and dependency review", indicators
	}

	if strings.Contains(target, ":") && !strings.HasPrefix(target, "/") {
		return "host", "Host service assessment — port scanning and service enumeration", indicators
	}

	return "host", "General host assessment — file system and process enumeration", indicators
}

func RegisterScout(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "audit.scout",
			// La descripción decía "detected technologies", pero inferTargetKind
			// sólo parsea la URL (esquema, host, puerto, extensión) sin tocar la
			// red. Prometer fingerprinting hacía que los agentes confiaran en una
			// salida que nunca lo incluye; el fingerprint real viene de web_tech /
			// web_probe.
			Description: "Classify a target URL or path by kind (web/api/host/repo) from its URL structure alone — no network request is made — and recommend an assessment methodology. For technology fingerprinting use web_tech / web_probe.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target": {
						Type:        "string",
						Description: "Target URL (e.g. https://example.com:8443/api) or directory path to analyze",
					},
				},
				Required: []string{"target"},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input ScoutInput
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid params: " + err.Error()}
			}

			kind, method, indicators := inferTargetKind(input.Target)

			result := ScoutResult{
				Target:     input.Target,
				Kind:       kind,
				Method:     method,
				Indicators: indicators,
			}

			if kind == "web" {
				result.Stack = detectWebStack(input.Target)
			} else if kind == "api" {
				result.Stack = detectAPIStack(input.Target)
			}

			return result, nil
		},
	)
}

func detectWebStack(target string) []string {
	var stack []string
	lower := strings.ToLower(target)

	if strings.Contains(lower, "wordpress") || strings.Contains(lower, "wp") || strings.Contains(lower, "wp-") {
		stack = append(stack, "WordPress")
	}
	if strings.Contains(lower, "laravel") || strings.Contains(lower, ".php") {
		stack = append(stack, "PHP")
	}
	if strings.Contains(lower, "django") || strings.Contains(lower, "python") {
		stack = append(stack, "Python/Django")
	}
	if strings.Contains(lower, "rails") || strings.Contains(lower, "ruby") || strings.Contains(lower, ".erb") {
		stack = append(stack, "Ruby on Rails")
	}
	if strings.Contains(lower, "node") || strings.Contains(lower, "express") || strings.Contains(lower, "next") {
		stack = append(stack, "Node.js/Express")
	}
	if strings.Contains(lower, "asp") || strings.Contains(lower, ".net") || strings.Contains(lower, "iis") {
		stack = append(stack, "ASP.NET/IIS")
	}
	if strings.Contains(lower, "java") || strings.Contains(lower, "spring") || strings.Contains(lower, "jsp") {
		stack = append(stack, "Java/Spring")
	}
	if strings.Contains(lower, "cms") || strings.Contains(lower, "drupal") || strings.Contains(lower, "joomla") {
		stack = append(stack, "CMS")
	}

	return stack
}

func detectAPIStack(target string) []string {
	var stack []string
	lower := strings.ToLower(target)

	if strings.Contains(lower, "graphql") {
		stack = append(stack, "GraphQL")
	}
	if strings.Contains(lower, "rest") || strings.Contains(lower, "api") {
		stack = append(stack, "RESTful")
	}
	if strings.Contains(lower, "grpc") || strings.Contains(lower, "proto") {
		stack = append(stack, "gRPC/Protobuf")
	}
	if strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger") {
		stack = append(stack, "OpenAPI/Swagger")
	}
	if strings.Contains(lower, "soap") || strings.Contains(lower, "xmlrpc") {
		stack = append(stack, "SOAP/XML-RPC")
	}
	if strings.Contains(lower, "elasticsearch") || strings.Contains(lower, "es:") {
		stack = append(stack, "Elasticsearch")
	}

	return stack
}

type DispatchInput struct {
	Target string `json:"target"`
}

type DispatchResult struct {
	Target      string   `json:"target"`
	TargetKind  string   `json:"target_kind"`
	Specialists []string `json:"recommended_specialists"`
	Reasoning   string   `json:"reasoning"`
}

var specialistMap = map[string][]string{
	"web": {
		"web-crawler",
		"xss-specialist",
		"sqli-specialist",
		"csrf-specialist",
		"headers-analyzer",
		"auth-tester",
		"session-analyzer",
	},
	"api": {
		"api-fuzzer",
		"graphql-inspector",
		"jwt-analyzer",
		"rate-limit-tester",
		"auth-tester",
		"cors-analyzer",
	},
	"host": {
		"port-scanner",
		"service-enumerator",
		"os-fingerprinter",
		"vuln-scanner",
		"credential-tester",
	},
	"repo": {
		"secret-scanner",
		"dependency-analyzer",
		"license-checker",
		"git-history-analyzer",
		"ci-pipeline-analyzer",
	},
}

func RegisterDispatch(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "audit.dispatch",
			Description: "Dispatch the appropriate security specialists to a target based on its kind (web, api, host, repo)",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target": {
						Type:        "string",
						Description: "Target URL or identifier to dispatch specialists to",
					},
				},
				Required: []string{"target"},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input DispatchInput
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid params: " + err.Error()}
			}

			kind, _, _ := inferTargetKind(input.Target)
			specialists := specialistMap[kind]
			if specialists == nil {
				specialists = []string{"general-vuln-scanner", "info-gatherer"}
			}

			result := DispatchResult{
				Target:      input.Target,
				TargetKind:  kind,
				Specialists: specialists,
				Reasoning:   fmt.Sprintf("Dispatched %d specialist(s) for %s-kind target", len(specialists), kind),
			}

			return result, nil
		},
	)
}
