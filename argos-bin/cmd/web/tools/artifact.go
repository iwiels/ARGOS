package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/iwiels/argos-auditor/argos-bin/internal/artifact"
	"github.com/iwiels/argos-auditor/argos-bin/internal/beautify"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

const maxArtifactDownloadSize = 10 << 20 // 10MB cap

func RegisterArtifact(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.artifact",
			Description: "Fetch, beautify (unminify HTML/JS/CSS/JSON), extract endpoints/secrets, and store web assets for security auditing.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":  {Type: "string", Description: "Target URL (e.g. https://example.com/assets/app.min.js) or local file path"},
					"content": {Type: "string", Description: "Raw content string to beautify and analyze directly without network request"},
					"type":    {Type: "string", Description: "Optional asset type: auto, js, html, css, json (default: auto)"},
				},
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
				Content string `json:"content"`
				Type    string `json:"type"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}

			target := strings.TrimSpace(input.Target)
			rawContent := input.Content

			if target == "" && rawContent == "" {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "either target URL/path or content must be provided"}
			}

			var host string
			// Fetch from URL if target is remote
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
				if env.Scope != nil && !env.Scope.RequiresWorkerProxy() {
					if _, err := env.Scope.ValidateTarget(ctx.Ctx, target); err != nil {
						return nil, &mcp.ErrorObj{Code: -32600, Message: fmt.Sprintf("target %q is out of authorized scope: %v", target, err)}
					}
				}

				u, _ := url.Parse(target)
				if u != nil {
					host = u.Hostname()
				}

				if rawContent == "" {
					fetched, err := fetchRemoteAsset(ctx.Ctx, env.Client(), target)
					if err != nil {
						return nil, &mcp.ErrorObj{Code: -32603, Message: fmt.Sprintf("failed to fetch asset: %v", err)}
					}
					rawContent = fetched
				}
			} else if target != "" && rawContent == "" {
				// Local file
				data, err := os.ReadFile(target)
				if err != nil {
					return nil, &mcp.ErrorObj{Code: -32603, Message: fmt.Sprintf("failed to read local file: %v", err)}
				}
				rawContent = string(data)
				host = "local"
			} else {
				host = "inline"
			}

			// Detect Language
			var lang beautify.Language
			switch strings.ToLower(input.Type) {
			case "js", "javascript":
				lang = beautify.LangJS
			case "html":
				lang = beautify.LangHTML
			case "css":
				lang = beautify.LangCSS
			case "json":
				lang = beautify.LangJSON
			default:
				lang = beautify.DetectLanguage(target, rawContent)
			}

			// Beautify
			formatted, err := beautify.Beautify(rawContent, lang)
			if err != nil {
				formatted = rawContent
			}

			// Extract intelligence
			intel := artifact.Extract(formatted, lang)

			// Store artifact
			store := artifact.NewStore(ctx.MemoryDir)
			id := artifact.GenerateArtifactID(target + rawContent[:min(len(rawContent), 100)])
			meta := &artifact.ArtifactMeta{
				ID:           id,
				Target:       target,
				Host:         host,
				Type:         string(lang),
				OriginalSize: len(rawContent),
				Endpoints:    intel.Endpoints,
				Secrets:      intel.Secrets,
				SourceMap:    intel.SourceMap,
			}

			if err := store.Save(meta, formatted); err != nil {
				ctx.Log("warning: failed to save artifact to store: %v", err)
			}

			// Preview (first 40 lines)
			lines := strings.Split(formatted, "\n")
			previewLines := lines[:min(len(lines), 40)]
			preview := strings.Join(previewLines, "\n")

			return map[string]interface{}{
				"status":          "completed",
				"artifact_id":     meta.ID,
				"target":          target,
				"type":            meta.Type,
				"original_size":   meta.OriginalSize,
				"beautified_size": meta.BeautifiedSize,
				"total_lines":     meta.TotalLines,
				"endpoints_count": len(meta.Endpoints),
				"endpoints":       meta.Endpoints,
				"secrets_count":   len(meta.Secrets),
				"secrets":         meta.Secrets,
				"sourcemap":       meta.SourceMap,
				"file_path":       meta.FilePath,
				"preview":         preview,
			}, nil
		},
	)

	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "web.artifact.read",
			Description: "Read paginated lines or search regex patterns within a beautified web artifact.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"artifact_id":   {Type: "string", Description: "Artifact ID (from web.artifact) or target URL/path"},
					"start_line":    {Type: "integer", Description: "Starting line number (1-indexed, default 1)"},
					"limit":         {Type: "integer", Description: "Number of lines to read (default 100, max 500)"},
					"pattern":       {Type: "string", Description: "Optional regex pattern to search for (returns matches with context)"},
					"context_lines": {Type: "integer", Description: "Number of context lines surrounding regex matches (default 2)"},
				},
				Required: []string{"artifact_id"},
			},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				ArtifactID   string `json:"artifact_id"`
				StartLine    int    `json:"start_line"`
				Limit        int    `json:"limit"`
				Pattern      string `json:"pattern"`
				ContextLines int    `json:"context_lines"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}

			if strings.TrimSpace(input.ArtifactID) == "" {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "artifact_id is required"}
			}

			store := artifact.NewStore(ctx.MemoryDir)

			if input.Pattern != "" {
				results, err := store.Search(input.ArtifactID, input.Pattern, input.ContextLines)
				if err != nil {
					return nil, &mcp.ErrorObj{Code: -32603, Message: err.Error()}
				}
				return map[string]interface{}{
					"status":        "completed",
					"artifact_id":   input.ArtifactID,
					"pattern":       input.Pattern,
					"matches_count": len(results),
					"matches":       results,
				}, nil
			}

			startLine := input.StartLine
			if startLine <= 0 {
				startLine = 1
			}
			limit := input.Limit
			if limit <= 0 {
				limit = 100
			}

			lines, hasMore, total, err := store.ReadLines(input.ArtifactID, startLine, limit)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: err.Error()}
			}

			endLine := startLine + len(lines) - 1
			if len(lines) == 0 {
				endLine = startLine
			}

			return map[string]interface{}{
				"status":          "completed",
				"artifact_id":     input.ArtifactID,
				"start_line":      startLine,
				"end_line":        endLine,
				"total_lines":     total,
				"lines_count":     len(lines),
				"has_more":        hasMore,
				"next_start_line": endLine + 1,
				"lines":           lines,
			}, nil
		},
	)
}

// fetchRemoteAsset downloads a remote asset through the scope-bound client.
//
// Invariante de seguridad: la descarga de un asset del target es tráfico de
// engagement — tiene que pasar por el IP-pinning, el rate limit y el audit
// log encadenado igual que el resto.
func fetchRemoteAsset(ctx context.Context, client *http.Client, target string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d %s", resp.StatusCode, resp.Status)
	}

	lr := io.LimitReader(resp.Body, maxArtifactDownloadSize)
	bodyBytes, err := io.ReadAll(lr)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}
