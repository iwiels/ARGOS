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

// RegisterWordlists registers the wordlist catalogue tool.
//
// It is called from RegisterAll (tools.go), which wires it in.
func RegisterWordlists(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.wordlists",
			Description: "Lists the wordlists available for fuzzing (SecLists, fetched on demand and verified by checksum) " +
				"with their entry count, size and cache state. Use it to pick the wordlist of a web.fuzz or web.params run.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"kind": {Type: "string", Description: "Filter by profile: dirs, params, api, dns, hosts, bypass"},
				},
			},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Kind string `json:"kind"`
			}
			if len(params) > 0 {
				if err := json.Unmarshal(params, &input); err != nil {
					return nil, invalidParams(err)
				}
			}
			kind := strings.ToLower(strings.TrimSpace(input.Kind))
			dir := wordlistToolsDir(env)
			items := make([]map[string]interface{}, 0, len(wordlistRegistry))
			for _, spec := range wordlistRegistry {
				if kind != "" && !strings.EqualFold(spec.Kind, kind) {
					continue
				}
				items = append(items, wordlistEntry(spec, dir))
			}
			res := map[string]interface{}{
				"tool":      "web.wordlists",
				"status":    "completed",
				"wordlists": items,
				"profiles":  WordlistProfiles(),
				"summary":   fmt.Sprintf("%d wordlists", len(items)),
			}
			if dir != "" {
				res["cache_dir"] = filepath.Join(dir, wordlistCacheDir)
			}
			return res, nil
		},
	)
}

// wordlistEntry describes one registry wordlist and whether it is already
// cached on disk.
func wordlistEntry(spec WordlistSpec, toolsDir string) map[string]interface{} {
	entry := map[string]interface{}{
		"name":    spec.Name,
		"kind":    spec.Kind,
		"repo":    spec.Repo,
		"path":    spec.Path,
		"version": spec.Version,
		"lines":   spec.Lines,
		"sha256":  spec.SHA256,
		"pinned":  spec.SHA256 != "",
		"cached":  false,
	}
	if toolsDir == "" {
		return entry
	}
	path := wordlistCachePath(toolsDir, spec)
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		return entry
	}
	entry["cached"] = true
	entry["cache_path"] = path
	entry["cache_bytes"] = fi.Size()
	entry["cache_age_days"] = int(time.Since(fi.ModTime()).Hours() / 24)
	return entry
}
