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

var fallbackWordlist = []string{
	".env", ".git/config", "wp-config.php.bak", "backup.zip", "api/v1/users",
	"swagger.json", "swagger-ui.html", "graphql", "admin/", "server-status",
	".htaccess", "robots.txt", "sitemap.xml", "phpinfo.php", "config.json",
	"db.sql", "dump.sql", "debug", "health", "actuator", ".well-known/security.txt",
}

// wordlistPath resolves the bundled common.txt when OPENCODE_CONFIG_DIR is set.
func wordlistPath() string {
	if dir := os.Getenv("OPENCODE_CONFIG_DIR"); dir != "" {
		p := filepath.Join(dir, "skills", "auditoria-web", "scripts", "wordlists", "common.txt")
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			return p
		}
	}
	return ""
}

func ensureWordlistFile() (string, func(), error) {
	if p := wordlistPath(); p != "" {
		return p, func() {}, nil
	}
	tmp, err := os.CreateTemp("", "argos-ffuf-wordlist-*")
	if err != nil {
		return "", func() {}, err
	}
	if _, err := tmp.WriteString(strings.Join(fallbackWordlist, "\n") + "\n"); err != nil {
		tmp.Close()
		return "", func() {}, err
	}
	name := tmp.Name()
	tmp.Close()
	return name, func() { os.Remove(name) }, nil
}

// fuzzArgs builds the ffuf command line for a fuzzing run. The wordlist
// path is resolved by the caller, so the arguments always point at the
// list the result declares.
func fuzzArgs(target, mode, wordlistPath string, rate int, filterStatus []int) []string {
	args := []string{"-w", wordlistPath + ":FUZZ", "-json", "-t", "20", "-rate", fmt.Sprintf("%d", rate), "-timeout", "10", "-mc", "all"}
	if len(filterStatus) > 0 {
		fc := make([]string, 0, len(filterStatus))
		for _, s := range filterStatus {
			fc = append(fc, fmt.Sprintf("%d", s))
		}
		args = append(args, "-fc", strings.Join(fc, ","))
	} else {
		args = append(args, "-fc", "404")
	}
	switch mode {
	case "vhost":
		args = append(args, "-H", "Host: FUZZ."+hostOf(target))
		args = append(args, "-u", target)
	default: // dir
		args = append(args, "-u", strings.TrimRight(target, "/")+"/FUZZ")
	}
	return args
}

func RegisterFuzz(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.fuzz",
			Description: "Fast directory / vhost / parameter fuzzing with ffuf. The wordlist is fetched on demand from SecLists " +
				"(wordlist: dirs, api, dns, big, small or an explicit name) and falls back to the bundled common.txt when offline.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":        {Type: "string", Description: "Base target URL, e.g. https://example.com"},
					"mode":          {Type: "string", Description: "fuzz mode: dir (default), vhost, param"},
					"rate":          {Type: "integer", Description: "Requests per second (default 50)"},
					"filter_status": {Type: "array", Items: &mcp.Items{Type: "integer"}, Description: "Status codes to filter out (default 404)"},
					"timeout":       {Type: "integer", Description: "Fuzz timeout in seconds (default 120, max 300)"},
					"wordlist": {Type: "string", Description: "Wordlist profile: dirs (default for dir mode), hosts, params, api, dns, big, small, " +
						"or an explicit wordlist name. See web.wordlists for the catalogue."},
				},
				Required: []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Target       string `json:"target"`
				Mode         string `json:"mode"`
				Rate         int    `json:"rate"`
				FilterStatus []int  `json:"filter_status"`
				Timeout      int    `json:"timeout"`
				Wordlist     string `json:"wordlist"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			mode := input.Mode
			if mode == "" {
				mode = "dir"
			}
			rate := input.Rate
			if rate <= 0 {
				rate = 50
			}
			timeout := clampTimeout(input.Timeout, 120)

			bin, installed, e := env.Binary(toolContext(ctx), "ffuf")
			if e != nil {
				return nil, e
			}
			profile := strings.TrimSpace(input.Wordlist)
			if profile == "" {
				profile = defaultWordlistProfile(mode)
			}
			if _, ok := ResolveWordlist(profile); !ok {
				return nil, invalidParams(fmt.Errorf("unknown wordlist %q: available %s", profile, strings.Join(WordlistNames(), ", ")))
			}
			wl, wlSpec, err := EnsureWordlistIn(toolContext(ctx), wordlistToolsDir(env), profile)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "cannot prepare wordlist: " + err.Error()}
			}
			entries, _ := countWordlistEntries(wl)

			args := fuzzArgs(target, mode, wl, rate, input.FilterStatus)

			r := run(toolContext(ctx), bin, runOptions{Args: args, Timeout: time.Duration(timeout) * time.Second})
			hits := parseFfuf(r.Output)
			hitsTruncated := false
			if len(hits) > 300 {
				hits = hits[:300]
				hitsTruncated = true
			}

			fs := findingsFromFuzz(hits, target)
			fs, truncated := capFindings(fs)
			res := baseResult("web.fuzz", target, r)
			res["mode"] = mode
			res["wordlist"] = wlSpec.Name
			res["wordlist_profile"] = profile
			res["wordlist_source"] = wlSpec.Source
			res["wordlist_entries"] = entries
			res["hits"] = hits
			res["findings"] = findingsToMaps(fs)
			res["truncated"] = truncated || hitsTruncated
			res["summary"] = fmt.Sprintf("%d rutas encontradas; el fuzzing no confirma vulnerabilidades", len(hits))
			debugToolOutput(res, r)
			if installed {
				res["installed"] = "ffuf " + env.Spec("ffuf").Version
			}
			return res, nil
		},
	)
}

func hostOf(target string) string {
	t := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	return strings.Split(t, "/")[0]
}

func findingsFromFuzz(_ []ffufResult, _ string) []Finding {
	return nil
}
