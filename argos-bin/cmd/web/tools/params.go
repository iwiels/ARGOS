package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

var paramNames = []string{
	"id", "user", "user_id", "username", "email", "token", "key", "api_key",
	"file", "path", "url", "redirect", "next", "return", "callback", "host",
	"page", "view", "action", "cmd", "command", "query", "q", "search", "name",
	"dir", "download", "img", "image", "ref", "source", "dest", "password",
	"pass", "debug", "test", "admin", "role", "type", "format", "lang",
}

func RegisterParams(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.params",
			Description: "Hidden parameter discovery (ffuf). Fuzzes the parameter names of a wordlist (default: the SecLists parameter names) " +
				"and reports those that change the response (potential reflection/processing).",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":   {Type: "string", Description: "Target URL, e.g. https://example.com/search"},
					"method":   {Type: "string", Description: "GET (default) or POST"},
					"timeout":  {Type: "integer", Description: "Scan timeout in seconds (default 120, max 300)"},
					"wordlist": {Type: "string", Description: "Wordlist profile: params (default), small, common or an explicit wordlist name. See web.wordlists."},
				},
				Required: []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Target   string `json:"target"`
				Method   string `json:"method"`
				Timeout  int    `json:"timeout"`
				Wordlist string `json:"wordlist"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			method := strings.ToUpper(input.Method)
			if method == "" {
				method = "GET"
			}
			timeout := clampTimeout(input.Timeout, 120)

			bin, installed, e := env.Binary(toolContext(ctx), "ffuf")
			if e != nil {
				return nil, e
			}
			profile := strings.TrimSpace(input.Wordlist)
			if profile == "" {
				profile = "params"
			}
			if _, ok := ResolveWordlist(profile); !ok {
				return nil, invalidParams(fmt.Errorf("unknown wordlist %q: available %s", profile, strings.Join(WordlistNames(), ", ")))
			}
			wl, wlSpec, err := EnsureWordlistIn(toolContext(ctx), wordlistToolsDir(env), profile)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "cannot prepare param wordlist: " + err.Error()}
			}
			entries, _ := countWordlistEntries(wl)

			args := paramsArgs(target, method, wl)

			r := run(toolContext(ctx), bin, runOptions{Args: args, Timeout: time.Duration(timeout) * time.Second})
			hits := parseFfuf(r.Output)
			paramsFound := make([]map[string]interface{}, 0, len(hits))
			for _, h := range hits {
				paramsFound = append(paramsFound, map[string]interface{}{
					"param":  h.Input["FUZZ"],
					"status": h.Status,
					"length": h.Length,
					"url":    h.URL,
				})
			}

			res := baseResult("web.params", target, r)
			res["method"] = method
			res["wordlist"] = wlSpec.Name
			res["wordlist_profile"] = profile
			res["wordlist_source"] = wlSpec.Source
			res["wordlist_entries"] = entries
			res["params"] = paramsFound
			res["summary"] = fmt.Sprintf("%d parámetros candidatos", len(paramsFound))
			if installed {
				res["installed"] = "ffuf " + env.Spec("ffuf").Version
			}
			return res, nil
		},
	)
}

// paramsArgs builds the ffuf command line that probes a target with the
// parameter names of the resolved wordlist.
func paramsArgs(target, method, wordlistPath string) []string {
	args := []string{"-w", wordlistPath + ":FUZZ", "-json", "-t", "20", "-timeout", "10", "-mc", "all", "-fc", "404"}
	if method == "POST" {
		args = append(args, "-X", "POST", "-d", "FUZZ=argos-probe")
		args = append(args, "-u", target)
		return args
	}
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return append(args, "-u", target+sep+"FUZZ=argos-probe")
}
