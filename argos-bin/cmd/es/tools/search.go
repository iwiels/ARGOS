package tools

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// sortParam converts "field:desc" / "field" into an Elasticsearch sort clause.
func sortParam(spec string) interface{} {
	parts := strings.SplitN(spec, ":", 2)
	field := strings.TrimSpace(parts[0])
	order := "asc"
	if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[1]), "desc") {
		order = "desc"
	}
	return []interface{}{map[string]interface{}{field: order}}
}

// containsScriptClause walks a decoded query DSL body looking for any "script"
// key at any depth (query.script, script_fields, sort[].script, aggs...script,
// etc). Scripting is disabled for this tool: an agent-supplied Painless script
// would run server-side with whatever privileges the configured ES credential
// has, which is a much larger blast radius than a plain query DSL search.
func containsScriptClause(v interface{}) bool {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, child := range val {
			if k == "script" {
				return true
			}
			if containsScriptClause(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range val {
			if containsScriptClause(child) {
				return true
			}
		}
	}
	return false
}

// clampResultSize enforces the same size<=100 cap regardless of whether the
// caller set it via the dedicated "size" param or embedded it directly inside
// the query DSL JSON (which previously bypassed the cap entirely).
func clampResultSize(body map[string]interface{}) {
	raw, ok := body["size"]
	if !ok {
		return
	}
	n, valid := 0, false
	switch t := raw.(type) {
	case float64:
		n, valid = int(t), true
	case int:
		n, valid = t, true
	}
	if !valid || n < 0 {
		delete(body, "size")
		return
	}
	if n > 100 {
		n = 100
	}
	body["size"] = n
}

func RegisterSearch(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "es.search",
			Description: "Search an Elasticsearch index using query DSL. The query must be a JSON string, e.g. {\"query\":{\"bool\":{\"must\":[{\"match\":{\"message\":\"failed\"}}]}}}. Omitting the query returns a match_all (first hits).",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"index": {Type: "string", Description: "Index or index pattern to search, e.g. winlogbeat-*"},
					"query": {Type: "string", Description: "Query DSL body as a JSON string (optional, defaults to match_all)"},
					"size":  {Type: "string", Description: "Max hits to return (default 10, max 100)"},
					"sort":  {Type: "string", Description: "Optional sort, e.g. @timestamp:desc"},
				},
				Required: []string{"index"},
			},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true), IdempotentHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Index string `json:"index"`
				Query string `json:"query"`
				Size  string `json:"size"`
				Sort  string `json:"sort"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			if input.Index == "" {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "missing required param: index"}
			}
			if referencesSystemIndex(input.Index) {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "access to dot-prefixed system indices is not permitted through this tool"}
			}

			var body map[string]interface{}
			query := strings.TrimSpace(input.Query)
			if query == "" {
				body = map[string]interface{}{"query": map[string]interface{}{"match_all": map[string]interface{}{}}}
			} else {
				if err := json.Unmarshal([]byte(query), &body); err != nil {
					return nil, &mcp.ErrorObj{Code: -32602, Message: fmt.Sprintf("invalid query DSL JSON: %v", err)}
				}
			}
			if containsScriptClause(body) {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "query DSL must not contain a 'script' clause: scripting is disabled for es.search"}
			}
			if input.Size != "" {
				if n, err := strconv.Atoi(input.Size); err == nil && n > 0 {
					body["size"] = n
				}
			}
			clampResultSize(body)
			if strings.TrimSpace(input.Sort) != "" {
				body["sort"] = sortParam(input.Sort)
			}

			if _, ok := body["timeout"]; !ok {
				body["timeout"] = "30s"
			}

			payload, err := json.Marshal(body)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: fmt.Sprintf("encode query: %v", err)}
			}
			path := "/" + url.PathEscape(input.Index) + "/_search"
			res, errObj := env.Client.Do(ctx.Ctx, "POST", path, payload)
			if errObj != nil {
				return nil, errObj
			}
			return res, nil
		},
	)
}

func RegisterGet(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "es.get",
			Description: "Fetch a single Elasticsearch document by id from an index.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"index": {Type: "string", Description: "Index containing the document"},
					"id":    {Type: "string", Description: "Document id"},
				},
				Required: []string{"index", "id"},
			},
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: mcp.BoolPtr(true), IdempotentHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Index string `json:"index"`
				ID    string `json:"id"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			if input.Index == "" || input.ID == "" {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "missing required params: index, id"}
			}
			if referencesSystemIndex(input.Index) {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "access to dot-prefixed system indices is not permitted through this tool"}
			}
			path := "/" + url.PathEscape(input.Index) + "/_doc/" + url.PathEscape(input.ID)
			res, errObj := env.Client.Do(ctx.Ctx, "GET", path, nil)
			if errObj != nil {
				return nil, errObj
			}
			return res, nil
		},
	)
}
