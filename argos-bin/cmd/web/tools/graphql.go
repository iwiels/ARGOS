package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// RegisterGraphQL registers the GraphQL auditing tool.
func RegisterGraphQL(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.graphql",
			Description: "GraphQL auditing: introspection, enumeration of queries and mutations, sensitive fields, " +
				"missing depth limit, batching abuse and the authorization of the mutations. The mutations are never " +
				"executed: the tool only reads the schema and probes the reads.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":     {Type: "string", Description: "GraphQL endpoint, e.g. https://example.com/graphql"},
					"method":     {Type: "string", Description: "HTTP method of the GraphQL request (default POST)"},
					"headers":    {Type: "object", Description: "Extra request headers, as a name to value map (authorization, apikey, ...)"},
					"depth":      {Type: "integer", Description: "Depth of the nested query used to test the depth limit (default 20, max 50)"},
					"batch_size": {Type: "integer", Description: "Number of operations sent in the batching probe (default 10, max 50)"},
					"timeout":    {Type: "integer", Description: "Per-request timeout in seconds (default 15, max 60)"},
				},
				Required: []string{"target"},
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
				Target    string            `json:"target"`
				Method    string            `json:"method"`
				Headers   map[string]string `json:"headers"`
				Depth     int               `json:"depth"`
				BatchSize int               `json:"batch_size"`
				Timeout   int               `json:"timeout"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			target, e := validateWebTargetWithToolContext(env, ctx, input.Target)
			if e != nil {
				return nil, e
			}
			started := time.Now()
			callCtx := toolContext(ctx)

			headers := map[string]string{}
			for name, value := range input.Headers {
				headers[name] = value
			}
			if _, ok := headers["Content-Type"]; !ok {
				headers["Content-Type"] = "application/json"
			}
			method := strings.ToUpper(strings.TrimSpace(input.Method))
			if method == "" {
				method = "POST"
			}
			depth := input.Depth
			if depth <= 0 {
				depth = 20
			}
			if depth > 50 {
				depth = 50
			}
			batchSize := input.BatchSize
			if batchSize <= 0 {
				batchSize = 10
			}
			if batchSize > 50 {
				batchSize = 50
			}

			report := auditGraphQL(callCtx, env, target, method, headers, depth, batchSize, vectorTimeout(input.Timeout))
			fs, truncated := capFindings(report.findings)
			res := vectorResult("web.graphql", target, started)
			res["introspection"] = report.introspection
			res["queries"] = report.queries
			res["mutations"] = report.mutations
			res["sensitive_fields"] = report.sensitiveFields
			res["depth_limit"] = report.depthLimit
			res["batching"] = report.batching
			env.publishFindings(res, fs)
			res["truncated"] = truncated
			res["summary"] = fmt.Sprintf("%d GraphQL issues detected", len(fs))
			return res, nil
		},
	)
}

// graphqlIntrospectionQuery is the introspection that lists the operations
// and the types of the schema.
const graphqlIntrospectionQuery = `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } } } } }"}`

// graphqlReport is the outcome of the audit of one endpoint.
type graphqlReport struct {
	findings        []Finding
	introspection   map[string]any
	queries         []string
	mutations       []string
	sensitiveFields []string
	depthLimit      map[string]any
	batching        map[string]any
}

// graphqlSensitivePatterns are the field names that usually expose data the
// client should not read directly.
var graphqlSensitivePatterns = []string{
	"password", "passwd", "secret", "token", "apikey", "api_key", "privatekey",
	"private_key", "creditcard", "credit_card", "cardnumber", "ssn", "socialsecurity",
	"balance", "salary", "iban", "credential", "sessionid", "session_id",
}

// graphqlDestructivePatterns are the mutations that change the state of the
// application.
var graphqlDestructivePatterns = []string{
	"delete", "remove", "destroy", "drop", "purge", "erase",
	"update", "create", "insert", "add", "set", "modify", "edit", "change",
	"reset", "grant", "revoke", "enable", "disable", "publish", "invite",
	"admin", "register", "signup", "payment", "charge", "refund", "transfer",
	"send", "execute", "run", "deploy", "install", "rotate",
}

// auditGraphQL inspects a GraphQL endpoint without ever executing a mutation.
func auditGraphQL(ctx context.Context, env *Env, target, method string, headers map[string]string, depth, batchSize int, timeout time.Duration) *graphqlReport {
	report := &graphqlReport{}
	client := env.Client()

	introspection := graphqlRequest(ctx, client, target, method, headers, graphqlIntrospectionQuery, timeout)
	report.introspection = map[string]any{"enabled": false}
	if introspection != nil {
		report.introspection["status"] = introspection.Status
		report.introspection["response_excerpt"] = vectorTruncate(introspection.Body, 1200)
	}

	schema := graphqlParseSchema(introspection)
	if schema != nil {
		report.introspection["enabled"] = true
		report.queries = schema.queries
		report.mutations = schema.mutations
		report.sensitiveFields = schema.sensitiveFields
		report.findings = append(report.findings, graphqlIntrospectionFinding(target, schema, introspection))
		if f, ok := graphqlSensitiveFieldFinding(target, schema); ok {
			report.findings = append(report.findings, f)
		}
		if f, ok := graphqlMutationSurfaceFinding(target, schema); ok {
			report.findings = append(report.findings, f)
		}
		report.depthLimit = graphqlDepthProbe(ctx, client, target, method, headers, schema, depth, timeout)
		if f, ok := graphqlDepthFinding(target, report.depthLimit); ok {
			report.findings = append(report.findings, f)
		}
		report.batching = graphqlBatchProbe(ctx, client, target, method, headers, batchSize, timeout)
		if f, ok := graphqlBatchFinding(target, report.batching); ok {
			report.findings = append(report.findings, f)
		}
		return report
	}

	// Introspection is closed: the schema cannot be read, so the field
	// enumeration is the only signal left.
	if f, ok := graphqlFieldEnumerationFinding(target, introspection); ok {
		report.findings = append(report.findings, f)
	}
	report.batching = map[string]any{"skipped": "the introspection is closed: the batching probe needs a readable schema"}
	return report
}

// graphqlRequest performs one GraphQL request with the scope-bound client.
func graphqlRequest(ctx context.Context, client *http.Client, target, method string, headers map[string]string, query string, timeout time.Duration) *vectorResponse {
	resp, err := vectorFetch(ctx, client, method, target, vectorHeader(headers), query, timeout)
	if err != nil {
		return nil
	}
	return resp
}

// graphqlField is one field of the schema.
type graphqlField struct {
	Name string
	Type string
	Kind string
}

// graphqlSchema is the part of the introspection the tool uses.
type graphqlSchema struct {
	queries         []string
	queryFields     []graphqlField
	mutations       []string
	sensitiveFields []string
	types           map[string][]graphqlField
}

// graphqlParseSchema reads the introspection response.
//
// It returns nil when the endpoint did not answer with a schema: a closed
// introspection is not a finding by itself.
func graphqlParseSchema(resp *vectorResponse) *graphqlSchema {
	if resp == nil {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(resp.Body), &doc); err != nil {
		return nil
	}
	data, ok := doc["data"].(map[string]any)
	if !ok {
		return nil
	}
	root, ok := data["__schema"].(map[string]any)
	if !ok {
		return nil
	}
	schema := &graphqlSchema{types: map[string][]graphqlField{}}

	types, _ := root["types"].([]any)
	for _, item := range types {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		typeName, _ := entry["name"].(string)
		if typeName == "" {
			continue
		}
		fields, _ := entry["fields"].([]any)
		var parsed []graphqlField
		for _, field := range fields {
			fieldEntry, ok := field.(map[string]any)
			if !ok {
				continue
			}
			fieldName, _ := fieldEntry["name"].(string)
			if fieldName == "" {
				continue
			}
			typeName, kind := graphqlFieldType(fieldEntry)
			parsed = append(parsed, graphqlField{Name: fieldName, Type: typeName, Kind: kind})
			if graphqlSensitiveField(fieldName) {
				schema.sensitiveFields = append(schema.sensitiveFields, typeName+"."+fieldName)
			}
		}
		schema.types[typeName] = parsed
	}

	if queryType, ok := root["queryType"].(map[string]any); ok {
		name, _ := queryType["name"].(string)
		schema.queryFields = schema.types[name]
		schema.queries = graphqlFieldNames(schema.queryFields)
	}
	if mutationType, ok := root["mutationType"].(map[string]any); ok {
		name, _ := mutationType["name"].(string)
		schema.mutations = graphqlFieldNames(schema.types[name])
	}

	sort.Strings(schema.queries)
	sort.Strings(schema.mutations)
	sort.Strings(schema.sensitiveFields)
	return schema
}

// graphqlFieldType resolves the type name and the kind of a field.
func graphqlFieldType(entry map[string]any) (string, string) {
	raw, ok := entry["type"].(map[string]any)
	if !ok {
		return "", ""
	}
	name, _ := raw["name"].(string)
	kind, _ := raw["kind"].(string)
	if name != "" {
		return name, kind
	}
	if ofType, ok := raw["ofType"].(map[string]any); ok {
		name, _ = ofType["name"].(string)
		if kind == "" {
			kind, _ = ofType["kind"].(string)
		}
		return name, kind
	}
	return "", kind
}

// graphqlFieldNames lists the names of the fields of a type.
func graphqlFieldNames(fields []graphqlField) []string {
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		out = append(out, field.Name)
	}
	return out
}

// graphqlSensitiveField reports whether the field name looks sensitive.
func graphqlSensitiveField(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range graphqlSensitivePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// graphqlIntrospectionFinding reports an open introspection.
func graphqlIntrospectionFinding(target string, schema *graphqlSchema, resp *vectorResponse) Finding {
	evidence := map[string]any{
		"queries":   schema.queries,
		"mutations": schema.mutations,
		"types":     len(schema.types),
		"url":       target,
	}
	if resp != nil {
		evidence["status"] = resp.Status
		evidence["response_excerpt"] = vectorTruncate(resp.Body, 800)
	}
	return Finding{
		Source: "web.graphql", SourceTool: "web.graphql", RuleID: "graphql:introspection-enabled",
		Title:      "GraphQL introspection is enabled: the whole schema is readable by any client",
		Severity:   SeverityMedium,
		Confidence: ConfidenceConfirmed,
		CWE:        "CWE-200",
		OWASP:      []string{"A05:2021"},
		Target:     target,
		Vector:     "graphql:introspection",
		Evidence:   evidence,
		Remediation: "Disable the introspection in production (or gate it behind an allow-list of the clients that need it) " +
			"and expose the schema through a curated endpoint instead.",
		Tags: []string{"graphql-introspection", "schema-disclosure"},
	}
}

// graphqlSensitiveFieldFinding reports the fields that expose sensitive data.
func graphqlSensitiveFieldFinding(target string, schema *graphqlSchema) (Finding, bool) {
	if len(schema.sensitiveFields) == 0 {
		return Finding{}, false
	}
	return Finding{
		Source: "web.graphql", SourceTool: "web.graphql", RuleID: "graphql:sensitive-fields",
		Title:      "GraphQL schema exposes sensitive fields: " + strings.Join(schema.sensitiveFields, ", "),
		Severity:   SeverityMedium,
		Confidence: ConfidenceProbable,
		CWE:        "CWE-200",
		OWASP:      []string{"A01:2021"},
		Target:     target,
		Vector:     "graphql:schema",
		Evidence: map[string]any{
			"sensitive_fields": schema.sensitiveFields,
			"url":              target,
		},
		Remediation: "Remove the sensitive fields from the GraphQL schema or protect them with an authorization rule that " +
			"is evaluated per field and per operation.",
		Tags: []string{"information-disclosure", "graphql-introspection"},
	}, true
}

// graphqlMutationSurfaceFinding reports the mutations the schema exposes.
//
// The tool never executes them: a mutation can change the state of the
// application, so it is only reported.
func graphqlMutationSurfaceFinding(target string, schema *graphqlSchema) (Finding, bool) {
	if len(schema.mutations) == 0 {
		return Finding{}, false
	}
	var destructive []string
	for _, mutation := range schema.mutations {
		lower := strings.ToLower(mutation)
		for _, pattern := range graphqlDestructivePatterns {
			if strings.Contains(lower, pattern) {
				destructive = append(destructive, mutation)
				break
			}
		}
	}
	severity := SeverityLow
	confidence := ConfidencePossible
	if len(destructive) > 0 {
		severity = SeverityMedium
		confidence = ConfidenceProbable
	}
	return Finding{
		Source: "web.graphql", SourceTool: "web.graphql", RuleID: "graphql:mutation-surface",
		Title:      fmt.Sprintf("GraphQL exposes %d mutations (%d state changing): the authorization of each one has to be verified", len(schema.mutations), len(destructive)),
		Severity:   severity,
		Confidence: confidence,
		CWE:        "CWE-862",
		OWASP:      []string{"A01:2021"},
		Target:     target,
		Vector:     "graphql:mutation",
		Evidence: map[string]any{
			"mutations":   schema.mutations,
			"destructive": destructive,
			"url":         target,
			"note":        "the mutations were not executed: the tool only reads the schema",
		},
		Remediation: "Apply an authorization rule to every mutation, deny the operations that the caller is not allowed to " +
			"perform and remove the ones that no client uses.",
		Tags: []string{"broken-access-control", "graphql-introspection"},
	}, true
}

// graphqlFieldEnumerationFinding reports the field names the endpoint leaks
// through its validation errors when the introspection is closed.
func graphqlFieldEnumerationFinding(target string, resp *vectorResponse) (Finding, bool) {
	if resp == nil {
		return Finding{}, false
	}
	suggestions := graphqlSuggestedFields(resp.Body)
	if len(suggestions) == 0 {
		return Finding{}, false
	}
	return Finding{
		Source: "web.graphql", SourceTool: "web.graphql", RuleID: "graphql:field-enumeration",
		Title:      "GraphQL leaks field names through the validation errors even with the introspection closed",
		Severity:   SeverityLow,
		Confidence: ConfidenceProbable,
		CWE:        "CWE-200",
		OWASP:      []string{"A05:2021"},
		Target:     target,
		Vector:     "graphql:introspection",
		Evidence: map[string]any{
			"suggested_fields": suggestions,
			"status":           resp.Status,
			"url":              target,
		},
		Remediation: "Disable the field suggestions of the validation errors in production.",
		Tags:        []string{"api-enumeration", "schema-disclosure"},
	}, true
}

// graphqlSuggestedFields extracts the field names the server suggests when it
// rejects an unknown field.
//
// GraphQL servers answer "Did you mean 'users'?" when the introspection is
// closed: the suggestion is a piece of the schema the client was not supposed
// to read.
func graphqlSuggestedFields(body string) []string {
	seen := map[string]bool{}
	var out []string
	rest := body
	for {
		index := strings.Index(rest, "Did you mean")
		if index < 0 {
			break
		}
		rest = rest[index+len("Did you mean"):]
		open := strings.Index(rest, "'")
		if open < 0 {
			break
		}
		rest = rest[open+1:]
		end := strings.Index(rest, "'")
		if end < 0 {
			break
		}
		name := rest[:end]
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
		rest = rest[end+1:]
	}
	sort.Strings(out)
	return out
}

// graphqlDepthProbe sends a deeply nested read and reports what the server
// answered.
func graphqlDepthProbe(ctx context.Context, client *http.Client, target, method string, headers map[string]string, schema *graphqlSchema, depth int, timeout time.Duration) map[string]any {
	result := map[string]any{"depth": depth}
	nested := graphqlNestedQuery(schema, depth)
	if nested == "" {
		result["skipped"] = "the schema does not expose a field that can be nested"
		return result
	}
	resp := graphqlRequest(ctx, client, target, method, headers, nested, timeout)
	if resp == nil {
		result["error"] = "the nested query did not get an answer"
		return result
	}
	result["status"] = resp.Status
	result["query"] = nested
	result["response_excerpt"] = vectorTruncate(resp.Body, 400)
	result["rejected"] = graphqlDepthRejected(resp.Body)
	return result
}

// graphqlNestedQuery builds a nested read out of the schema.
//
// The query has to be valid: a validation error says nothing about the depth
// limit, so the nesting follows the real types of the schema.
func graphqlNestedQuery(schema *graphqlSchema, depth int) string {
	chain := graphqlNestedChain(schema, depth)
	if len(chain) < 2 {
		return ""
	}
	selection := ""
	for i := len(chain) - 1; i >= 0; i-- {
		if i == len(chain)-1 {
			selection = chain[i].Name + " { __typename }"
			continue
		}
		selection = chain[i].Name + " { " + selection + " }"
	}
	return "{\"query\":\"{ " + selection + " }\"}"
}

// graphqlNestedChain returns the chain of fields that can be nested.
//
// The chain stops when the schema has no deeper object to descend into.
func graphqlNestedChain(schema *graphqlSchema, depth int) []graphqlField {
	var chain []graphqlField
	for _, root := range schema.queryFields {
		if !graphqlObjectKind(root.Kind) {
			continue
		}
		chain = []graphqlField{root}
		for len(chain) < depth {
			next, ok := graphqlObjectChild(schema, chain[len(chain)-1])
			if !ok {
				break
			}
			chain = append(chain, next)
		}
		if len(chain) >= 2 {
			return chain
		}
	}
	return nil
}

// graphqlObjectKind reports whether the kind of a field is a composite one.
func graphqlObjectKind(kind string) bool {
	switch strings.ToUpper(kind) {
	case "OBJECT", "INTERFACE", "UNION", "LIST":
		return true
	}
	return false
}

// graphqlObjectChild returns the first field of the type of the field that
// can be nested again.
func graphqlObjectChild(schema *graphqlSchema, field graphqlField) (graphqlField, bool) {
	for _, child := range schema.types[field.Type] {
		if graphqlObjectKind(child.Kind) {
			return child, true
		}
	}
	return graphqlField{}, false
}

// graphqlDepthRejected reports whether the answer is a depth limit refusal.
func graphqlDepthRejected(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{"depth", "too complex", "too deep", "max depth", "query complexity", "exceeds the maximum"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// graphqlDepthFinding reports a missing depth limit.
func graphqlDepthFinding(target string, depth map[string]any) (Finding, bool) {
	if depth == nil {
		return Finding{}, false
	}
	if rejected, _ := depth["rejected"].(bool); rejected {
		return Finding{}, false
	}
	if _, skipped := depth["skipped"]; skipped {
		return Finding{}, false
	}
	if _, failed := depth["error"]; failed {
		return Finding{}, false
	}
	return Finding{
		Source: "web.graphql", SourceTool: "web.graphql", RuleID: "graphql:no-depth-limit",
		Title:       "GraphQL accepts a deeply nested query: the endpoint has no depth limit",
		Severity:    SeverityMedium,
		Confidence:  ConfidencePossible,
		CWE:         "CWE-770",
		OWASP:       []string{"A05:2021"},
		Target:      target,
		Vector:      "graphql:depth",
		Evidence:    depth,
		Remediation: "Apply a maximum depth (and a maximum cost) to every GraphQL query and reject the ones that exceed it.",
		Tags:        []string{"dos", "resource-exhaustion"},
	}, true
}

// graphqlBatchProbe sends a batch of operations in one request.
func graphqlBatchProbe(ctx context.Context, client *http.Client, target, method string, headers map[string]string, batchSize int, timeout time.Duration) map[string]any {
	result := map[string]any{"batch_size": batchSize}
	operations := make([]string, 0, batchSize)
	for i := 0; i < batchSize; i++ {
		operations = append(operations, graphqlIntrospectionQuery)
	}
	payload := "[" + strings.Join(operations, ",") + "]"
	resp, err := vectorFetch(ctx, client, method, target, vectorHeader(headers), payload, timeout)
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	result["status"] = resp.Status
	processed := graphqlProcessedOperations(resp.Body)
	result["processed"] = processed
	result["response_excerpt"] = vectorTruncate(resp.Body, 400)
	return result
}

// graphqlProcessedOperations counts the operations the server answered.
func graphqlProcessedOperations(body string) int {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return 0
	}
	if strings.HasPrefix(trimmed, "[") {
		var items []any
		if err := json.Unmarshal([]byte(trimmed), &items); err == nil {
			return len(items)
		}
		return 0
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(trimmed), &doc); err == nil {
		if errs, ok := doc["errors"].([]any); ok && len(errs) > 0 {
			return 0
		}
		if _, ok := doc["data"]; ok {
			return 1
		}
	}
	return 0
}

// graphqlBatchFinding reports that the endpoint processes batched operations.
func graphqlBatchFinding(target string, batching map[string]any) (Finding, bool) {
	if batching == nil {
		return Finding{}, false
	}
	processed, _ := batching["processed"].(int)
	size, _ := batching["batch_size"].(int)
	if processed < 2 || size < 2 || processed < size {
		return Finding{}, false
	}
	return Finding{
		Source: "web.graphql", SourceTool: "web.graphql", RuleID: "graphql:batching-allowed",
		Title:      "GraphQL processes batched operations: the endpoint amplifies a single request",
		Severity:   SeverityMedium,
		Confidence: ConfidenceProbable,
		CWE:        "CWE-770",
		OWASP:      []string{"A05:2021"},
		Target:     target,
		Vector:     "graphql:batching",
		Evidence:   batching,
		Remediation: "Limit the number of operations per request and the total cost of the batch, and apply the rate limit " +
			"to the batched operations instead of to the request.",
		Tags: []string{"dos", "resource-exhaustion"},
	}, true
}
