package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
)

// graphqlHasRule reports whether the findings carry the rule.
func graphqlHasRule(findings []Finding, rule string) bool {
	for _, finding := range findings {
		if finding.RuleID == rule {
			return true
		}
	}
	return false
}

// graphqlOpenSchema is the introspection answer of an endpoint that leaves
// the schema open.
const graphqlOpenSchema = `{"data":{"__schema":{
  "queryType":{"name":"Query"},
  "mutationType":{"name":"Mutation"},
  "types":[
    {"name":"Query","kind":"OBJECT","fields":[
      {"name":"users","type":{"name":"User","kind":"OBJECT","ofType":null}},
      {"name":"user","type":{"name":"User","kind":"OBJECT","ofType":null}}
    ]},
    {"name":"Mutation","kind":"OBJECT","fields":[
      {"name":"deleteUser","type":{"name":"Boolean","kind":"SCALAR","ofType":null}}
    ]},
    {"name":"User","kind":"OBJECT","fields":[
      {"name":"id","type":{"name":"ID","kind":"SCALAR","ofType":null}},
      {"name":"email","type":{"name":"String","kind":"SCALAR","ofType":null}},
      {"name":"password","type":{"name":"String","kind":"SCALAR","ofType":null}}
    ]}
  ]}}}`

func TestGraphQLOpenIntrospectionIsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		query, _ := body["query"].(string)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(query, "__schema") {
			_, _ = w.Write([]byte(graphqlOpenSchema))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"users":[]}}`))
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-graphql-open",
		MaxRPS:       50,
	})

	report := auditGraphQL(context.Background(), env, srv.URL, "POST", map[string]string{"Content-Type": "application/json"}, 20, 5, 5*time.Second)
	if !graphqlHasRule(report.findings, "graphql:introspection-enabled") {
		t.Fatalf("expected the introspection finding, got %+v", report.findings)
	}
	if len(report.queries) == 0 {
		t.Error("the queries of the schema have to be reported")
	}
	for _, finding := range report.findings {
		if finding.RuleID == "graphql:introspection-enabled" {
			if finding.Confidence != ConfidenceConfirmed {
				t.Errorf("confidence = %q, want confirmed", finding.Confidence)
			}
			if finding.CWE != "CWE-200" {
				t.Errorf("cwe = %q, want CWE-200", finding.CWE)
			}
		}
	}
}

func TestGraphQLClosedIntrospectionProducesNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`))
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-graphql-closed",
		MaxRPS:       50,
	})

	report := auditGraphQL(context.Background(), env, srv.URL, "POST", map[string]string{"Content-Type": "application/json"}, 20, 5, 5*time.Second)
	if len(report.findings) != 0 {
		t.Fatalf("expected no findings for a closed introspection, got %d: %+v", len(report.findings), report.findings)
	}
}

func TestGraphQLMutationsAreNeverExecuted(t *testing.T) {
	executed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		query, _ := body["query"].(string)
		if strings.Contains(query, "deleteUser") {
			executed = true
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(query, "__schema") {
			_, _ = w.Write([]byte(graphqlOpenSchema))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"users":[]}}`))
	}))
	defer srv.Close()

	env := envWithScope(t, scope.ScopeConfig{
		AllowedCIDRs: []string{"127.0.0.0/8"},
		SessionID:    "tools-graphql-readonly",
		MaxRPS:       50,
	})

	auditGraphQL(context.Background(), env, srv.URL, "POST", map[string]string{"Content-Type": "application/json"}, 20, 5, 5*time.Second)
	if executed {
		t.Fatal("the tool must never execute a mutation")
	}
}
