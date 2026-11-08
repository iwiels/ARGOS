package tools

import "testing"

func TestContainsScriptClause(t *testing.T) {
	cases := []struct {
		name string
		body map[string]interface{}
		want bool
	}{
		{"no script", map[string]interface{}{"query": map[string]interface{}{"match_all": map[string]interface{}{}}}, false},
		{"top-level script", map[string]interface{}{"script": "malicious"}, true},
		{"nested in query", map[string]interface{}{
			"query": map[string]interface{}{
				"script_score": map[string]interface{}{
					"script": map[string]interface{}{"source": "..."},
				},
			},
		}, true},
		{"script_fields", map[string]interface{}{
			"script_fields": map[string]interface{}{
				"foo": map[string]interface{}{"script": map[string]interface{}{"source": "..."}},
			},
		}, true},
		{"script inside array", map[string]interface{}{
			"sort": []interface{}{
				map[string]interface{}{"_script": map[string]interface{}{"script": map[string]interface{}{"source": "..."}}},
			},
		}, true},
		{"nil body", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := containsScriptClause(c.body); got != c.want {
				t.Errorf("containsScriptClause(%v) = %v, want %v", c.body, got, c.want)
			}
		})
	}
}

func TestClampResultSize(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]interface{}
		want interface{}
		has  bool
	}{
		{"no size key", map[string]interface{}{}, nil, false},
		{"under cap", map[string]interface{}{"size": float64(10)}, 10, true},
		{"exactly cap", map[string]interface{}{"size": float64(100)}, 100, true},
		{"embedded over cap gets clamped", map[string]interface{}{"size": float64(50000)}, 100, true},
		{"negative removed", map[string]interface{}{"size": float64(-1)}, nil, false},
		{"non-numeric removed", map[string]interface{}{"size": "not-a-number"}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clampResultSize(c.in)
			got, ok := c.in["size"]
			if ok != c.has {
				t.Fatalf("clampResultSize(%v): presence = %v, want %v", c.name, ok, c.has)
			}
			if c.has && got != c.want {
				t.Fatalf("clampResultSize(%v) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

func TestReferencesSystemIndex(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"logs-*", false},
		{"winlogbeat-*", false},
		{".kibana", true},
		{".kibana_1", true},
		{".security-7", true},
		{"logs-*,.kibana", true},
		{" .kibana ", true},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			if got := referencesSystemIndex(c.pattern); got != c.want {
				t.Errorf("referencesSystemIndex(%q) = %v, want %v", c.pattern, got, c.want)
			}
		})
	}
}
