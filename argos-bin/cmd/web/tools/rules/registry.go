// Package rules exposes the canonical finding taxonomy registry.
//
// The registry is the single source of truth for the mapping between a
// scanner rule and the taxonomy the Argos engines match on: CWE, OWASP
// Top 10 2021, the canonical tag vocabulary and the minimum severity a rule
// guarantees.
//
// The JSON lives in packages/core/src/security/rules/registry.json (the
// TypeScript side owns it) and is mirrored into this package by
// scripts/sync-finding-rules.ts, which also fails CI when the two diverge.
// The Go module cannot embed a file outside its own tree, hence the mirror.
package rules

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed registry.json
var embeddedRegistry []byte

// Rule is one entry of the registry: the taxonomy of a single scanner rule.
type Rule struct {
	ID            string   `json:"id"`
	CWE           []string `json:"cwe"`
	OWASP         []string `json:"owasp"`
	SeverityFloor string   `json:"severity_floor"`
	Tags          []string `json:"tags"`
	References    []string `json:"references"`
	// Matcher records how the template decides that it matched: "content"
	// (a word, regex or dsl assertion on the response) or "status" (the
	// status code alone). Empty means the rule is not known here.
	Matcher string `json:"matcher"`
}

type registryFile struct {
	Version    string            `json:"version"`
	Vocabulary []string          `json:"vocabulary"`
	CWEByTag   map[string]string `json:"cwe_by_tag"`
	Rules      []Rule            `json:"rules"`
}

type registry struct {
	version    string
	byID       map[string]Rule
	order      []string
	vocabulary map[string]bool
	cweByTag   map[string]string
}

var (
	once    sync.Once
	loaded  *registry
	loadErr error
)

// load parses the embedded registry exactly once. The result is immutable
// afterwards, so every accessor below is safe for concurrent use.
func load() *registry {
	once.Do(func() {
		var file registryFile
		if err := json.Unmarshal(embeddedRegistry, &file); err != nil {
			loadErr = err
			return
		}
		r := &registry{
			version:    file.Version,
			byID:       make(map[string]Rule, len(file.Rules)),
			order:      make([]string, 0, len(file.Rules)),
			vocabulary: make(map[string]bool, len(file.Vocabulary)),
			cweByTag:   file.CWEByTag,
		}
		for _, tag := range file.Vocabulary {
			r.vocabulary[strings.ToLower(tag)] = true
		}
		if r.cweByTag == nil {
			r.cweByTag = map[string]string{}
		}
		for _, rule := range file.Rules {
			if _, seen := r.byID[rule.ID]; seen {
				continue
			}
			r.byID[rule.ID] = rule
			r.order = append(r.order, rule.ID)
		}
		loaded = r
	})
	return loaded
}

// Err returns the error raised while parsing the embedded registry, if any.
// A parse failure degrades every lookup to "rule not found" instead of
// panicking inside a scan.
func Err() error {
	load()
	return loadErr
}

// Lookup returns the registry entry of a rule id ("nuclei:exposed-env-file",
// "semgrep:javascript.lang.security.audit.eval-detected"). The second return
// value reports whether the rule is known here.
func Lookup(id string) (Rule, bool) {
	r := load()
	if r == nil {
		return Rule{}, false
	}
	rule, ok := r.byID[strings.TrimSpace(id)]
	return rule, ok
}

// All returns every rule of the registry, in registry order.
func All() []Rule {
	r := load()
	if r == nil {
		return nil
	}
	out := make([]Rule, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.byID[id])
	}
	return out
}

// Version returns the version of the embedded registry.
func Version() string {
	r := load()
	if r == nil {
		return ""
	}
	return r.version
}

// Vocabulary returns the canonical tag vocabulary the compliance and ATT&CK
// engines match on.
func Vocabulary() []string {
	r := load()
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.vocabulary))
	for tag := range r.vocabulary {
		out = append(out, tag)
	}
	return out
}

// IsCanonicalTag reports whether a tag belongs to the canonical vocabulary.
// A scanner tag outside the vocabulary is dropped instead of reaching the
// compliance and ATT&CK engines, which would not match it anyway.
func IsCanonicalTag(tag string) bool {
	r := load()
	if r == nil {
		return false
	}
	return r.vocabulary[strings.ToLower(strings.TrimSpace(tag))]
}

// CWEForTag returns the CWE a canonical tag implies, or "" when the tag
// carries no CWE of its own.
func CWEForTag(tag string) string {
	r := load()
	if r == nil {
		return ""
	}
	return r.cweByTag[strings.ToLower(strings.TrimSpace(tag))]
}

// CWEByTagAll returns a copy of the canonical tag to CWE mapping.
func CWEByTagAll() map[string]string {
	r := load()
	if r == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(r.cweByTag))
	for tag, cwe := range r.cweByTag {
		out[tag] = cwe
	}
	return out
}
