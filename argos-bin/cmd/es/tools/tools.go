package tools

import (
	"strings"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

// Env holds the shared Elasticsearch client for all connector tools.
type Env struct {
	Client *Client
}

// referencesSystemIndex reports whether an index/pattern parameter (which may
// be a comma-separated list) names a dot-prefixed index. Dot-prefixed names
// are Elasticsearch's convention for system/internal indices (.kibana*,
// .security*, .geoip_databases, ...); expand_wildcards=open,closed only gates
// wildcard expansion, not an exact or explicit dotted name, so a caller can
// still reach these by naming them directly. This connector is scoped to
// customer log/data indices, so system indices are blocked by default.
func referencesSystemIndex(pattern string) bool {
	for _, part := range strings.Split(pattern, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

func NewEnv() *Env {
	return &Env{Client: NewClient(ConfigFromEnv())}
}

func RegisterAll(s *mcp.Server, env *Env) {
	RegisterInfo(s, env)
	RegisterClusterHealth(s, env)
	RegisterIndices(s, env)
	RegisterMapping(s, env)
	RegisterSearch(s, env)
	RegisterGet(s, env)
}
