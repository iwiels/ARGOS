package tools

import "github.com/iwiels/ARGOS/argos-bin/internal/mcp"

func RegisterAll(s *mcp.Server) {
	RegisterSync(s)
	RegisterInfo(s)
	RegisterMemorySearch(s)
	RegisterMemoryContext(s)
	RegisterMemorySave(s)
	RegisterScout(s)
	RegisterDispatch(s)
	RegisterAuditRunStart(s)
	RegisterAuditRunPhase(s)
	RegisterAuditRunInspect(s)
	RegisterAuditRunCorrelate(s)
}
