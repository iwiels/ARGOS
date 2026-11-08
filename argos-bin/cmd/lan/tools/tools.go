package tools

import "github.com/iwiels/ARGOS/argos-bin/internal/mcp"

func RegisterAll(s *mcp.Server) {
	RegisterHostDiscovery(s)
	RegisterPortScan(s)
	RegisterBannerGrab(s)
	RegisterSNMPQuery(s)
	RegisterMDNSDiscover(s)
	RegisterBuildTopology(s)
}
