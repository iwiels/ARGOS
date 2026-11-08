package tools

import (
	"net"


	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
	"github.com/iwiels/ARGOS/argos-bin/internal/scope"
	"github.com/iwiels/ARGOS/argos-bin/internal/env"
)

const allowPublicLanTargetsEnv = "ARGOS_ALLOW_PUBLIC_LAN_TARGETS"

var lanScopeGuard *scope.ScopeGuard

func init() {
	lanScopeGuard, _ = scope.LoadFromEnv()
}

func publicLanTargetsAllowed() bool {
	return env.Get(allowPublicLanTargetsEnv) == "1"
}

func isLocalAuditIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func validateLanIP(input string) (net.IP, *mcp.ErrorObj) {
	ip := net.ParseIP(input)
	if ip == nil {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid IP address: " + input}
	}
	if lanScopeGuard != nil && !lanScopeGuard.IsIPAllowed(ip) {
		return nil, &mcp.ErrorObj{
			Code:    -32602,
			Message: "SECURITY ENFORCEMENT: Refusing to scan IP out of authorized scope: " + input,
		}
	}
	if publicLanTargetsAllowed() || isLocalAuditIP(ip) {
		return ip, nil
	}
	return nil, &mcp.ErrorObj{
		Code:    -32602,
		Message: "Refusing to scan public IP with LAN scanner: " + input + ". Set " + allowPublicLanTargetsEnv + "=1 only for an explicitly authorized public-scope engagement.",
	}
}

func validateLanCIDR(input string) (*net.IPNet, *mcp.ErrorObj) {
	ip, ipnet, err := net.ParseCIDR(input)
	if err != nil {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid CIDR: " + err.Error()}
	}
	if lanScopeGuard != nil && !lanScopeGuard.IsIPAllowed(ip) {
		return nil, &mcp.ErrorObj{
			Code:    -32602,
			Message: "SECURITY ENFORCEMENT: Refusing to scan CIDR out of authorized scope: " + input,
		}
	}
	if publicLanTargetsAllowed() || isLocalAuditIP(ip) {
		return ipnet, nil
	}
	return nil, &mcp.ErrorObj{
		Code:    -32602,
		Message: "Refusing to scan public CIDR with LAN scanner: " + input + ". Set " + allowPublicLanTargetsEnv + "=1 only for an explicitly authorized public-scope engagement.",
	}
}
