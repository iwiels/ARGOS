package oob

import (
	"os"
	"os/exec"
	"path/filepath"
)

// DNSMode describes whether DNS-based out-of-band callbacks can be collected
// in this environment.
//
// A DNS collector is a whole DNS server with its own zone: implementing one
// in-process is out of scope, so the built-in collector speaks HTTP only.
// DNS callbacks are available when the operator runs the interactsh
// client/server pair, which is exactly the self-hosted setup Argos points
// at with ARGOS_OAST_DOMAIN.
type DNSMode struct {
	// Available reports whether DNS callbacks can be collected.
	Available bool
	// Client is the path of the interactsh-client binary, when found.
	Client string
	// Server is the path of the interactsh-server binary, when found.
	Server string
	// Reason explains how the DNS callbacks are collected, or why they are
	// not available. It is always set: the tool reports it to the agent.
	Reason string
}

// DetectDNS inspects the host for the interactsh client/server pair.
//
// The lookup never downloads anything: pulling a DNS server onto the host is
// an operator decision, not something a tool call may trigger on its own.
func DetectDNS(toolsDir string) DNSMode {
	client, hasClient := Locate("interactsh-client", toolsDir)
	server, hasServer := Locate("interactsh-server", toolsDir)
	mode := DNSMode{Client: client, Server: server}
	switch {
	case hasClient && hasServer:
		mode.Available = true
		mode.Reason = "the local interactsh server " + server + " collects the DNS callbacks"
	case hasClient:
		mode.Available = true
		mode.Reason = "the interactsh client is installed: the DNS callbacks are served by the " +
			"OAST server configured by the operator"
	case hasServer:
		mode.Reason = "interactsh-server was found but interactsh-client is missing: " +
			"DNS callbacks are unavailable, use HTTP callbacks only"
	default:
		mode.Reason = "neither interactsh-client nor interactsh-server was found in PATH or in the " +
			"tools directory: DNS callbacks are unavailable, use HTTP callbacks only"
	}
	return mode
}

// Locate finds an executable called name in PATH or in the tools directory.
// The tools directory layout matches the downloader: <toolsDir>/<name>/<name>.
func Locate(name, toolsDir string) (string, bool) {
	if path, err := exec.LookPath(name); err == nil {
		return path, true
	}
	if toolsDir == "" {
		return "", false
	}
	candidates := []string{
		filepath.Join(toolsDir, name, name),
		filepath.Join(toolsDir, name, name+".exe"),
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Size() == 0 {
			continue
		}
		return candidate, true
	}
	return "", false
}
