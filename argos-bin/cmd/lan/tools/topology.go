package tools

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

type topologyReport struct {
	Summary   topologySummary   `json:"summary"`
	Topology  []hostClass       `json:"topology"`
	Risks     []riskFinding     `json:"risks"`
	Timestamp string            `json:"timestamp"`
}

type topologySummary struct {
	TotalHosts int `json:"total_hosts"`
	RiskCount  int `json:"risk_count"`
}

type hostClass struct {
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	Classification string `json:"classification"`
	OpenPorts      []int  `json:"open_ports,omitempty"`
}

type riskFinding struct {
	IP          string `json:"ip"`
	Port        int    `json:"port,omitempty"`
	Risk        string `json:"risk"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type storedFinding struct {
	Timestamp string                 `json:"timestamp"`
	Kind      string                 `json:"kind"`
	Agent     string                 `json:"agent"`
	Data      map[string]interface{} `json:"data"`
}

func RegisterBuildTopology(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "build_topology",
			Description: "Build network topology report from accumulated scan findings, classifying hosts and identifying risks",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]mcp.Property{},
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			report := buildTopologyFromMemory(ctx.MemoryDir)

			// Persist the topology for future reference
			if ctx.MemoryDir != "" {
				topoPath := filepath.Join(ctx.MemoryDir, "findings", "topology.json")
				data, err := json.MarshalIndent(report, "", "  ")
				if err == nil {
					os.WriteFile(topoPath, data, 0644)
					ctx.Log("Topology persisted to %s", topoPath)
				}
			}

			return report, nil
		},
	)
}

func buildTopologyFromMemory(memoryDir string) topologyReport {
	report := topologyReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Collect all findings
	var findings []storedFinding
	if memoryDir != "" {
		findingsDir := filepath.Join(memoryDir, "findings")
		entries, err := os.ReadDir(findingsDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				fpath := filepath.Join(findingsDir, entry.Name())
				data, err := os.ReadFile(fpath)
				if err != nil {
					continue
				}
				var finding storedFinding
				if err := json.Unmarshal(data, &finding); err != nil {
					continue
				}
				if finding.Kind == "job_listing" || finding.Kind == "cv_profile" || finding.Kind == "job_match" {
					continue
				}
				findings = append(findings, finding)
			}
		}
	}

	// Extract hosts from findings
	hostMap := make(map[string]*hostInfo)
	extractHostsFromFindings(findings, hostMap)

	// Also try to load scan results from various memory paths
	loadScanResults(memoryDir, hostMap)

	// Classify hosts
	classifyHosts(hostMap)

	// Build topology list
	for _, ip := range sortedKeys(hostMap) {
		info := hostMap[ip]
		report.Topology = append(report.Topology, hostClass{
			IP:             info.ip,
			MAC:            info.mac,
			Hostname:       info.hostname,
			Classification: info.classification,
			OpenPorts:      info.openPorts,
		})
	}

	// Identify risks
	report.Risks = identifyRisks(hostMap)
	report.Summary.TotalHosts = len(report.Topology)
	report.Summary.RiskCount = len(report.Risks)

	if report.Topology == nil {
		report.Topology = []hostClass{}
	}
	if report.Risks == nil {
		report.Risks = []riskFinding{}
	}

	return report
}

type hostInfo struct {
	ip             string
	mac            string
	hostname       string
	openPorts      []int
	services       []string
	classification string
	isGateway      bool
}

// riskPorts maps a port to a risk description
var riskPorts = map[int]struct {
	risk        string
	severity    string
	description string
}{
	23:   {"Telnet", "high", "Telnet is unencrypted and should be replaced with SSH"},
	3389: {"Open RDP", "medium", "Remote Desktop exposed; ensure strong authentication and NLA"},
	6379: {"Redis No Auth", "high", "Redis without authentication may expose sensitive data"},
	27017: {"MongoDB No Auth", "high", "MongoDB without authentication may expose databases"},
	1433: {"MSSQL", "medium", "Microsoft SQL Server exposed; review firewall rules"},
	3306: {"MySQL", "medium", "MySQL exposed to network; consider restricting access"},
	5432: {"PostgreSQL", "medium", "PostgreSQL exposed to network; consider restricting access"},
	5900: {"VNC", "high", "VNC without encryption can expose screen content"},
	161:  {"SNMP Public", "medium", "SNMP public community string exposes system information"},
}

func extractHostsFromFindings(findings []storedFinding, hostMap map[string]*hostInfo) {
	for _, f := range findings {
		data := f.Data
		if data == nil {
			continue
		}

		switch f.Kind {
		case "host_discovery", "discovery":
			if hostsRaw, ok := data["hosts"]; ok {
				if hostsList, ok := hostsRaw.([]interface{}); ok {
					for _, hRaw := range hostsList {
						if hMap, ok := hRaw.(map[string]interface{}); ok {
							addHostFromMap(hMap, hostMap)
						}
					}
				}
			}
			// Also handle direct raw JSON stored in findings dir
			ip, _ := data["ip"].(string)
			if ip != "" {
				ensureHost(hostMap, ip)
				info := hostMap[ip]
				if mac, ok := data["mac"].(string); ok && info.mac == "" {
					info.mac = mac
				}
				if hostname, ok := data["hostname"].(string); ok && info.hostname == "" {
					info.hostname = hostname
				}
			}

		case "port_scan", "portscan":
			if ip, ok := data["ip"].(string); ok {
				ensureHost(hostMap, ip)
				if results, ok := data["results"].([]interface{}); ok {
					for _, rRaw := range results {
						if rMap, ok := rRaw.(map[string]interface{}); ok {
							port, _ := rMap["port"].(float64)
							service, _ := rMap["service"].(string)
							info := hostMap[ip]
							info.openPorts = append(info.openPorts, int(port))
							if service != "" {
								info.services = append(info.services, service)
							}
						}
					}
				}
			}
		}
	}
}

func loadScanResults(memoryDir string, hostMap map[string]*hostInfo) {
	if memoryDir == "" {
		return
	}

	// Load individual result files from memory-root
	patterns := []string{
		filepath.Join(memoryDir, "findings", "*.json"),
		filepath.Join(memoryDir, "*.json"),
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			data, err := os.ReadFile(match)
			if err != nil {
				continue
			}

			// Try to parse as an array of discovered hosts
			var hosts []discoveredHost
			if err := json.Unmarshal(data, &hosts); err == nil {
				for _, h := range hosts {
					info := ensureHost(hostMap, h.IP)
					if h.MAC != "" && info.mac == "" {
						info.mac = h.MAC
					}
					if h.Hostname != "" && info.hostname == "" {
						info.hostname = h.Hostname
					}
				}
				continue
			}

			// Try to parse as port scan results
			var ports []portResult
			if err := json.Unmarshal(data, &ports); err == nil && len(ports) > 0 {
				// Find the IP from log or filename
				ip := extractIPFromFilename(match)
				if ip != "" {
					info := ensureHost(hostMap, ip)
					for _, p := range ports {
						info.openPorts = append(info.openPorts, p.Port)
						info.services = append(info.services, p.Service)
					}
				}
				continue
			}

			// Try to parse as standalone finding
			var finding map[string]interface{}
			if err := json.Unmarshal(data, &finding); err == nil {
				extractHostFromMap(finding, hostMap)
			}
		}
	}
}

func extractIPFromFilename(name string) string {
	base := filepath.Base(name)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	// Try to find an IP pattern in the filename
	if net.ParseIP(base) != nil {
		return base
	}
	return ""
}

func extractHostFromMap(data map[string]interface{}, hostMap map[string]*hostInfo) {
	// Check various known fields
	for _, key := range []string{"ip", "target", "host", "address"} {
		if ipRaw, ok := data[key]; ok {
			if ip, ok := ipRaw.(string); ok && net.ParseIP(ip) != nil {
				info := ensureHost(hostMap, ip)
				if hostname, ok := data["hostname"].(string); ok && info.hostname == "" {
					info.hostname = hostname
				}
				if mac, ok := data["mac"].(string); ok && info.mac == "" {
					info.mac = mac
				}
				break
			}
		}
	}

	// Check nested results
	if results, ok := data["results"].([]interface{}); ok {
		for _, rRaw := range results {
			if rMap, ok := rRaw.(map[string]interface{}); ok {
				extractHostFromMap(rMap, hostMap)
			}
		}
	}

	// Check hosts array
	if hosts, ok := data["hosts"].([]interface{}); ok {
		for _, hRaw := range hosts {
			if hMap, ok := hRaw.(map[string]interface{}); ok {
				addHostFromMap(hMap, hostMap)
			}
		}
	}
}

func addHostFromMap(hMap map[string]interface{}, hostMap map[string]*hostInfo) {
	ip, _ := hMap["ip"].(string)
	if ip == "" || net.ParseIP(ip) == nil {
		return
	}

	info := ensureHost(hostMap, ip)
	if mac, ok := hMap["mac"].(string); ok && info.mac == "" {
		info.mac = mac
	}
	if hostname, ok := hMap["hostname"].(string); ok && info.hostname == "" {
		info.hostname = hostname
	}
}

func ensureHost(hostMap map[string]*hostInfo, ip string) *hostInfo {
	if _, ok := hostMap[ip]; !ok {
		hostMap[ip] = &hostInfo{
			ip:        ip,
			openPorts: []int{},
			services:  []string{},
		}
	}
	return hostMap[ip]
}

func classifyHosts(hostMap map[string]*hostInfo) {
	for _, info := range hostMap {
		info.classification = classifyHost(info)
	}
}

func classifyHost(info *hostInfo) string {
	// Check for gateway (usually .1 or .254 with minimal ports)
	if info.isGateway {
		return "gateway"
	}

	if ip := net.ParseIP(info.ip); ip != nil {
		parts := strings.Split(info.ip, ".")
		if len(parts) == 4 {
			lastOctet := parts[3]
			if lastOctet == "1" || lastOctet == "254" {
				// Often a gateway
				if len(info.openPorts) <= 3 {
					return "gateway"
				}
			}
		}
	}

	// Check for known IoT/multimedia services
	hasPrinter := false
	hasMedia := false
	hasServer := false

	for _, svc := range info.services {
		s := strings.ToLower(svc)
		if s == "printer" || s == "ipp" || s == "jetdirect" {
			hasPrinter = true
		}
		if s == "googlecast" || s == "airplay" || s == "raop" || s == "homekit" {
			hasMedia = true
		}
		if s == "ssh" || s == "http" || s == "https" || s == "smtp" || s == "mysql" || s == "postgresql" {
			hasServer = true
		}
	}

	if hasPrinter {
		return "printer"
	}

	if hasMedia {
		return "iot"
	}

	// Check port signatures
	for _, port := range info.openPorts {
		switch port {
		case 80, 443, 8080, 8443:
			hasServer = true
		case 22, 21, 25, 53:
			hasServer = true
		case 3306, 5432, 1433, 6379, 27017:
			return "database"
		}
	}

	if hasServer && len(info.openPorts) >= 3 {
		return "server"
	}

	if len(info.openPorts) > 5 {
		return "server"
	}

	return "workstation"
}

func identifyRisks(hostMap map[string]*hostInfo) []riskFinding {
	var risks []riskFinding

	for _, info := range hostMap {
		if info.classification == "gateway" {
			continue
		}

		for _, port := range info.openPorts {
			if risk, ok := riskPorts[port]; ok {
				risks = append(risks, riskFinding{
					IP:          info.ip,
					Port:        port,
					Risk:        risk.risk,
					Severity:    risk.severity,
					Description: risk.description,
				})
			}
		}

		if len(info.openPorts) > 20 {
			risks = append(risks, riskFinding{
				IP:          info.ip,
				Risk:        "Excessive Open Ports",
				Severity:    "low",
				Description: fmt.Sprintf("Host has %d open ports, which may indicate a large attack surface", len(info.openPorts)),
			})
		}
	}

	return risks
}

func sortedKeys(m map[string]*hostInfo) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Ensure fmt is used
var _ = fmt.Sprintf
