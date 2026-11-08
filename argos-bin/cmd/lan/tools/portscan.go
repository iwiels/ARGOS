package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	webtools "github.com/iwiels/ARGOS/argos-bin/cmd/web/tools"
	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

var standardPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
	993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
	5900, 6379, 8080, 8443, 9090, 27017,
}

var scanProfiles = map[string][]int{
	"fast":     {80, 443, 8080, 8443, 22, 3389},
	"database": {1433, 1521, 3306, 5432, 6379, 27017},
	"web":      {80, 443, 8000, 8080, 8443, 8888, 9090},
	"standard": standardPorts,
}

var portServices = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	143:   "imap",
	443:   "https",
	445:   "smb",
	993:   "imaps",
	995:   "pop3s",
	1433:  "ms-sql",
	1521:  "oracle-db",
	2049:  "nfs",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	9090:  "http-alt",
	27017: "mongodb",
}

type portResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	State    string `json:"state"`
}

type lanPortScanner func(context.Context, string, []int) ([]portResult, error)

func RegisterPortScan(s *mcp.Server) {
	registerPortScan(s, scanLanPorts)
}

func registerPortScan(s *mcp.Server, scan lanPortScanner) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "port_scan",
			Description: "Scan open TCP ports; the Linux runtime uses Naabu in unprivileged connect mode",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"ip": {
						Type:        "string",
						Description: "Target IP address",
					},
					"ports": {
						Type:        "array",
						Description: "Ports to scan. Empty uses standard audit set (21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9090,27017)",
						Items: &mcp.Items{
							Type: "integer",
						},
					},
					"profile": {
						Type:        "string",
						Description: "Predefined port profile: 'fast', 'database', 'web', or 'standard'",
					},
				},
				Required: []string{"ip"},
			},
			Annotations: &mcp.ToolAnnotations{
				DestructiveHint: mcp.BoolPtr(true),
			},
		},
		func(toolCtx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				IP      string `json:"ip"`
				Ports   []int  `json:"ports"`
				Profile string `json:"profile"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid parameters: " + err.Error()}
			}

			ip, policyErr := validateLanIP(input.IP)
			if policyErr != nil {
				return nil, policyErr
			}

			requestedPorts := input.Ports
			if len(requestedPorts) == 0 && input.Profile != "" {
				requestedPorts = scanProfiles[input.Profile]
			}
			ports, err := normalizeLanPorts(requestedPorts)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: err.Error()}
			}

			ctx := toolCtx.Ctx
			if ctx == nil {
				ctx = context.Background()
			}
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()

			results, err := scan(ctx, ip.String(), ports)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "LAN port scan failed: " + err.Error()}
			}
			return results, nil
		},
	)
}

func normalizeLanPorts(ports []int) ([]int, error) {
	if len(ports) == 0 {
		return append([]int(nil), standardPorts...), nil
	}
	seen := make(map[int]struct{}, len(ports))
	result := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port must be between 1 and 65535: %d", port)
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		result = append(result, port)
	}
	return result, nil
}

func buildNaabuArgs(ip string, ports []int) []string {
	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = strconv.Itoa(port)
	}
	return []string{"-host", ip, "-p", strings.Join(portStrings, ","), "-scan-type", "c", "-silent"}
}

func parseNaabuOutput(output string) []int {
	seen := make(map[int]struct{})
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		separator := strings.LastIndexByte(line, ':')
		if separator < 0 {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(line[separator+1:]))
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		seen[port] = struct{}{}
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

type naabuCommandRunner func(context.Context, string, []string) ([]byte, error)

func scanNaabu(ctx context.Context, binary, ip string, ports []int, run naabuCommandRunner) ([]portResult, error) {
	output, err := run(ctx, binary, buildNaabuArgs(ip, ports))
	if err != nil {
		return nil, fmt.Errorf("Naabu exited with an error: %w", err)
	}

	openPorts := parseNaabuOutput(string(output))
	results := make([]portResult, 0, len(openPorts))
	for _, port := range openPorts {
		service := portServices[port]
		if service == "" {
			service = "unknown"
		}
		results = append(results, portResult{
			Port:     port,
			Protocol: "tcp",
			Service:  service,
			State:    "open",
		})
	}
	return results, nil
}

func scanLanPorts(ctx context.Context, ip string, ports []int) ([]portResult, error) {
	if runtime.GOOS == "linux" {
		return scanLanPortsNaabu(ctx, ip, ports)
	}
	return scanLanPortsNative(ctx, ip, ports)
}

func scanLanPortsNative(ctx context.Context, ip string, ports []int) ([]portResult, error) {
	results := make(chan portResult, len(ports))
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

scanLoop:
	for _, port := range ports {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break scanLoop
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			portCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			address := net.JoinHostPort(ip, strconv.Itoa(port))
			connection, err := (&net.Dialer{}).DialContext(portCtx, "tcp", address)
			if err != nil {
				return
			}
			connection.Close()

			service := portServices[port]
			if service == "" {
				service = "unknown"
			}
			results <- portResult{Port: port, Protocol: "tcp", Service: service, State: "open"}
		}(port)
	}

	wg.Wait()
	close(results)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	openPorts := make([]portResult, 0, len(results))
	for result := range results {
		openPorts = append(openPorts, result)
	}
	sort.Slice(openPorts, func(i, j int) bool { return openPorts[i].Port < openPorts[j].Port })
	return openPorts, nil
}

func scanLanPortsNaabu(ctx context.Context, ip string, ports []int) ([]portResult, error) {
	binary, _, err := webtools.EnsureNaabu(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot prepare pinned Naabu: %w", err)
	}
	return scanNaabu(ctx, binary, ip, ports, func(ctx context.Context, binary string, args []string) ([]byte, error) {
		return exec.CommandContext(ctx, binary, args...).CombinedOutput()
	})
}
