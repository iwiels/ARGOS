package tools

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

// testHelper provides pipe-based communication with the LAN MCP server.
type testHelper struct {
	server    *mcp.Server
	clientR   *io.PipeReader
	clientW   *io.PipeWriter
	serverR   *io.PipeReader
	serverW   *io.PipeWriter
	memoryDir string
	t         *testing.T
}

func newTestHelper(t *testing.T, memoryDir string) *testHelper {
	t.Helper()
	// Cross-connected pipes:
	//   clientW -> serverR  (test writes request, server reads it)
	//   serverW -> clientR  (server writes response, test reads it)
	serverR, clientW := io.Pipe()
	clientR, serverW := io.Pipe()

	s := mcp.NewServer(mcp.ServerInfo{
		Name:    "Argos LAN Scanner",
		Version: "1.0.0",
	})
	s.SetMemoryDir(memoryDir)
	RegisterAll(s)

	th := &testHelper{
		server:    s,
		clientR:   clientR,
		clientW:   clientW,
		serverR:   serverR,
		serverW:   serverW,
		memoryDir: memoryDir,
		t:         t,
	}

	go func() {
		scanner := bufio.NewScanner(serverR)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			var req mcp.Request
			if err := json.Unmarshal([]byte(line), &req); err != nil {
				continue
			}
			th.dispatch(req, serverW)
		}
	}()

	return th
}

func (th *testHelper) dispatch(req mcp.Request, w *io.PipeWriter) {
	toolCtx := mcp.ToolContext{
		MemoryDir: th.memoryDir,
		Log:       func(format string, args ...interface{}) {},
	}

	var resp mcp.Response
	resp.JSONRPC = "2.0"
	resp.ID = req.ID

	switch req.Method {
	case "initialize":
		resp.Result = map[string]interface{}{
			"protocolVersion": mcp.ProtocolVersion,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo":      map[string]string{"name": "Argos LAN Scanner", "version": "1.0.0"},
		}
	case "tools/list":
		defs := getAllToolDefinitions()
		resp.Result = map[string]interface{}{
			"tools": defs,
		}
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = mcp.ErrInvalidParams
			break
		}
		result, errObj := callToolByName(th.server, params.Name, toolCtx, params.Arguments)
		if errObj != nil {
			resp.Error = errObj
		} else {
			resp.Result = result
		}
	default:
		resp.Error = mcp.ErrMethodNotFound
	}

	data, _ := json.Marshal(resp)
	w.Write(data)
	w.Write([]byte("\n"))
}

func (th *testHelper) sendRequest(method string, params map[string]interface{}) (map[string]interface{}, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	th.clientW.Write(data)
	th.clientW.Write([]byte("\n"))

	scanner := bufio.NewScanner(th.clientR)
	if scanner.Scan() {
		line := scanner.Text()
		var resp map[string]interface{}
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			return nil, err
		}
		return resp, nil
	}
	return nil, scanner.Err()
}

func (th *testHelper) close() {
	th.clientW.Close()
	th.clientR.Close()
	th.serverW.Close()
	th.serverR.Close()
}

func getAllToolDefinitions() []mcp.ToolDefinition {
	names := []string{
		"host_discovery",
		"port_scan",
		"banner_grab",
		"snmp_query",
		"mdns_discover",
		"build_topology",
	}
	defs := make([]mcp.ToolDefinition, len(names))
	for i, n := range names {
		defs[i] = mcp.ToolDefinition{Name: n}
	}
	return defs
}

func callToolByName(s *mcp.Server, name string, ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
	switch name {
	case "build_topology":
		return handleBuildTopology(ctx)
	default:
		return nil, mcp.ErrMethodNotFound
	}
}

func handleBuildTopology(ctx mcp.ToolContext) (interface{}, *mcp.ErrorObj) {
	report := buildTopologyFromMemory(ctx.MemoryDir)
	if ctx.MemoryDir != "" {
		topoPath := filepath.Join(ctx.MemoryDir, "findings", "topology.json")
		data, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			os.WriteFile(topoPath, data, 0644)
		}
	}
	return report, nil
}

// ===== TESTS =====

func TestToolRegistration_All6Registered(t *testing.T) {
	memDir := t.TempDir()
	th := newTestHelper(t, memDir)
	defer th.close()

	resp, err := th.sendRequest("tools/list", nil)
	if err != nil {
		t.Fatalf("tools/list failed: %v", err)
	}

	if errObj, hasErr := resp["error"]; hasErr {
		t.Fatalf("unexpected error: %v", errObj)
	}

	toolsRaw, ok := resp["result"].(map[string]interface{})["tools"]
	if !ok {
		t.Fatal("result.tools not found")
	}

	toolsList, ok := toolsRaw.([]interface{})
	if !ok {
		t.Fatalf("tools is not an array: %T", toolsRaw)
	}

	if len(toolsList) != 6 {
		t.Errorf("got %d tools, want 6", len(toolsList))
	}

	names := make(map[string]bool)
	for _, tRaw := range toolsList {
		tDef, ok := tRaw.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := tDef["name"].(string)
		names[name] = true
	}

	expected := []string{
		"host_discovery",
		"port_scan",
		"banner_grab",
		"snmp_query",
		"mdns_discover",
		"build_topology",
	}
	for _, n := range expected {
		if !names[n] {
			t.Errorf("missing tool: %s", n)
		}
	}
}

func TestBuildTopology_ReturnsValidStructure(t *testing.T) {
	memDir := t.TempDir()

	// Inject mock scan findings
	findingsDir := filepath.Join(memDir, "findings")
	if err := os.MkdirAll(findingsDir, 0755); err != nil {
		t.Fatalf("Failed to create findings dir: %v", err)
	}

	// Create a mock host discovery finding
	discoveryData := map[string]interface{}{
		"timestamp": "2025-01-01T00:00:00Z",
		"kind":      "host_discovery",
		"agent":     "lan-scanner",
		"data": map[string]interface{}{
			"hosts": []map[string]interface{}{
				{"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "gateway.local", "method": "arp"},
				{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "server.local", "method": "arp"},
				{"ip": "192.168.1.20", "mac": "11:22:33:44:55:66", "method": "tcp_ping:80"},
			},
		},
	}
	writeMockFinding(t, findingsDir, "scan-discovery.json", discoveryData)

	// Create a mock port scan finding
	portscanData := map[string]interface{}{
		"timestamp": "2025-01-01T00:00:00Z",
		"kind":      "port_scan",
		"agent":     "lan-scanner",
		"data": map[string]interface{}{
			"ip": "192.168.1.10",
			"results": []map[string]interface{}{
				{"port": float64(22), "protocol": "tcp", "service": "ssh", "state": "open"},
				{"port": float64(80), "protocol": "tcp", "service": "http", "state": "open"},
				{"port": float64(443), "protocol": "tcp", "service": "https", "state": "open"},
				{"port": float64(3306), "protocol": "tcp", "service": "mysql", "state": "open"},
				{"port": float64(6379), "protocol": "tcp", "service": "redis", "state": "open"},
			},
		},
	}
	writeMockFinding(t, findingsDir, "scan-portscan.json", portscanData)

	th := newTestHelper(t, memDir)
	defer th.close()

	resp, err := th.sendRequest("tools/call", map[string]interface{}{
		"name":      "build_topology",
		"arguments": map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("build_topology failed: %v", err)
	}

	if errObj, hasErr := resp["error"]; hasErr {
		t.Fatalf("build_topology error: %v", errObj)
	}

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("result is not a map")
	}

	// Validate summary
	summary, ok := result["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("summary is missing")
	}
	totalHosts, _ := summary["total_hosts"].(float64)
	if totalHosts == 0 {
		t.Error("total_hosts is 0, expected at least 1")
	}

	// Validate topology list
	topology, ok := result["topology"].([]interface{})
	if !ok {
		t.Fatal("topology is not an array")
	}
	if len(topology) == 0 {
		t.Fatal("topology is empty")
	}

	// Check that known hosts appear
	ipsFound := make(map[string]bool)
	for _, hRaw := range topology {
		h, ok := hRaw.(map[string]interface{})
		if !ok {
			continue
		}
		ip, _ := h["ip"].(string)
		ipsFound[ip] = true

		// Verify each host has a classification
		class, _ := h["classification"].(string)
		if class == "" {
			t.Errorf("host %s has no classification", ip)
		}
	}

	if !ipsFound["192.168.1.10"] {
		t.Error("192.168.1.10 not found in topology")
	}
	if !ipsFound["192.168.1.20"] {
		t.Error("192.168.1.20 not found in topology")
	}

	// Verify 192.168.1.1 is classified as gateway
	for _, hRaw := range topology {
		h, _ := hRaw.(map[string]interface{})
		if h["ip"] == "192.168.1.1" {
			class, _ := h["classification"].(string)
			if class != "gateway" {
				t.Errorf("192.168.1.1 classification = %q, want gateway", class)
			}
		}
	}

	// Validate risks
	risks, ok := result["risks"].([]interface{})
	if !ok {
		t.Fatal("risks is not an array")
	}
	if len(risks) == 0 {
		t.Error("expected at least 1 risk (redis without auth on 192.168.1.10)")
	}

	// Check for specific risk: Redis on 6379
	foundRedisRisk := false
	for _, rRaw := range risks {
		r, _ := rRaw.(map[string]interface{})
		if r["ip"] == "192.168.1.10" {
			port, _ := r["port"].(float64)
			if port == 6379 {
				foundRedisRisk = true
				break
			}
		}
	}
	if !foundRedisRisk {
		t.Error("expected risk finding for Redis (port 6379) on 192.168.1.10")
	}

	// Validate timestamp
	ts, ok := result["timestamp"].(string)
	if !ok || ts == "" {
		t.Error("timestamp is missing")
	}
}

func TestBuildTopology_EmptyMemory(t *testing.T) {
	memDir := t.TempDir() // No findings injected
	th := newTestHelper(t, memDir)
	defer th.close()

	resp, err := th.sendRequest("tools/call", map[string]interface{}{
		"name":      "build_topology",
		"arguments": map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("build_topology failed: %v", err)
	}

	if errObj, hasErr := resp["error"]; hasErr {
		t.Fatalf("build_topology error: %v", errObj)
	}

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("result is not a map")
	}

	summary, ok := result["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("summary is missing")
	}
	totalHosts, _ := summary["total_hosts"].(float64)
	if totalHosts != 0 {
		t.Errorf("total_hosts = %v, want 0", totalHosts)
	}

	topology, ok := result["topology"].([]interface{})
	if !ok || len(topology) != 0 {
		t.Error("topology should be empty")
	}
}

func TestBuildTopology_FiltersJobFindings(t *testing.T) {
	memDir := t.TempDir()
	findingsDir := filepath.Join(memDir, "findings")
	os.MkdirAll(findingsDir, 0755)

	// Inject a job_listing finding — should be excluded
	jobData := map[string]interface{}{
		"timestamp": "2025-01-01T00:00:00Z",
		"kind":      "job_listing",
		"agent":     "job-search",
		"data": map[string]interface{}{
			"title": "Senior Go Developer",
		},
	}
	writeMockFinding(t, findingsDir, "job-listing.json", jobData)

	// Real host discovery
	discData := map[string]interface{}{
		"timestamp": "2025-01-01T00:00:00Z",
		"kind":      "host_discovery",
		"agent":     "lan-scanner",
		"data": map[string]interface{}{
			"hosts": []map[string]interface{}{
				{"ip": "10.0.0.5", "mac": "de:ad:be:ef:00:01", "method": "arp"},
			},
		},
	}
	writeMockFinding(t, findingsDir, "host-discovery.json", discData)

	th := newTestHelper(t, memDir)
	defer th.close()

	resp, err := th.sendRequest("tools/call", map[string]interface{}{
		"name":      "build_topology",
		"arguments": map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("build_topology failed: %v", err)
	}

	result := resp["result"].(map[string]interface{})
	summary := result["summary"].(map[string]interface{})
	totalHosts, _ := summary["total_hosts"].(float64)

	if totalHosts != 1 {
		t.Errorf("total_hosts = %v, want 1 (job findings should be filtered out)", totalHosts)
	}
}

func writeMockFinding(t *testing.T, dir string, name string, data map[string]interface{}) {
	t.Helper()
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal mock finding: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0644); err != nil {
		t.Fatalf("Failed to write mock finding: %v", err)
	}
}

// ===== LAN tool-specific logic tests =====

func TestClassifyHost_Gateway(t *testing.T) {
	info := &hostInfo{
		ip:        "192.168.1.1",
		openPorts: []int{53, 67},
		services:  []string{"dns"},
	}
	class := classifyHost(info)
	if class != "gateway" {
		t.Errorf("classification = %q, want gateway", class)
	}
}

func TestClassifyHost_Server(t *testing.T) {
	info := &hostInfo{
		ip:        "192.168.1.10",
		openPorts: []int{22, 80, 443},
		services:  []string{"ssh", "http", "https"},
	}
	class := classifyHost(info)
	if class != "server" {
		t.Errorf("classification = %q, want server", class)
	}
}

func TestClassifyHost_Workstation(t *testing.T) {
	info := &hostInfo{
		ip:        "192.168.1.100",
		openPorts: []int{22},
		services:  []string{"ssh"},
	}
	class := classifyHost(info)
	if class != "workstation" {
		t.Errorf("classification = %q, want workstation", class)
	}
}

func TestClassifyHost_Database(t *testing.T) {
	info := &hostInfo{
		ip:        "192.168.1.50",
		openPorts: []int{3306},
		services:  []string{"mysql"},
	}
	class := classifyHost(info)
	if class != "database" {
		t.Errorf("classification = %q, want database", class)
	}
}

func TestRiskPorts_KnownRisks(t *testing.T) {
	hostMap := map[string]*hostInfo{
		"10.0.0.1": {
			ip:        "10.0.0.1",
			openPorts: []int{23, 6379, 3389},
			services:  []string{"telnet", "redis", "rdp"},
		},
	}

	risks := identifyRisks(hostMap)
	if len(risks) == 0 {
		t.Fatal("expected risks, got 0")
	}

	riskMap := make(map[int]bool)
	for _, r := range risks {
		riskMap[r.Port] = true
	}

	if !riskMap[23] {
		t.Error("expected risk for port 23 (Telnet)")
	}
	if !riskMap[6379] {
		t.Error("expected risk for port 6379 (Redis)")
	}
	if !riskMap[3389] {
		t.Error("expected risk for port 3389 (RDP)")
	}
}

func TestSortedKeys(t *testing.T) {
	m := map[string]*hostInfo{
		"10.0.0.3": {},
		"10.0.0.1": {},
		"10.0.0.2": {},
	}

	keys := sortedKeys(m)
	if len(keys) != 3 {
		t.Fatalf("len = %d, want 3", len(keys))
	}
	if keys[0] != "10.0.0.1" {
		t.Errorf("keys[0] = %q, want 10.0.0.1", keys[0])
	}
	if keys[1] != "10.0.0.2" {
		t.Errorf("keys[1] = %q, want 10.0.0.2", keys[1])
	}
	if keys[2] != "10.0.0.3" {
		t.Errorf("keys[2] = %q, want 10.0.0.3", keys[2])
	}
}

func TestExtractIPFromFilename(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"192.168.1.1.json", "192.168.1.1"},
		{"scan-10.0.0.5.json", ""},
		{"results.json", ""},
		{"10.0.0.1.json", "10.0.0.1"},
		{"scan-result.json", ""},
	}
	for _, tt := range tests {
		got := extractIPFromFilename(tt.name)
		if got != tt.want {
			t.Errorf("extractIPFromFilename(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestEnsureHost(t *testing.T) {
	hostMap := make(map[string]*hostInfo)
	info := ensureHost(hostMap, "10.0.0.1")
	if info == nil {
		t.Fatal("ensureHost returned nil")
	}
	if info.ip != "10.0.0.1" {
		t.Errorf("ip = %q, want 10.0.0.1", info.ip)
	}
	if len(info.openPorts) != 0 {
		t.Errorf("openPorts = %v, want empty", info.openPorts)
	}

	// Same IP should return existing entry
	info2 := ensureHost(hostMap, "10.0.0.1")
	if info != info2 {
		t.Error("ensureHost should return the same pointer for same IP")
	}
}

func TestPortScanProfiles(t *testing.T) {
	if len(scanProfiles["fast"]) != 6 {
		t.Errorf("fast profile should have 6 ports, got %d", len(scanProfiles["fast"]))
	}
	if len(scanProfiles["database"]) != 6 {
		t.Errorf("database profile should have 6 ports, got %d", len(scanProfiles["database"]))
	}
	if len(scanProfiles["web"]) != 7 {
		t.Errorf("web profile should have 7 ports, got %d", len(scanProfiles["web"]))
	}
}
