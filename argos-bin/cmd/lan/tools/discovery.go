package tools

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

type discoveredHost struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Method   string `json:"method"`
}

func RegisterHostDiscovery(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "host_discovery",
			Description: "Discover active hosts on the local network using ARP, TCP ping, and NBNS",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"cidr": {
						Type:        "string",
						Description: "CIDR notation (e.g. 192.168.1.0/24). Empty auto-detects local network",
					},
				},
			},
			Annotations: &mcp.ToolAnnotations{
				IdempotentHint: mcp.BoolPtr(true),
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				CIDR string `json:"cidr"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid parameters: " + err.Error()}
			}

			cidr := input.CIDR
			if cidr == "" {
				auto, err := autoDetectCIDR()
				if err != nil {
					return nil, &mcp.ErrorObj{Code: -32603, Message: "Cannot auto-detect network: " + err.Error()}
				}
				cidr = auto
				ctx.Log("Auto-detected network: %s", cidr)
			}

			ipnet, policyErr := validateLanCIDR(cidr)
			if policyErr != nil {
				return nil, policyErr
			}

			seen := make(map[string]bool)
			var hosts []discoveredHost

			arpHosts := discoverARP()
			for _, h := range arpHosts {
				if ipnet.Contains(net.ParseIP(h.IP)) && !seen[h.IP] {
					seen[h.IP] = true
					hosts = append(hosts, h)
				}
			}

			tcpHosts := discoverTCPPing(ipnet)
			for _, h := range tcpHosts {
				if !seen[h.IP] {
					seen[h.IP] = true
					hosts = append(hosts, h)
				}
			}

			// NBNS discovery for Windows networks
			nbnsHosts := discoverNBNS(ipnet)
			for _, h := range nbnsHosts {
				if !seen[h.IP] {
					seen[h.IP] = true
					hosts = append(hosts, h)
				}
			}

			if hosts == nil {
				hosts = []discoveredHost{}
			}

			return hosts, nil
		},
	)
}

func autoDetectCIDR() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("cannot list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() == nil {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if ones == 32 || ones == 0 {
				continue
			}
			_ = bits
			return ipnet.String(), nil
		}
	}
	return "", fmt.Errorf("no suitable network interface found")
}

func discoverARP() []discoveredHost {
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var hosts []discoveredHost
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	interfaceRE := regexp.MustCompile(`^Interface:\s+(\d+\.\d+\.\d+\.\d+)`)
	entryRE := regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{2,17})\s+(dynamic|static)`)

	var currentIface string
	for scanner.Scan() {
		line := scanner.Text()
		if m := interfaceRE.FindStringSubmatch(line); m != nil {
			currentIface = m[1]
			continue
		}
		if m := entryRE.FindStringSubmatch(line); m != nil {
			mac := strings.ReplaceAll(m[2], "-", ":")
			if strings.ToLower(mac) == "ff:ff:ff:ff:ff:ff" {
				continue
			}
			h := discoveredHost{
				IP:     m[1],
				MAC:    mac,
				Method: "arp",
			}
			_ = currentIface
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func discoverTCPPing(ipnet *net.IPNet) []discoveredHost {
	pingPorts := []int{80, 443, 22}
	var hosts []discoveredHost

	ip := ipnet.IP.Mask(ipnet.Mask)
	ones, bits := ipnet.Mask.Size()
	numHosts := (1 << uint(bits-ones)) - 2
	if numHosts > 1024 {
		numHosts = 256
	}

	results := make(chan discoveredHost, numHosts*len(pingPorts))
	done := make(chan struct{}, 1)

	go func() {
		sem := make(chan struct{}, 50)
		base := make(net.IP, len(ip))
		copy(base, ip)
		for i := 1; i <= numHosts; i++ {
			sem <- struct{}{}
			go func(idx int) {
				defer func() { <-sem }()
				testIP := net.IPv4(base[0], base[1], base[2], base[3]+byte(idx))
				if !ipnet.Contains(testIP) {
					return
				}

				for _, port := range pingPorts {
					addr := net.JoinHostPort(testIP.String(), strconv.Itoa(port))
					conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
					if err != nil {
						continue
					}
					conn.Close()
					results <- discoveredHost{
						IP:     testIP.String(),
						Method: fmt.Sprintf("tcp_ping:%d", port),
					}
					return
				}
			}(i)
		}
		for i := 0; i < cap(sem); i++ {
			sem <- struct{}{}
		}
		done <- struct{}{}
	}()

	seen := make(map[string]bool)
	timeout := time.After(15 * time.Second)
	loop := true
	for loop {
		select {
		case h := <-results:
			if !seen[h.IP] {
				seen[h.IP] = true
				hosts = append(hosts, h)
			}
		case <-done:
			loop = false
		case <-timeout:
			loop = false
		}
	}

	return hosts
}

func discoverNBNS(ipnet *net.IPNet) []discoveredHost {
	var hosts []discoveredHost

	broadcast := ipnet.IP.Mask(ipnet.Mask)

	for i := 0; i < len(broadcast); i++ {
		broadcast[i] |= ^ipnet.Mask[i]
	}
	if broadcast.To4() == nil {
		return nil
	}

	brAddr := broadcast.To4()
	bcastStr := fmt.Sprintf("%d.%d.%d.%d", brAddr[0], brAddr[1], brAddr[2], brAddr[3])

	// Query suffix: *<00><00><00><00><00>... (NetBIOS status query for all names)
	// Simplified: we do a NetBIOS Name Service NBSTAT query
	// Transaction ID 0x0010, Flags: 0x0110 (Name query, broadcast, no recursion)
	// Questions: 1, AnswerRRs: 0, Authority: 0, Additional: 0
	// Question: encoded "*" + 00 00 21 00 01 (NBSTAT type, IN class)

	encodedName := encodeNetBIOSName("*")
	pkt := buildNBNSQueryPacket(encodedName, 0x0021) // NBSTAT

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(bcastStr),
		Port: 137,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)

	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n < 50 {
			continue
		}

		hostname := parseNBNSResponse(buf[:n])
		if hostname != "" {
			hosts = append(hosts, discoveredHost{
				IP:       addr.IP.String(),
				Hostname: hostname,
				Method:   "nbns",
			})
		}
	}

	return hosts
}

func encodeNetBIOSName(name string) []byte {
	var encoded []byte
	// Pad name to 16 characters
	padded := name
	for len(padded) < 16 {
		padded += " "
	}
	if len(padded) > 16 {
		padded = padded[:16]
	}

	for _, ch := range []byte(padded) {
		encoded = append(encoded, byte((ch>>4)+0x41))
		encoded = append(encoded, byte((ch&0x0F)+0x41))
	}
	return encoded
}

func buildNBNSQueryPacket(encodedName []byte, qtype uint16) []byte {
	pkt := make([]byte, 0, 512)

	// Transaction ID
	pkt = append(pkt, 0x00, 0x10)
	// Flags: 0x0110 = broadcast, no recursion
	pkt = append(pkt, 0x01, 0x10)
	// Questions: 1
	pkt = append(pkt, 0x00, 0x01)
	// Answer RRs: 0
	pkt = append(pkt, 0x00, 0x00)
	// Authority RRs: 0
	pkt = append(pkt, 0x00, 0x00)
	// Additional RRs: 0
	pkt = append(pkt, 0x00, 0x00)

	// Question: name length + encoded name + 0x00 terminator + type + class
	pkt = append(pkt, byte(len(encodedName)))
	pkt = append(pkt, encodedName...)
	pkt = append(pkt, 0x00)

	// QTYPE
	pkt = append(pkt, byte(qtype>>8), byte(qtype))
	// QCLASS = IN (0x0001)
	pkt = append(pkt, 0x00, 0x01)

	return pkt
}

func parseNBNSResponse(data []byte) string {
	if len(data) < 12 {
		return ""
	}

	// Skip header (12 bytes) and question section
	pos := 12
	if pos >= len(data) {
		return ""
	}

	// Skip question name
	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			pos++
			break
		}
		if length&0xC0 == 0xC0 {
			pos += 2
			break
		}
		pos += length + 1
		if pos >= len(data) {
			return ""
		}
	}

	// Skip QTYPE and QCLASS
	pos += 4
	if pos+2 > len(data) {
		return ""
	}

	// Parse answer RR count from header
	ansCount := int(data[6])<<8 | int(data[7])
	if ansCount == 0 {
		return ""
	}

	// Parse first answer - skip name
	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			pos++
			break
		}
		if length&0xC0 == 0xC0 {
			pos += 2
			break
		}
		pos += length + 1
		if pos >= len(data) {
			return ""
		}
	}

	if pos+10 > len(data) {
		return ""
	}

	// Skip type, class, TTL (8 bytes)
	pos += 8
	// Read RDLENGTH
	rdLength := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if pos+rdLength > len(data) {
		return ""
	}

	// NBSTAT response: number of names (1 byte) followed by name entries
	if rdLength < 1 {
		return ""
	}
	numNames := int(data[pos])
	pos++

	for i := 0; i < numNames && pos+18 <= len(data); i++ {
		// 16 bytes NetBIOS name + 1 byte type + 1 byte flags
		nameBytes := data[pos : pos+15]
		// Decode first 15 bytes of first name
		name := decodeNetBIOSName(nameBytes)
		if name != "" {
			return name
		}
		pos += 18
	}

	return ""
}

func decodeNetBIOSName(encoded []byte) string {
	var decoded []byte
	for i := 0; i+1 < len(encoded) && i < 32; i += 2 {
		high := encoded[i] - 0x41
		low := encoded[i+1] - 0x41
		if high > 15 || low > 15 {
			break
		}
		decoded = append(decoded, byte(high<<4|low))
	}

	name := string(decoded)
	name = strings.TrimRight(name, " ")
	return name
}
