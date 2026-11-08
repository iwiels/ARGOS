package tools

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

type mdnsService struct {
	ServiceType string            `json:"service_type"`
	Hostname    string            `json:"hostname"`
	IP          string            `json:"ip"`
	Port        int               `json:"port"`
	TxtRecords  map[string]string `json:"txt_records,omitempty"`
}

var mdnsTargetTypes = []string{
	"_http._tcp.local",
	"_ssh._tcp.local",
	"_smb._tcp.local",
	"_printer._tcp.local",
	"_googlecast._tcp.local",
	"_homekit._tcp.local",
	"_airplay._tcp.local",
	"_raop._tcp.local",
}

func RegisterMDNSDiscover(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "mdns_discover",
			Description: "Discover mDNS services on the local network (HTTP, SSH, SMB, Printer, Google Cast, HomeKit, AirPlay)",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]mcp.Property{},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: mcp.BoolPtr(true),
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			services := discoverMDNSServices()
			if services == nil {
				services = []mdnsService{}
			}
			return services, nil
		},
	)
}

func discoverMDNSServices() []mdnsService {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 0,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	// First query for service list via PTR for _services._dns-sd._udp.local
	// Then directly query each known service type for efficiency
	var allServices []mdnsService
	seen := make(map[string]bool)

	for _, serviceType := range mdnsTargetTypes {
		services := queryMDNSServiceType(conn, serviceType)
		for _, svc := range services {
			key := fmt.Sprintf("%s:%s:%d", svc.ServiceType, svc.IP, svc.Port)
			if !seen[key] {
				seen[key] = true
				allServices = append(allServices, svc)
			}
		}
	}

	return allServices
}

func queryMDNSServiceType(conn *net.UDPConn, serviceType string) []mdnsService {
	mcastAddr := &net.UDPAddr{
		IP:   net.IPv4(224, 0, 0, 251),
		Port: 5353,
	}

	// Build DNS PTR query for the service type
	// Also query SRV records for specific instances
	pkt := buildMDNSQuery(serviceType)

	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.WriteToUDP(pkt, mcastAddr); err != nil {
		return nil
	}

	var services []mdnsService
	deadline := time.Now().Add(1 * time.Second)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(deadline)
		buf := make([]byte, 4096)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		if addr.IP.IsMulticast() || addr.IP.IsUnspecified() {
			continue
		}

		svcs := parseMDNSResponse(buf[:n], serviceType, addr.IP.String())
		services = append(services, svcs...)
	}

	return services
}

func buildMDNSQuery(serviceType string) []byte {
	pkt := make([]byte, 0, 512)

	// DNS Header
	// ID: 0x0000
	pkt = append(pkt, 0x00, 0x00)
	// Flags: 0x0000 (standard query)
	pkt = append(pkt, 0x00, 0x00)
	// Questions: 1
	pkt = append(pkt, 0x00, 0x01)
	// Answer RRs: 0
	pkt = append(pkt, 0x00, 0x00)
	// Authority RRs: 0
	pkt = append(pkt, 0x00, 0x00)
	// Additional RRs: 0
	pkt = append(pkt, 0x00, 0x00)

	// Question: PTR record for service type
	qname := encodeDNSName(serviceType)
	pkt = append(pkt, qname...)

	// QTYPE = PTR (12)
	pkt = append(pkt, 0x00, 0x0C)
	// QCLASS = IN with QU flag (0x8001)
	pkt = append(pkt, 0x80, 0x01)

	return pkt
}

func encodeDNSName(name string) []byte {
	var encoded []byte
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) > 0 {
			encoded = append(encoded, byte(len(label)))
			encoded = append(encoded, []byte(label)...)
		}
	}
	encoded = append(encoded, 0x00)
	return encoded
}

func parseMDNSResponse(data []byte, serviceType string, srcIP string) []mdnsService {
	if len(data) < 12 {
		return nil
	}

	var services []mdnsService
	pos := 12

	// Parse question section
	pos = skipDNSName(data, pos)
	if pos < 0 {
		return nil
	}
	pos += 4 // skip QTYPE + QCLASS

	if pos >= len(data) {
		return nil
	}

	// Parse answer counts from header
	ansCount := int(data[6])<<8 | int(data[7])
	authCount := int(data[8])<<8 | int(data[9])
	addCount := int(data[10])<<8 | int(data[11])

	// Parse answers
	services = append(services, parseDNSRecords(data, &pos, ansCount, serviceType, srcIP)...)
	if pos < 0 {
		return nil
	}

	// Parse authority records
	services = append(services, parseDNSRecords(data, &pos, authCount, serviceType, srcIP)...)
	if pos < 0 {
		return nil
	}

	// Parse additional records (often contain A/AAAA and TXT)
	services = append(services, parseDNSRecords(data, &pos, addCount, serviceType, srcIP)...)

	return services
}

func parseDNSRecords(data []byte, pos *int, count int, serviceType string, srcIP string) []mdnsService {
	var services []mdnsService

	for i := 0; i < count; i++ {
		if *pos >= len(data) {
			*pos = -1
			return nil
		}

		*pos = skipDNSName(data, *pos)
		if *pos < 0 {
			return nil
		}

		if *pos+10 > len(data) {
			*pos = -1
			return nil
		}

		rtype := int(data[*pos])<<8 | int(data[*pos+1])
		*pos += 2
		rclass := int(data[*pos])<<8 | int(data[*pos+1])
		_ = rclass
		*pos += 2
		ttl := int(data[*pos])<<24 | int(data[*pos+1])<<16 | int(data[*pos+2])<<8 | int(data[*pos+3])
		_ = ttl
		*pos += 4
		rdlength := int(data[*pos])<<8 | int(data[*pos+1])
		*pos += 2

		if *pos+rdlength > len(data) {
			*pos = -1
			return nil
		}

		switch rtype {
		case 12: // PTR
			// PTR record: points to instance name
			instanceName := parseDNSNameString(data, *pos)
			// Query SRV record for this instance
			if instanceName != "" {
				// We'll get the details from the accompanying SRV/TXT records
			}

		case 16: // TXT
			txtMap := parseTXTRecord(data[*pos : *pos+rdlength])
			if len(services) > 0 {
				services[len(services)-1].TxtRecords = txtMap
			}

		case 33: // SRV
			if rdlength < 6 {
				*pos += rdlength
				continue
			}
			priority := int(data[*pos])<<8 | int(data[*pos+1])
			_ = priority
			weight := int(data[*pos+2])<<8 | int(data[*pos+3])
			_ = weight
			port := int(data[*pos+4])<<8 | int(data[*pos+5])
			*pos += 6

			target := parseDNSNameString(data, *pos)
			if target == "" {
				target = srcIP
			}

			svc := mdnsService{
				ServiceType: serviceType,
				Hostname:    target,
				IP:          srcIP,
				Port:        port,
			}
			services = append(services, svc)
			// Adjust pos back for the skip at the end
			*pos = *pos + (rdlength - 6)

		case 1: // A
			if rdlength == 4 {
				ip := net.IPv4(data[*pos], data[*pos+1], data[*pos+2], data[*pos+3]).String()
				if len(services) > 0 {
					services[len(services)-1].IP = ip
				}
			}

		case 28: // AAAA
			if rdlength == 16 {
				ip := net.IP(data[*pos : *pos+16]).String()
				if len(services) > 0 {
					if services[len(services)-1].IP == "" || services[len(services)-1].IP == srcIP {
						services[len(services)-1].IP = ip
					}
				}
			}
		}

		*pos += rdlength

		// Re-adjust for SRV parsing
		if rtype == 33 {
			// SRV already advanced pos past the data
		}
	}

	return services
}

func skipDNSName(data []byte, pos int) int {
	for pos < len(data) {
		b := data[pos]
		if b == 0 {
			return pos + 1
		}
		if b&0xC0 == 0xC0 {
			return pos + 2
		}
		pos += int(b) + 1
		if pos >= len(data) {
			return -1
		}
	}
	return -1
}

func parseDNSNameString(data []byte, start int) string {
	var labels []string
	pos := start

	for pos < len(data) {
		b := data[pos]
		if b == 0 {
			break
		}
		if b&0xC0 == 0xC0 {
			// Pointer - follow it
			if pos+1 >= len(data) {
				return ""
			}
			offset := int(b&0x3F)<<8 | int(data[pos+1])
			// Recursively resolve pointer
			rest := parseDNSNameString(data, offset)
			if rest != "" {
				labels = append(labels, rest)
			}
			break
		}
		pos++
		if pos+int(b) > len(data) {
			return ""
		}
		labels = append(labels, string(data[pos:pos+int(b)]))
		pos += int(b)
	}

	return strings.Join(labels, ".")
}

func parseTXTRecord(data []byte) map[string]string {
	result := make(map[string]string)
	pos := 0

	for pos < len(data) {
		if pos >= len(data) {
			break
		}
		length := int(data[pos])
		pos++
		if pos+length > len(data) {
			break
		}

		entry := string(data[pos : pos+length])
		pos += length

		if eqIdx := strings.Index(entry, "="); eqIdx >= 0 {
			key := entry[:eqIdx]
			val := entry[eqIdx+1:]
			result[key] = val
		}
	}

	return result
}

// Ensure fmt is used
var _ = fmt.Sprintf
