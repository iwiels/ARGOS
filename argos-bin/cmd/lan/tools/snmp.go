package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
)

type snmpResult struct {
	SysDescr    string `json:"sysDescr"`
	SysName     string `json:"sysName"`
	SysLocation string `json:"sysLocation"`
	SysServices int    `json:"sysServices"`
}

// SNMP OIDs to query
var snmpOIDs = map[string]string{
	"sysDescr":    "1.3.6.1.2.1.1.1.0",
	"sysName":     "1.3.6.1.2.1.1.5.0",
	"sysLocation": "1.3.6.1.2.1.1.6.0",
	"sysServices": "1.3.6.1.2.1.1.7.0",
}

func RegisterSNMPQuery(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "snmp_query",
			Description: "Query an SNMP v2c agent for system information (sysDescr, sysName, sysLocation, sysServices)",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"ip": {
						Type:        "string",
						Description: "Target IP address",
					},
					"community": {
						Type:        "string",
						Description: "SNMP community string",
						Default:     "public",
					},
				},
				Required: []string{"ip"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: mcp.BoolPtr(true),
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				IP        string `json:"ip"`
				Community string `json:"community"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid parameters: " + err.Error()}
			}

			if _, policyErr := validateLanIP(input.IP); policyErr != nil {
				return nil, policyErr
			}

			if input.Community == "" {
				input.Community = "public"
			}

			// Try external snmpget tool first
			result, err := snmpViaExec(input.IP, input.Community)
			if err == nil {
				return result, nil
			}

			// Fallback to manual SNMP v2c implementation
			ctx.Log("External snmpget not available, using manual SNMP: %v", err)
			result, err = snmpManual(input.IP, input.Community)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "SNMP query failed: " + err.Error()}
			}

			return result, nil
		},
	)
}

func snmpViaExec(ip, community string) (*snmpResult, error) {
	result := &snmpResult{}

	for key, oid := range snmpOIDs {
		cmd := exec.Command("snmpget", "-v", "2c", "-c", community, "-t", "2", "-r", "1", "-Oqv", ip, oid)
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("snmpget %s failed: %w", key, err)
		}
		val := strings.TrimSpace(string(output))
		val = strings.Trim(val, "\"")
		switch key {
		case "sysDescr":
			result.SysDescr = val
		case "sysName":
			result.SysName = val
		case "sysLocation":
			result.SysLocation = val
		case "sysServices":
			var s int
			fmt.Sscanf(val, "%d", &s)
			result.SysServices = s
		}
	}

	if result.SysDescr == "" && result.SysName == "" {
		return nil, fmt.Errorf("no SNMP response received")
	}

	return result, nil
}

func snmpManual(ip, community string) (*snmpResult, error) {
	addr := net.JoinHostPort(ip, "161")
	conn, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("cannot connect: %w", err)
	}
	defer conn.Close()

	result := &snmpResult{}
	requestID := 0x12345678

	for key, oid := range snmpOIDs {
		pkt, err := buildSNMPGetRequest(community, requestID, oid)
		if err != nil {
			continue
		}

		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(pkt); err != nil {
			continue
		}

		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}

		value := parseSNMPResponse(buf[:n])
		if value == "" {
			continue
		}

		switch key {
		case "sysDescr":
			result.SysDescr = value
		case "sysName":
			result.SysName = value
		case "sysLocation":
			result.SysLocation = value
		case "sysServices":
			var s int
			fmt.Sscanf(value, "%d", &s)
			result.SysServices = s
		}

		requestID++
	}

	if result.SysDescr == "" && result.SysName == "" {
		return nil, fmt.Errorf("no SNMP response received")
	}

	return result, nil
}

// buildSNMPGetRequest builds a raw SNMP v2c GetRequest PDU
// ASN.1 BER encoding structure:
//
//	SEQUENCE {
//	  INTEGER (version = 1 for v2c)
//	  OCTET STRING (community)
//	  [0] IMPLICIT SEQUENCE (GetRequest PDU) {
//	    INTEGER (request-id)
//	    INTEGER (error = 0)
//	    INTEGER (error-index = 0)
//	    SEQUENCE (varbind list) {
//	      SEQUENCE (varbind) {
//	        OID
//	        NULL
//	      }
//	    }
//	  }
//	}
func buildSNMPGetRequest(community string, requestID int, oid string) ([]byte, error) {
	var buf bytes.Buffer

	version := encodeInteger(1) // SNMP v2c
	communityBytes := encodeOctetString([]byte(community))
	encodedOID, err := encodeOID(oid)
	if err != nil {
		return nil, err
	}

	// Build varbind: SEQUENCE { OID, NULL }
	varbind := encodeSequence([]byte{
		0x06, byte(len(encodedOID)),
	}, encodedOID, []byte{0x05, 0x00})

	// Build varbind list: SEQUENCE { varbind }
	varbindList := encodeSequence([]byte{0x30}, varbind)

	// Build GetRequest PDU: [0] IMPLICIT SEQUENCE { request-id, error, error-index, varbind-list }
	pduBody := encodeSequence(nil,
		encodeInteger(requestID),
		encodeInteger(0), // error
		encodeInteger(0), // error-index
		varbindList,
	)
	pdu := encodeContextConstructed(0, pduBody)

	// Build outer SEQUENCE
	inner := encodeSequence(nil, version, communityBytes, pdu)
	buf.Write(inner)

	return buf.Bytes(), nil
}

func encodeInteger(value int) []byte {
	var data []byte
	v := value
	if v < 0 {
		v = -v
	}
	for v > 0 {
		data = append([]byte{byte(v & 0xFF)}, data...)
		v >>= 8
	}
	if len(data) == 0 {
		data = []byte{0x00}
	}
	// If high bit is set, add leading zero
	if data[0]&0x80 != 0 {
		data = append([]byte{0x00}, data...)
	}
	if value < 0 {
		data[0] |= 0x80
	}
	return append([]byte{0x02, byte(len(data))}, data...)
}

func encodeOctetString(data []byte) []byte {
	return append([]byte{0x04, byte(len(data))}, data...)
}

func encodeOID(oid string) ([]byte, error) {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID: %s", oid)
	}

	nums := make([]int, len(parts))
	for i, p := range parts {
		n := 0
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
			return nil, fmt.Errorf("invalid OID component: %s", p)
		}
		nums[i] = n
	}

	var encoded []byte
	// First two components are encoded as 40*first + second
	encoded = append(encoded, byte(40*nums[0]+nums[1]))

	for i := 2; i < len(nums); i++ {
		encoded = append(encoded, encodeOIDComponent(nums[i])...)
	}

	return append([]byte{0x06, byte(len(encoded))}, encoded...), nil
}

func encodeOIDComponent(value int) []byte {
	if value < 128 {
		return []byte{byte(value)}
	}

	var bytes []byte
	for value > 0 {
		b := byte(value & 0x7F)
		value >>= 7
		if len(bytes) > 0 {
			b |= 0x80
		}
		bytes = append([]byte{b}, bytes...)
	}
	return bytes
}

func encodeSequence(tag []byte, items ...[]byte) []byte {
	var body []byte
	for _, item := range items {
		body = append(body, item...)
	}
	if tag == nil {
		tag = []byte{0x30}
	}
	if len(body) < 128 {
		return append(append(tag, byte(len(body))), body...)
	}

	// Length > 127: use long form
	lengthBytes := make([]byte, 0)
	length := len(body)
	for length > 0 {
		lengthBytes = append([]byte{byte(length & 0xFF)}, lengthBytes...)
		length >>= 8
	}
	lengthBytes = append([]byte{byte(0x80 | len(lengthBytes))}, lengthBytes...)
	return append(append(tag, lengthBytes...), body...)
}

func encodeContextConstructed(tagNumber int, body []byte) []byte {
	tag := byte(0xA0 | tagNumber)
	if len(body) < 128 {
		return append([]byte{tag, byte(len(body))}, body...)
	}
	lengthBytes := make([]byte, 0)
	length := len(body)
	for length > 0 {
		lengthBytes = append([]byte{byte(length & 0xFF)}, lengthBytes...)
		length >>= 8
	}
	lengthBytes = append([]byte{byte(0x80 | len(lengthBytes))}, lengthBytes...)
	return append(append([]byte{tag}, lengthBytes...), body...)
}

func parseSNMPResponse(data []byte) string {
	// Find the varbind value in the SNMP response
	// Simple approach: skip to the last SEQUENCE and extract the value
	if len(data) < 10 {
		return ""
	}

	// Skip outer SEQUENCE header
	pos := 0
	if data[pos] != 0x30 {
		return ""
	}
	pos++
	if data[pos] < 0x80 {
		pos += 1 + int(data[pos])
	} else {
		numLen := int(data[pos] & 0x7F)
		pos++
		totalLen := 0
		for i := 0; i < numLen; i++ {
			totalLen = totalLen*256 + int(data[pos])
			pos++
		}
		pos = len(data) - totalLen
		// Reset: let's just search from the end
	}

	// Find the last varbind value by searching for tag 0x04 (OctetString) or 0x02 (Integer) or 0x41 (Gauge32, etc.)
	// Walk backwards to find the last value
	for i := len(data) - 1; i >= 0; i-- {
		tag := data[i]
		if tag == 0x04 || tag == 0x02 || tag == 0x41 || tag == 0x42 || tag == 0x43 || tag == 0x46 {
			length := int(data[i+1])
			if i+2+length > len(data) {
				continue
			}
			valueData := data[i+2 : i+2+length]

			switch tag {
			case 0x04: // OctetString
				return strings.TrimSpace(string(valueData))
			case 0x02, 0x41, 0x42, 0x43, 0x46: // Integer types
				val := big.NewInt(0)
				val.SetBytes(valueData)
				return val.String()
			}
		}
	}

	return ""
}
