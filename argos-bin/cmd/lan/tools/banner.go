package tools

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
)

type bannerResult struct {
	IP               string `json:"ip"`
	Port             int    `json:"port"`
	Service          string `json:"service"`
	BannerText       string `json:"banner_text"`
	DetectedSoftware string `json:"detected_software"`
}

func RegisterBannerGrab(s *mcp.Server) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name:        "banner_grab",
			Description: "Connect to a service on an open port and read its banner to identify software and version",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"ip": {
						Type:        "string",
						Description: "Target IP address",
					},
					"port": {
						Type:        "integer",
						Description: "Target port number",
					},
				},
				Required: []string{"ip", "port"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: mcp.BoolPtr(true),
			},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Invalid parameters: " + err.Error()}
			}

			if _, policyErr := validateLanIP(input.IP); policyErr != nil {
				return nil, policyErr
			}

			if input.Port < 1 || input.Port > 65535 {
				return nil, &mcp.ErrorObj{Code: -32602, Message: "Port must be between 1 and 65535"}
			}

			service := portServices[input.Port]
			if service == "" {
				service = "unknown"
			}

			addr := net.JoinHostPort(input.IP, fmt.Sprintf("%d", input.Port))
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: fmt.Sprintf("Connection failed: %v", err)}
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(5 * time.Second))

			banner := readBanner(conn, service)
			detected := detectSoftware(banner, service)

			return bannerResult{
				IP:               input.IP,
				Port:             input.Port,
				Service:          service,
				BannerText:       banner,
				DetectedSoftware: detected,
			}, nil
		},
	)
}

func readBanner(conn net.Conn, service string) string {
	// Some services need a trigger to send their banner
	if service == "http" || service == "https" || service == "http-proxy" || service == "http-alt" {
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	} else if service == "smtp" {
		// SMTP sends banner on connect, just read
	} else if service == "ftp" {
		// FTP sends banner on connect
	} else if service == "ssh" {
		// SSH sends banner on connect
	} else if service == "pop3" {
		fmt.Fprintf(conn, "\r\n")
	} else if service == "imap" {
		fmt.Fprintf(conn, "\r\n")
	} else if service == "telnet" {
		// Telnet negotiation usually happens but just try to read
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		// Try reading line by line for some services
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			return ""
		}
		return strings.TrimSpace(line)
	}

	banner := strings.TrimSpace(string(buf[:n]))
	// Keep only printable ASCII
	clean := make([]byte, 0, len(banner))
	for _, b := range []byte(banner) {
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			clean = append(clean, b)
		} else {
			clean = append(clean, '.')
		}
	}
	return string(clean)
}

func detectSoftware(banner, service string) string {
	bannerLower := strings.ToLower(banner)

	switch service {
	case "ssh":
		if strings.Contains(bannerLower, "openssh") {
			return "OpenSSH"
		}
		if strings.Contains(bannerLower, "dropbear") {
			return "Dropbear SSH"
		}
		parts := strings.SplitN(banner, " ", 3)
		if len(parts) >= 2 {
			return parts[0] + " " + parts[1]
		}
		return strings.TrimSpace(banner)

	case "http", "https", "http-proxy", "http-alt":
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return strings.TrimSpace(line[7:])
			}
		}
		if strings.Contains(bannerLower, "apache") {
			return "Apache HTTP Server"
		}
		if strings.Contains(bannerLower, "nginx") {
			return "nginx"
		}
		if strings.Contains(bannerLower, "iis") {
			return "Microsoft IIS"
		}
		return "HTTP server"

	case "ftp":
		if strings.Contains(bannerLower, "vsftpd") {
			return "vsftpd"
		}
		if strings.Contains(bannerLower, "proftpd") {
			return "ProFTPD"
		}
		if strings.Contains(bannerLower, "filezilla") {
			return "FileZilla Server"
		}
		if strings.Contains(bannerLower, "microsoft") {
			return "Microsoft FTP"
		}
		parts := strings.SplitN(banner, " ", 3)
		if len(parts) >= 2 {
			return parts[0] + " " + parts[1]
		}
		return strings.TrimSpace(banner)

	case "smtp":
		if strings.Contains(bannerLower, "postfix") {
			return "Postfix"
		}
		if strings.Contains(bannerLower, "sendmail") {
			return "Sendmail"
		}
		if strings.Contains(bannerLower, "exim") {
			return "Exim"
		}
		if strings.Contains(bannerLower, "exchange") || strings.Contains(bannerLower, "microsoft") {
			return "Microsoft Exchange"
		}
		parts := strings.SplitN(banner, " ", 3)
		if len(parts) >= 2 {
			return parts[0] + " " + parts[1]
		}
		return strings.TrimSpace(banner)

	default:
		if len(banner) > 0 && len(banner) < 200 {
			return banner
		}
		return ""
	}
}
