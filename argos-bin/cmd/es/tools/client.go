package tools

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/env"
)

const defaultTimeout = 30 * time.Second

type Config struct {
	BaseURL   string
	APIKey    string
	User      string
	Password  string
	Insecure  bool
	TimeoutMS int
}

func ConfigFromEnv() *Config {
	cfg := &Config{
		BaseURL:  env.Get("ARGOS_ES_URL"),
		APIKey:   env.Get("ARGOS_ES_API_KEY"),
		User:     env.Get("ARGOS_ES_USER"),
		Password: env.Get("ARGOS_ES_PASSWORD"),
	}
	switch env.Get("ARGOS_ES_INSECURE") {
	case "1", "true", "TRUE", "yes":
		cfg.Insecure = true
	}
	if ms, err := strconv.Atoi(env.Get("ARGOS_ES_TIMEOUT_MS")); err == nil && ms > 0 {
		cfg.TimeoutMS = ms
	}
	return cfg
}

type Client struct {
	base string
	auth string // "ApiKey <key>" or empty
	user string
	pass string
	http *http.Client
}

func NewClient(cfg *Config) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Insecure {
		// Opcional y explícito vía env: clusters on-prem suelen tener certificados
		// auto-firmados. Preferir ARGOS_ES_API_KEY con TLS válido en producción.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
	}
	timeout := defaultTimeout
	if cfg.TimeoutMS > 0 {
		timeout = time.Duration(cfg.TimeoutMS) * time.Millisecond
	}
	auth := ""
	if cfg.APIKey != "" {
		auth = "ApiKey " + cfg.APIKey
	}
	return &Client{
		base: strings.TrimRight(cfg.BaseURL, "/"),
		auth: auth,
		user: cfg.User,
		pass: cfg.Password,
		http: &http.Client{Timeout: timeout, Transport: transport},
	}
}

// Do executes a request against the customer's Elasticsearch REST API and
// returns the parsed JSON response. Read-only by contract: all connector
// tools only use GET/POST _search; nothing ever mutates the cluster.
func (c *Client) Do(ctx context.Context, method, path string, body []byte) (interface{}, *mcp.ErrorObj) {
	if c.base == "" {
		return nil, &mcp.ErrorObj{
			Code:    -32603,
			Message: "Elasticsearch connector not configured: set ARGOS_ES_URL and ARGOS_ES_API_KEY (or ARGOS_ES_USER/ARGOS_ES_PASSWORD)",
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, &mcp.ErrorObj{Code: -32603, Message: fmt.Sprintf("invalid request: %v", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.auth != "" {
		req.Header.Set("Authorization", c.auth)
	} else if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &mcp.ErrorObj{Code: -32603, Message: fmt.Sprintf("request failed: %v", err)}
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, &mcp.ErrorObj{Code: -32603, Message: fmt.Sprintf("read response: %v", err)}
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 500 {
			msg = msg[:500] + "…"
		}
		return nil, &mcp.ErrorObj{Code: -32603, Message: fmt.Sprintf("Elasticsearch HTTP %d: %s", resp.StatusCode, msg)}
	}

	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return map[string]interface{}{"status": resp.StatusCode, "raw": string(data)}, nil
	}
	return parsed, nil
}

func invalidParams(err error) *mcp.ErrorObj {
	return &mcp.ErrorObj{Code: -32602, Message: fmt.Sprintf("invalid params: %v", err)}
}
