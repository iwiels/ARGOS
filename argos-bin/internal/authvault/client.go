package authvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxSecretBytes = 512 << 10

var secretIDPattern = regexp.MustCompile(`^auth_[A-Fa-f0-9]{32}$`)

type Client struct {
	endpoints []*url.URL
	token     string
	http      *http.Client
}

func NewClient(endpoints []string, token string) *Client {
	parsed := make([]*url.URL, 0, len(endpoints))
	for _, raw := range endpoints {
		if endpoint, ok := parseEndpoint(raw); ok {
			parsed = append(parsed, endpoint)
		}
	}
	return &Client{
		endpoints: parsed,
		token:     token,
		http: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy: nil,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func FromEnv() *Client {
	var endpoints []string
	if raw := os.Getenv("ARGOS_AUTH_VAULT_URLS"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &endpoints)
	}
	return NewClient(endpoints, os.Getenv("ARGOS_AUTH_VAULT_TOKEN"))
}

func parseEndpoint(raw string) (*url.URL, bool) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, false
	}
	if endpoint.Path != "" && endpoint.Path != "/" {
		return nil, false
	}
	address, err := netip.ParseAddr(strings.Trim(endpoint.Hostname(), "[]"))
	if err != nil || !privateAddress(address) {
		return nil, false
	}
	if endpoint.Port() != "" {
		port, err := strconv.Atoi(endpoint.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, false
		}
	}
	endpoint.Path = ""
	return endpoint, true
}

func privateAddress(address netip.Addr) bool {
	return address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast()
}

func (c *Client) Get(ctx context.Context, id string) (*string, error) {
	response, err := c.request(ctx, http.MethodGet, id, nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("secure vault is unavailable")
	}
	var payload struct {
		Value string `json:"value"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxSecretBytes+1))
	if err := decoder.Decode(&payload); err != nil || len(payload.Value) > maxSecretBytes {
		return nil, errors.New("secure vault is unavailable")
	}
	return &payload.Value, nil
}

func (c *Client) Put(ctx context.Context, id, value string) error {
	if len(value) > maxSecretBytes {
		return errors.New("secure vault is unavailable")
	}
	body, err := json.Marshal(struct {
		Value string `json:"value"`
	}{Value: value})
	if err != nil {
		return errors.New("secure vault is unavailable")
	}
	response, err := c.request(ctx, http.MethodPut, id, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		return errors.New("secure vault is unavailable")
	}
	return nil
}

func (c *Client) Delete(ctx context.Context, id string) error {
	response, err := c.request(ctx, http.MethodDelete, id, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		return errors.New("secure vault is unavailable")
	}
	return nil
}

func (c *Client) request(ctx context.Context, method, id string, body []byte) (*http.Response, error) {
	if !secretIDPattern.MatchString(id) || c.token == "" || len(c.endpoints) == 0 {
		return nil, errors.New("secure vault is unavailable")
	}
	for _, endpoint := range c.endpoints {
		requestURL := *endpoint
		requestURL.Path = "/v1/secrets/" + url.PathEscape(id)
		request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
		if err != nil {
			continue
		}
		request.Header.Set("Authorization", "Bearer "+c.token)
		request.Header.Set("Cache-Control", "no-store")
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := c.http.Do(request)
		if err != nil {
			continue
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			response.Body.Close()
			return nil, errors.New("secure vault is unavailable")
		}
		return response, nil
	}
	return nil, errors.New("secure vault is unavailable")
}
