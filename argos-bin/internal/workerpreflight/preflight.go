package workerpreflight

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/gatewayprotocol"
	"github.com/iwiels/argos-auditor/argos-bin/internal/guard"
)

const (
	ProtocolVersion = 1
	maxProbeCount   = 20
	maxProbeBody    = 64 << 10
)

type Probe struct {
	Status    int   `json:"status"`
	LatencyMS int64 `json:"latency_ms"`
}

type Result struct {
	Protocol    int               `json:"protocol"`
	Target      string            `json:"target"`
	Complete    bool              `json:"complete"`
	Probes      []Probe           `json:"probes"`
	WAFVendors  []string          `json:"waf_vendors"`
	WAFEvidence map[string]string `json:"waf_evidence"`
}

func NewClient(proxyAddress string) (*http.Client, error) {
	client, _, err := NewClientWithMonitor(proxyAddress)
	return client, err
}

func NewClientWithMonitor(proxyAddress string) (*http.Client, *Monitor, error) {
	proxyURL, err := url.Parse(strings.TrimSpace(proxyAddress))
	if err != nil || proxyURL == nil || proxyURL.Scheme != "http" || proxyURL.User != nil || proxyURL.Hostname() == "" || proxyURL.Path != "" || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		return nil, nil, fmt.Errorf("worker scope gateway proxy address is invalid")
	}
	ip := net.ParseIP(proxyURL.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return nil, nil, fmt.Errorf("worker scope gateway proxy must use a loopback IP address")
	}
	port, err := strconv.Atoi(proxyURL.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, nil, fmt.Errorf("worker scope gateway proxy port is invalid")
	}
	monitor := &Monitor{}
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return proxyURL, nil },
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{
		Transport: gatewayResponseTransport{base: transport, monitor: monitor},
		Timeout:   30 * time.Second,
	}, monitor, nil
}

type Monitor struct {
	failures atomic.Int64
}

func (m *Monitor) FailureCount() int64 {
	if m == nil {
		return 0
	}
	return m.failures.Load()
}

func (m *Monitor) recordFailure() {
	if m != nil {
		m.failures.Add(1)
	}
}

func Run(ctx context.Context, target string, probes int, client *http.Client) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		return Result{}, fmt.Errorf("worker preflight requires the scope gateway client")
	}
	if err := validateTarget(target); err != nil {
		return Result{}, err
	}
	if probes < 1 || probes > maxProbeCount {
		return Result{}, fmt.Errorf("worker preflight probe count must be between 1 and %d", maxProbeCount)
	}

	result := Result{
		Protocol:    ProtocolVersion,
		Target:      target,
		Probes:      make([]Probe, 0, probes),
		WAFVendors:  make([]string, 0),
		WAFEvidence: map[string]string{},
	}
	for i := 0; i < probes; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return Result{}, fmt.Errorf("create health probe %d: %w", i+1, err)
		}
		req.Header.Set("User-Agent", guardWAFUserAgent)
		started := time.Now()
		response, err := client.Do(req)
		latency := time.Since(started).Milliseconds()
		if err != nil {
			return Result{}, fmt.Errorf("health probe %d failed through the scope gateway: %w", i+1, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxProbeBody))
		closeErr := response.Body.Close()
		if readErr != nil {
			return Result{}, fmt.Errorf("read health probe %d response: %w", i+1, readErr)
		}
		if closeErr != nil {
			return Result{}, fmt.Errorf("close health probe %d response: %w", i+1, closeErr)
		}
		result.Probes = append(result.Probes, Probe{Status: response.StatusCode, LatencyMS: latency})
		vendors, evidence := guard.FingerprintWAFResponse(response.Header, body)
		for _, vendor := range vendors {
			if _, exists := result.WAFEvidence[vendor]; !exists {
				result.WAFVendors = append(result.WAFVendors, vendor)
			}
			result.WAFEvidence[vendor] = evidence[vendor]
		}
	}

	result.Complete = true
	return result, nil
}

func ValidateResult(result Result, target string, probes int) error {
	if result.Protocol != ProtocolVersion {
		return fmt.Errorf("worker preflight protocol %d is unsupported", result.Protocol)
	}
	if result.Target != target {
		return fmt.Errorf("worker preflight target does not match the requested target")
	}
	if !result.Complete {
		return fmt.Errorf("worker preflight reported an incomplete result")
	}
	if probes < 1 || probes > maxProbeCount || len(result.Probes) != probes {
		return fmt.Errorf("worker preflight returned %d of %d required health probes", len(result.Probes), probes)
	}
	for i, probe := range result.Probes {
		if probe.Status < 100 || probe.Status > 599 || probe.LatencyMS < 0 {
			return fmt.Errorf("worker preflight probe %d has invalid status or latency", i+1)
		}
	}
	for _, vendor := range result.WAFVendors {
		if strings.TrimSpace(vendor) == "" {
			return fmt.Errorf("worker preflight returned an empty WAF vendor")
		}
	}
	return nil
}

func validateTarget(target string) error {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return fmt.Errorf("worker preflight target must be an absolute HTTP or HTTPS URL without user information")
	}
	return nil
}

const guardWAFUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"

type gatewayResponseTransport struct {
	base    http.RoundTripper
	monitor *Monitor
}

func (t gatewayResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	if err != nil {
		t.monitor.recordFailure()
		return nil, err
	}
	if response.Header.Get(gatewayprotocol.ScopeBlockedHeader) != "" {
		t.monitor.recordFailure()
		_ = response.Body.Close()
		return nil, fmt.Errorf("target blocked by session scope gateway")
	}
	if response.Header.Get(gatewayprotocol.GatewayErrorHeader) != "" {
		t.monitor.recordFailure()
		_ = response.Body.Close()
		return nil, fmt.Errorf("scope gateway could not complete the upstream request")
	}
	response.Body = monitoredBody{ReadCloser: response.Body, monitor: t.monitor}
	return response, nil
}

type monitoredBody struct {
	io.ReadCloser
	monitor *Monitor
}

func (b monitoredBody) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	if err != nil && err != io.EOF {
		b.monitor.recordFailure()
	}
	return n, err
}

func (b monitoredBody) Close() error {
	err := b.ReadCloser.Close()
	if err != nil {
		b.monitor.recordFailure()
	}
	return err
}

func (t gatewayResponseTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
