package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/gatewayprotocol"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
	"github.com/iwiels/argos-auditor/argos-bin/internal/traffic"
)

type CaptureConfig struct {
	Store      *traffic.Store
	SessionID  string
	SourceTool string
}

func (c CaptureConfig) enabled() bool {
	return c.Store != nil && strings.TrimSpace(c.SessionID) != ""
}

func NewHandler(guard *scope.ScopeGuard, capture ...CaptureConfig) http.Handler {
	var captureConfig CaptureConfig
	if len(capture) > 0 {
		captureConfig = capture[0]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if guard == nil {
			writeGatewayError(w, "scope gateway is unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodConnect {
			handleConnect(w, r, guard, captureConfig)
			return
		}
		handleHTTP(w, r, guard, captureConfig)
	})
}

func handleHTTP(w http.ResponseWriter, r *http.Request, guard *scope.ScopeGuard, capture CaptureConfig) {
	if r.URL == nil || r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
		writeGatewayError(w, "only absolute HTTP proxy requests are supported", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		writeGatewayError(w, "protocol upgrades are not supported by the scope gateway", http.StatusNotImplemented)
		return
	}
	if !validPort(r.URL, "80") {
		writeScopeBlocked(w, "HTTP proxy request has an invalid port", http.StatusForbidden)
		return
	}
	if _, err := guard.ValidateTarget(r.Context(), r.URL.String()); err != nil {
		writeScopeBlocked(w, "target blocked by session scope", http.StatusForbidden)
		return
	}

	started := time.Now()
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header = r.Header.Clone()
	removeHopByHopHeaders(out.Header)
	if capture.enabled() && out.Body != nil {
		body := &capturedRequestBody{source: out.Body, limit: traffic.MaxBodySize}
		out.Body = body
		out.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body.snapshot())), nil
		}
	}
	transport := &http.Transport{
		DialContext:       guard.DialContext,
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(out)
	if err != nil {
		writeGatewayError(w, "scoped upstream request failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if capture.enabled() {
		_, err := traffic.CaptureAndRecord(capture.Store, guard.Client(), out, response, traffic.Meta{
			SessionID:    capture.SessionID,
			SourceTool:   capture.sourceTool(),
			Target:       r.URL.String(),
			Duration:     time.Since(started),
			ScopeAllowed: true,
		})
		if err != nil {
			log.Printf("argos scope gateway: cannot capture HTTP exchange for %s: %v", r.URL.Host, err)
		}
	}
	response.Header.Del(gatewayprotocol.ScopeBlockedHeader)
	response.Header.Del(gatewayprotocol.GatewayErrorHeader)
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	removeHopByHopHeaders(w.Header())
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

type capturedRequestBody struct {
	source io.ReadCloser
	limit  int
	mu     sync.Mutex
	data   []byte
}

func (b *capturedRequestBody) Read(p []byte) (int, error) {
	n, err := b.source.Read(p)
	if n > 0 {
		b.mu.Lock()
		remaining := b.limit - len(b.data)
		if remaining > n {
			remaining = n
		}
		if remaining > 0 {
			b.data = append(b.data, p[:remaining]...)
		}
		b.mu.Unlock()
	}
	return n, err
}

func (b *capturedRequestBody) Close() error {
	return b.source.Close()
}

func (b *capturedRequestBody) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...)
}

func (c CaptureConfig) sourceTool() string {
	if source := strings.TrimSpace(c.SourceTool); source != "" {
		return source
	}
	return "argos-worker"
}

func (c CaptureConfig) recordTunnel(target string, started time.Time) {
	if !c.enabled() {
		return
	}
	err := c.Store.Record(traffic.Exchange{
		SessionID:    c.SessionID,
		Timestamp:    started.UTC(),
		Method:       http.MethodConnect,
		URL:          target,
		Status:       http.StatusOK,
		DurationMs:   time.Since(started).Milliseconds(),
		SourceTool:   c.sourceTool(),
		Target:       target,
		ScopeAllowed: true,
	})
	if err != nil {
		log.Printf("argos scope gateway: cannot capture HTTPS tunnel metadata for %s: %v", target, err)
	}
}

func handleConnect(w http.ResponseWriter, r *http.Request, guard *scope.ScopeGuard, capture CaptureConfig) {
	if guard.HasPathExclusions() {
		writeScopeBlocked(w, "HTTPS CONNECT is disabled when route exclusions cannot be inspected", http.StatusForbidden)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = strings.Trim(r.Host, "[]")
		port = "443"
	}
	if port != "443" {
		writeScopeBlocked(w, "HTTPS CONNECT is limited to port 443", http.StatusForbidden)
		return
	}
	target := "https://" + net.JoinHostPort(host, port) + "/"
	if _, err := guard.ValidateTarget(r.Context(), target); err != nil {
		writeScopeBlocked(w, "target blocked by session scope", http.StatusForbidden)
		return
	}
	started := time.Now()
	upstream, err := guard.DialContext(r.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		writeGatewayError(w, "scoped upstream connection failed", http.StatusForbidden)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		writeGatewayError(w, "CONNECT is unavailable on this server", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	if _, err := fmt.Fprint(buffered, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	if err := buffered.Flush(); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	pipeConnections(r.Context(), client, upstream, buffered.Reader)
	capture.recordTunnel(target, started)
}

func writeScopeBlocked(w http.ResponseWriter, message string, status int) {
	w.Header().Set(gatewayprotocol.ScopeBlockedHeader, "true")
	http.Error(w, message, status)
}

func writeGatewayError(w http.ResponseWriter, message string, status int) {
	w.Header().Set(gatewayprotocol.GatewayErrorHeader, "true")
	http.Error(w, message, status)
}

func validPort(target *url.URL, defaultPort string) bool {
	port := target.Port()
	if port == "" {
		port = defaultPort
	}
	value, err := strconv.Atoi(port)
	return err == nil && value > 0 && value <= 65535
}

func pipeConnections(ctx context.Context, client, upstream net.Conn, clientReader io.Reader) {
	finished := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientReader)
		finished <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		finished <- struct{}{}
	}()
	select {
	case <-ctx.Done():
	case <-finished:
	}
	_ = client.Close()
	_ = upstream.Close()
	<-finished
}

func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}
