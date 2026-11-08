// Package oob implements a self-hosted out-of-band (OAST) interaction
// collector.
//
// The collector exists so Argos never has to disclose the identity of the
// audited target to a third party. Public OAST providers (oast.fun,
// interact.sh, ...) observe every callback the engine emits, which on a real
// engagement is a confidentiality breach: the provider learns which target is
// being tested and when. The default collector is therefore a listener this
// process owns; a public provider is only reachable through an explicit
// opt-in (ARGOS_OAST_EXTERNAL=1) and operators with their own infrastructure
// point ARGOS_OAST_DOMAIN at it.
package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Event is a single out-of-band interaction captured by the collector.
type Event struct {
	Token      string
	Timestamp  time.Time
	Protocol   string
	Method     string
	URL        string
	Headers    map[string][]string
	Body       []byte
	RemoteAddr string
}

const (
	// DefaultBind is the address the collector binds when the caller does not
	// ask for a specific one. Loopback keeps the callbacks private to the
	// host running the audit.
	DefaultBind = "127.0.0.1:0"

	// maxBodyBytes caps how much of a callback body is kept in memory.
	maxBodyBytes = 1 << 20

	// shutdownTimeout bounds how long Stop waits for in-flight callbacks.
	shutdownTimeout = 2 * time.Second
)

// Server is a local HTTP collector for out-of-band callbacks.
//
// Callbacks are correlated by token, never by URL shape: the injected
// reference is "<token>.<domain>" and the collector accepts the token either
// as the leftmost label of the Host header or as a path segment, so the
// correlation survives a target that rewrites, truncates or url-encodes the
// path around it.
type Server struct {
	mu       sync.Mutex
	listener net.Listener
	http     *http.Server
	domain   string
	port     int
	tokens   map[string]struct{}
	events   map[string][]Event
	stopped  bool
}

// NewServer starts a collector bound to bind.
//
// An empty bind means DefaultBind (loopback, ephemeral port). The listener is
// owned by the returned server: Stop closes it and releases the port.
func NewServer(bind string) (*Server, error) {
	if strings.TrimSpace(bind) == "" {
		bind = DefaultBind
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, fmt.Errorf("oob: listen on %s: %w", bind, err)
	}
	s := &Server{
		listener: ln,
		tokens:   map[string]struct{}{},
		events:   map[string][]Event{},
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		s.port = tcp.Port
	}
	s.domain = defaultDomain(ln.Addr())
	s.http = &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 10 * time.Second,
	}
	srv := s.http
	go func() {
		_ = srv.Serve(ln)
	}()
	return s, nil
}

// Domain returns the wildcard domain of the collector, e.g.
// "a1b2c3d4.localhost". The random label makes the domain unique per
// process; the correlation is carried by the token, not by the domain.
func (s *Server) Domain() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.domain
}

// Port returns the TCP port the collector listens on.
func (s *Server) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

// Addr returns the "host:port" the collector listens on.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listener.Addr().String()
}

// Register declares a correlation token owned by this collector. Callbacks
// carrying an unknown token are ignored, so unrelated traffic hitting the
// port is never recorded.
func (s *Server) Register(token string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokens == nil {
		s.tokens = map[string]struct{}{}
	}
	s.tokens[token] = struct{}{}
}

// Unregister drops a token and any event still buffered for it.
func (s *Server) Unregister(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	delete(s.events, token)
}

// Has reports whether the token is registered on this collector.
func (s *Server) Has(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tokens[token]
	return ok
}

// ActiveTokens returns how many tokens are still registered.
func (s *Server) ActiveTokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

// Poll returns the events captured for token since the previous poll and
// removes them from the buffer.
//
// Poll is destructive on purpose: the tool's poll/stop cycle must not deliver
// the same callback twice, and an unbounded buffer would grow for the whole
// life of the MCP process.
func (s *Server) Poll(token string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := s.events[token]
	delete(s.events, token)
	if len(events) == 0 {
		return nil
	}
	return events
}

// Stop closes the listener and releases the port. It is idempotent.
func (s *Server) Stop() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	srv := s.http
	s.http = nil
	ln := s.listener
	s.events = map[string][]Event{}
	s.tokens = map[string]struct{}{}
	s.mu.Unlock()

	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			// Shutdown gives up on the in-flight requests; Close releases the
			// listener unconditionally so the port never stays bound.
			_ = srv.Close()
		}
	}
	// The raw listener is closed too: http.Server registers it asynchronously,
	// so a Stop issued right after NewServer would otherwise leave the port
	// bound.
	if ln != nil {
		_ = ln.Close()
	}
	return nil
}

// handle records a callback. Requests that do not carry a registered token
// are not callbacks: they are answered with 404 and never logged, so a
// browser hitting /favicon.ico does not pollute the audit trail.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	// OAST callbacks are cross-origin by nature (the target, not the
	// auditor's page, performs the request).
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	token := s.matchToken(r)
	if token == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil && err != io.EOF {
		body = nil
	}
	event := Event{
		Token:      token,
		Timestamp:  time.Now().UTC(),
		Protocol:   "http",
		Method:     r.Method,
		URL:        r.URL.String(),
		Headers:    r.Header.Clone(),
		Body:       body,
		RemoteAddr: r.RemoteAddr,
	}
	s.mu.Lock()
	if s.events == nil {
		s.events = map[string][]Event{}
	}
	s.events[token] = append(s.events[token], event)
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// matchToken returns the registered token carried by the request, if any.
func (s *Server) matchToken(r *http.Request) string {
	candidates := tokenCandidates(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, candidate := range candidates {
		if _, ok := s.tokens[candidate]; ok {
			return candidate
		}
	}
	return ""
}

// tokenCandidates extracts the possible correlation tokens from the Host
// header and from the path.
func tokenCandidates(r *http.Request) []string {
	var out []string
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	for _, label := range strings.Split(host, ".") {
		if label != "" {
			out = append(out, label)
		}
	}
	for _, segment := range strings.Split(r.URL.Path, "/") {
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

// defaultDomain builds the wildcard domain for the given bind address.
// Loopback (and unspecified) binds get the ".localhost" suffix, which
// resolves to the loopback interface on most resolvers; a routable bind
// keeps its own host as the suffix.
func defaultDomain(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return randomLabel() + ".localhost"
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return randomLabel() + ".localhost"
		}
	}
	return randomLabel() + "." + host
}

// randomLabel returns a short random label for the collector domain.
func randomLabel() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}
