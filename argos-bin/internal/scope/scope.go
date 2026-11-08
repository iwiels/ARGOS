package scope

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/env"
)

var (
	// ErrOutOfScope is returned when a target domain or IP is not within the authorized scope.
	ErrOutOfScope = errors.New("SECURITY ENFORCEMENT: Target is out of authorized scope")
	// ErrRateLimitExceeded is returned when the request rate exceeds the configured maximum RPS.
	ErrRateLimitExceeded   = errors.New("SECURITY ENFORCEMENT: Rate limit exceeded")
	ErrWorkerProxyRequired = errors.New("SECURITY ENFORCEMENT: direct network access is disabled; this operation requires the container worker scope gateway")
)

var safeAuditID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// ScopeConfig represents the immutable scope parameters passed from the human operator / database.
type ScopeConfig struct {
	AllowedCIDRs       []string `json:"allowed_cidrs"`
	AllowedDomains     []string `json:"allowed_domains"`
	ExcludedHosts      []string `json:"excluded_hosts"`
	MaxRPS             int      `json:"max_rps"`
	SafeMode           bool     `json:"safe_mode"`
	SessionID          string   `json:"session_id"`
	OperationID        string   `json:"operation_id,omitempty"`
	AuditLogDir        string   `json:"audit_log_dir"`
	CustomHeader       string   `json:"custom_header,omitempty"`
	MaxConcurrency     int      `json:"max_concurrency,omitempty"`
	RequireWorkerProxy bool     `json:"-"`
}

// AuditEntry is an immutable record of a network action.
type AuditEntry struct {
	Timestamp   time.Time      `json:"timestamp"`
	SessionID   string         `json:"session_id"`
	OperationID string         `json:"operation_id,omitempty"`
	Target      string         `json:"target"`
	IP          string         `json:"ip,omitempty"`
	Port        string         `json:"port,omitempty"`
	Action      string         `json:"action"`
	Status      string         `json:"status"`
	PrevHash    string         `json:"prev_hash"`
	Hash        string         `json:"hash"`
	Meta        map[string]any `json:"meta,omitempty"`
	HashVersion int            `json:"hash_version,omitempty"`
}

type AuditVerification struct {
	Entries                int
	LegacyEntries          int
	DisconnectedLegacyRuns int
}

// Resolver resolves a hostname into the IP addresses it currently points to.
//
// It is injectable so the pinning logic can be exercised against controlled
// resolutions (DNS rebinding) without touching the real resolver.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// dnsCacheTTL bounds how long a DNS answer is reused before the host is
// resolved again.
const dnsCacheTTL = 60 * time.Second

const maxAuditEntryBytes = 4 << 20

type dnsEntry struct {
	ips     []net.IP
	expires time.Time
}

// ScopeGuard enforces network boundaries at the socket layer.
type ScopeGuard struct {
	mu                 sync.RWMutex
	allowedCIDRs       []*net.IPNet
	allowedDomains     []string
	excludedHosts      map[string]bool
	excludedDomains    []string
	excludedCIDRs      []*net.IPNet
	excludedPaths      []*regexp.Regexp
	maxRPS             int
	safeMode           bool
	sessionID          string
	operationID        string
	auditLogPath       string
	lastAuditHash      string
	auditErr           error
	customHeader       string
	maxConcurrency     int
	requireWorkerProxy bool
	dialer             *net.Dialer
	resolver           Resolver
	dnsCache           map[string]dnsEntry
	tokens             chan struct{}
	stopLimiter        chan struct{}
}

// LoadFromEnv initializes a ScopeGuard from ARGOS_SCOPE_CONFIG, ARGOS_SCOPE_FILE, or workspace argos.json.
func LoadFromEnv() (*ScopeGuard, error) {
	raw := env.Get("ARGOS_SCOPE_CONFIG")
	if raw == "" {
		if path := env.Get("ARGOS_SCOPE_FILE"); path != "" {
			data, err := os.ReadFile(path)
			if err == nil {
				raw = string(data)
			}
		}
	}
	if raw == "" {
		candidates := []string{
			"argos.json",
			filepath.Join(".argos", "argos.json"),
			"opencode.json",
			filepath.Join(".opencode", "opencode.json"),
		}
		for _, candidate := range candidates {
			if data, err := os.ReadFile(candidate); err == nil {
				var doc map[string]any
				if err := json.Unmarshal(data, &doc); err == nil {
					if scopeRaw, ok := doc["scope"]; ok {
						if scopeBytes, err := json.Marshal(scopeRaw); err == nil {
							raw = string(scopeBytes)
							break
						}
					}
				}
			}
		}
	}

	var cfg ScopeConfig
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return nil, fmt.Errorf("invalid ARGOS_SCOPE_CONFIG: %w", err)
		}
		var alias struct {
			AllowedCIDRs   []string `json:"allowedCIDRs"`
			CIDRs          []string `json:"cidrs"`
			AllowedDomains []string `json:"allowedDomains"`
			Domains        []string `json:"domains"`
			ExcludedHosts  []string `json:"excludedHosts"`
			Excluded       []string `json:"excluded"`
			MaxRPS         int      `json:"maxRPS"`
			SafeMode       *bool    `json:"safeMode"`
			SessionID      string   `json:"sessionId"`
			AuditLogDir    string   `json:"auditLogDir"`
			CustomHeader   string   `json:"customHeader"`
			MaxConcurrency int      `json:"maxConcurrency"`
		}
		if err := json.Unmarshal([]byte(raw), &alias); err == nil {
			if len(cfg.AllowedCIDRs) == 0 {
				if len(alias.AllowedCIDRs) > 0 {
					cfg.AllowedCIDRs = alias.AllowedCIDRs
				} else if len(alias.CIDRs) > 0 {
					cfg.AllowedCIDRs = alias.CIDRs
				}
			}
			if len(cfg.AllowedDomains) == 0 {
				if len(alias.AllowedDomains) > 0 {
					cfg.AllowedDomains = alias.AllowedDomains
				} else if len(alias.Domains) > 0 {
					cfg.AllowedDomains = alias.Domains
				}
			}
			if len(cfg.ExcludedHosts) == 0 {
				if len(alias.ExcludedHosts) > 0 {
					cfg.ExcludedHosts = alias.ExcludedHosts
				} else if len(alias.Excluded) > 0 {
					cfg.ExcludedHosts = alias.Excluded
				}
			}
			if cfg.MaxRPS == 0 && alias.MaxRPS != 0 {
				cfg.MaxRPS = alias.MaxRPS
			}
			if !cfg.SafeMode && alias.SafeMode != nil {
				cfg.SafeMode = *alias.SafeMode
			}
			if cfg.SessionID == "" && alias.SessionID != "" {
				cfg.SessionID = alias.SessionID
			}
			if cfg.AuditLogDir == "" && alias.AuditLogDir != "" {
				cfg.AuditLogDir = alias.AuditLogDir
			}
			if cfg.CustomHeader == "" && alias.CustomHeader != "" {
				cfg.CustomHeader = alias.CustomHeader
			}
			if cfg.MaxConcurrency == 0 && alias.MaxConcurrency != 0 {
				cfg.MaxConcurrency = alias.MaxConcurrency
			}
		}
	}

	cfg.RequireWorkerProxy = env.Get("ARGOS_REQUIRE_CONTAINER_AUDIT") == "1"
	return New(cfg)
}

// New creates and initializes a new ScopeGuard instance.
func New(cfg ScopeConfig) (*ScopeGuard, error) {
	var cidrs []*net.IPNet
	for _, raw := range cfg.AllowedCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			if ip := net.ParseIP(raw); ip != nil {
				if ip.To4() != nil {
					raw += "/32"
				} else {
					raw += "/128"
				}
			}
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		cidrs = append(cidrs, network)
	}

	var domains []string
	for _, d := range cfg.AllowedDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if strings.Contains(d, "://") {
			if u, err := url.Parse(d); err == nil && u.Hostname() != "" {
				d = strings.ToLower(u.Hostname())
			} else {
				parts := strings.Split(d, "://")
				d = strings.Split(parts[len(parts)-1], "/")[0]
			}
		}
		d = strings.TrimSuffix(d, "/")
		if d != "" {
			domains = append(domains, d)
		}
	}

	excluded := make(map[string]bool)
	var excludedDomains []string
	var excludedCIDRs []*net.IPNet
	var excludedPaths []*regexp.Regexp
	for _, e := range cfg.ExcludedHosts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if strings.HasPrefix(e, "/") {
			pattern := "^"
			for _, char := range e {
				if char == '*' {
					pattern += ".*"
				} else {
					pattern += regexp.QuoteMeta(string(char))
				}
			}
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid excluded route %q: %w", e, err)
			}
			excludedPaths = append(excludedPaths, compiled)
			if strings.HasSuffix(e, "/*") {
				root, err := regexp.Compile("^" + regexp.QuoteMeta(strings.TrimSuffix(e, "/*")) + "$")
				if err != nil {
					return nil, fmt.Errorf("invalid excluded route %q: %w", e, err)
				}
				excludedPaths = append(excludedPaths, root)
			}
			continue
		}
		if strings.Contains(e, "://") {
			if parsed, err := url.Parse(e); err == nil && parsed.Hostname() != "" {
				e = parsed.Hostname()
			}
		} else {
			e = hostFromTarget(e)
		}
		if _, network, err := net.ParseCIDR(e); err == nil {
			excludedCIDRs = append(excludedCIDRs, network)
			continue
		}
		if strings.HasPrefix(e, "*.") {
			excludedDomains = append(excludedDomains, e[2:])
			continue
		}
		excluded[e] = true
	}

	maxRPS := cfg.MaxRPS
	if maxRPS <= 0 {
		maxRPS = 20
	}

	sessionID := cfg.SessionID
	if sessionID == "" {
		sessionID = "default"
	}

	if cfg.AuditLogDir == "" && cfg.OperationID != "" {
		auditRoot := strings.TrimSpace(env.Get("ARGOS_AUDIT_LOG_DIR"))
		if auditRoot == "" {
			if configDir, err := os.UserConfigDir(); err == nil {
				auditRoot = filepath.Join(configDir, "argos", "audit")
			}
		}
		if auditRoot == "" {
			return nil, errors.New("cannot determine an audit log directory for this operation")
		}
		operationDigest := sha256.Sum256([]byte(sessionID + "\x00" + cfg.OperationID))
		cfg.AuditLogDir = filepath.Join(auditRoot, hex.EncodeToString(operationDigest[:]), "native")
	}

	var auditPath string
	var lastAuditHash string
	if cfg.AuditLogDir != "" {
		if err := os.MkdirAll(cfg.AuditLogDir, 0700); err != nil {
			return nil, fmt.Errorf("prepare scope audit log directory: %w", err)
		}
		filenameID := sessionID
		if !safeAuditID.MatchString(filenameID) {
			hash := sha256.Sum256([]byte(sessionID))
			filenameID = hex.EncodeToString(hash[:])
		}
		auditPath = filepath.Join(cfg.AuditLogDir, fmt.Sprintf("audit-%s.jsonl", filenameID))
		if info, err := os.Lstat(auditPath); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
			return nil, errors.New("scope audit log path must be a regular file")
		} else if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect scope audit log: %w", err)
		}
		file, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("prepare scope audit log: %w", err)
		}
		if err := file.Chmod(0600); err != nil {
			file.Close()
			return nil, fmt.Errorf("restrict scope audit log permissions: %w", err)
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close prepared scope audit log: %w", err)
		}
		lastAuditHash, err = readVerifiedAuditLog(auditPath)
		if err != nil {
			return nil, fmt.Errorf("verify existing scope audit log: %w", err)
		}
	}

	sg := &ScopeGuard{
		allowedCIDRs:    cidrs,
		allowedDomains:  domains,
		excludedHosts:   excluded,
		excludedDomains: excludedDomains,
		excludedCIDRs:   excludedCIDRs,
		excludedPaths:   excludedPaths,
		maxRPS:          maxRPS,
		safeMode:        cfg.SafeMode,
		sessionID:       sessionID,
		operationID:     cfg.OperationID,
		auditLogPath:    auditPath,
		lastAuditHash:   lastAuditHash,
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		resolver:           net.DefaultResolver,
		dnsCache:           map[string]dnsEntry{},
		tokens:             make(chan struct{}, maxRPS),
		stopLimiter:        make(chan struct{}),
		customHeader:       cfg.CustomHeader,
		maxConcurrency:     cfg.MaxConcurrency,
		requireWorkerProxy: cfg.RequireWorkerProxy,
	}

	// Pre-fill token bucket
	for i := 0; i < maxRPS; i++ {
		sg.tokens <- struct{}{}
	}

	// Start token replenishment
	go sg.runRateLimiter()

	return sg, nil
}

// CustomHeader returns the custom audit HTTP header configured for this engagement.
func (s *ScopeGuard) CustomHeader() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.customHeader
}

// SetResolver replaces the DNS resolver used to validate and pin targets.
func (s *ScopeGuard) SetResolver(r Resolver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resolver = r
}

// resolve returns the current IPs of host, reusing the previous answer for
// dnsCacheTTL.
//
// Invariante de seguridad: la respuesta cacheada es la MISMA que se valida y
// la MISMA que se fija en el socket, así que el pinning sigue siendo
// consistente — un re-resolve posterior no puede desviar la conexión a una IP
// que no se validó.
func (s *ScopeGuard) resolve(ctx context.Context, host string) ([]net.IP, error) {
	s.mu.RLock()
	entry, cached := s.dnsCache[host]
	resolver := s.resolver
	s.mu.RUnlock()

	if cached && time.Now().Before(entry.expires) {
		return entry.ips, nil
	}

	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.dnsCache == nil {
		s.dnsCache = map[string]dnsEntry{}
	}
	s.dnsCache[host] = dnsEntry{ips: ips, expires: time.Now().Add(dnsCacheTTL)}
	s.mu.Unlock()
	return ips, nil
}

// hostFromTarget normalizes a raw target (URL, host:port, IP or domain) into a
// lowercase hostname or IP literal.
func hostFromTarget(rawTarget string) string {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return ""
	}
	host := rawTarget
	if strings.Contains(rawTarget, "://") {
		if u, err := url.Parse(rawTarget); err == nil {
			host = u.Hostname()
		}
	} else if h, _, err := net.SplitHostPort(rawTarget); err == nil {
		host = h
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

// Allowed reports whether the target is inside the authorized scope.
//
// It is the cheap pre-check callers use before opening a socket; the binding
// decision is still taken by the dialer, which pins the validated IP. The
// verdict mirrors ValidateTarget so a pre-check can never be more permissive
// than the enforcement it precedes.
func (s *ScopeGuard) Allowed(target string) bool {
	if s.requireWorkerProxy {
		return false
	}
	if s.isPathExcluded(target) {
		return false
	}
	if !s.hasAllowlist() {
		return false
	}
	host := hostFromTarget(target)
	if host == "" {
		return false
	}

	if s.isHostExcluded(host) {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		return s.IsIPAllowed(ip)
	}

	domainAllowed := s.IsDomainAllowed(host)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := s.resolve(ctx, host)
	if err != nil || len(ips) == 0 {
		return false
	}

	for _, ip := range ips {
		if s.isHostExcluded(ip.String()) {
			return false
		}
		if !s.targetIPAllowed(ip, domainAllowed) {
			return false
		}
	}
	return true
}

// MaxConcurrency returns the maximum concurrent threads configured for this engagement.
func (s *ScopeGuard) MaxConcurrency() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.maxConcurrency <= 0 {
		return 4
	}
	return s.maxConcurrency
}

func (s *ScopeGuard) RequiresWorkerProxy() bool {
	return s != nil && s.requireWorkerProxy
}

func (s *ScopeGuard) runRateLimiter() {
	interval := time.Second / time.Duration(s.maxRPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopLimiter:
			return
		case <-ticker.C:
			select {
			case s.tokens <- struct{}{}:
			default:
			}
		}
	}
}

// Close stops background routines.
func (s *ScopeGuard) Close() {
	select {
	case <-s.stopLimiter:
	default:
		close(s.stopLimiter)
	}
}

// IsIPAllowed checks if an IP is within the authorized CIDRs and not excluded.
func (s *ScopeGuard) IsIPAllowed(ip net.IP) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ipStr := ip.String()
	if s.hostExcludedLocked(strings.ToLower(ipStr)) {
		return false
	}

	for _, cidr := range s.allowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// IsDomainAllowed checks if a domain matches the authorized list.
func (s *ScopeGuard) IsDomainAllowed(domain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	if s.hostExcludedLocked(domain) {
		return false
	}

	for _, pattern := range s.allowedDomains {
		if pattern == domain {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			root := pattern[2:]
			if domain == root || strings.HasSuffix(domain, "."+root) {
				return true
			}
		}
	}

	return false
}

func (s *ScopeGuard) HasPathExclusions() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.excludedPaths) > 0
}

func (s *ScopeGuard) isPathExcluded(rawTarget string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil || parsed.Scheme == "" {
		parsed, err = url.Parse("http://" + strings.TrimLeft(strings.TrimSpace(rawTarget), "/"))
	}
	s.mu.RLock()
	patterns := append([]*regexp.Regexp(nil), s.excludedPaths...)
	s.mu.RUnlock()
	if len(patterns) == 0 {
		return false
	}
	if err != nil {
		return true
	}
	requestPath := parsed.EscapedPath()
	if requestPath == "" {
		requestPath = "/"
	}
	paths, valid := canonicalPathVariants(requestPath)
	if !valid {
		return true
	}
	for _, pattern := range patterns {
		for _, candidate := range paths {
			if pattern.MatchString(candidate) {
				return true
			}
		}
	}
	return false
}

// canonicalPathVariants checks the interpretations commonly produced by URL
// decoders and HTTP servers. It is intentionally conservative: malformed or
// excessively encoded paths fail closed when route exclusions are configured.
func canonicalPathVariants(rawPath string) ([]string, bool) {
	const maxDecodeLayers = 8
	paths := make([]string, 0, maxDecodeLayers)
	seen := make(map[string]struct{}, maxDecodeLayers)
	current := rawPath
	for range maxDecodeLayers {
		if strings.ContainsAny(current, "\x00\r\n") {
			return paths, false
		}
		normalized := strings.ReplaceAll(current, "\\", "/")
		normalized = path.Clean(normalized)
		if normalized == "." {
			normalized = "/"
		}
		if !strings.HasPrefix(normalized, "/") {
			normalized = "/" + normalized
		}
		normalized = strings.ToLower(normalized)
		if _, ok := seen[normalized]; !ok {
			paths = append(paths, normalized)
			seen[normalized] = struct{}{}
		}

		decoded, err := url.PathUnescape(current)
		if err != nil {
			return paths, false
		}
		if decoded == current {
			return paths, true
		}
		current = decoded
	}
	return paths, false
}

func (s *ScopeGuard) isHostExcluded(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hostExcludedLocked(strings.ToLower(strings.Trim(host, "[]")))
}

func (s *ScopeGuard) hostExcludedLocked(host string) bool {
	if s.excludedHosts[host] {
		return true
	}
	for _, domain := range s.excludedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range s.excludedCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (s *ScopeGuard) targetIPAllowed(ip net.IP, domainAllowed bool) bool {
	if ip == nil {
		return false
	}
	ipAllowedByCIDR := s.IsIPAllowed(ip)
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return ipAllowedByCIDR
	}
	return domainAllowed || ipAllowedByCIDR
}

func (s *ScopeGuard) hasAllowlist() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.allowedCIDRs) > 0 || len(s.allowedDomains) > 0
}

// ValidateTarget validates a raw target string (URL, host:port, IP or domain).
func (s *ScopeGuard) ValidateTarget(ctx context.Context, rawTarget string) (string, error) {
	if s.requireWorkerProxy {
		return "", ErrWorkerProxyRequired
	}
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return "", errors.New("empty target")
	}
	if err := s.auditFailure(); err != nil {
		return "", fmt.Errorf("scope audit log failed: %w", err)
	}
	if s.isPathExcluded(rawTarget) {
		if err := s.logAudit(rawTarget, "", "", "VALIDATE", "BLOCKED_EXCLUDED_PATH", nil); err != nil {
			return "", fmt.Errorf("scope audit log failed: %w", err)
		}
		return "", fmt.Errorf("%w: target route %q is explicitly excluded", ErrOutOfScope, rawTarget)
	}
	if !s.hasAllowlist() {
		if err := s.logAudit(rawTarget, "", "", "VALIDATE", "BLOCKED_EMPTY_SCOPE", nil); err != nil {
			return "", fmt.Errorf("scope audit log failed: %w", err)
		}
		return "", fmt.Errorf("%w: no authorized domains or CIDRs are configured", ErrOutOfScope)
	}

	host := hostFromTarget(rawTarget)

	// Check exclusion first
	if s.isHostExcluded(host) {
		if err := s.logAudit(host, "", "", "VALIDATE", "BLOCKED_EXCLUDED", nil); err != nil {
			return "", fmt.Errorf("scope audit log failed: %w", err)
		}
		return "", fmt.Errorf("%w: host %q is in exclusion list", ErrOutOfScope, host)
	}

	// If it is a direct IP
	if ip := net.ParseIP(host); ip != nil {
		if !s.IsIPAllowed(ip) {
			if err := s.logAudit(host, ip.String(), "", "VALIDATE", "BLOCKED_IP", nil); err != nil {
				return "", fmt.Errorf("scope audit log failed: %w", err)
			}
			return "", fmt.Errorf("%w: IP %s not in allowed CIDRs", ErrOutOfScope, ip.String())
		}
		if err := s.logAudit(host, ip.String(), "", "VALIDATE", "ALLOWED_IP", nil); err != nil {
			return "", fmt.Errorf("scope audit log failed: %w", err)
		}
		return ip.String(), nil
	}

	// It is a domain: check domain list
	domainAllowed := s.IsDomainAllowed(host)

	// Resolve DNS once (cached for dnsCacheTTL)
	ips, err := s.resolve(ctx, host)
	if err != nil {
		if auditErr := s.logAudit(host, "", "", "DNS_LOOKUP", "FAILED", map[string]any{"error": err.Error()}); auditErr != nil {
			return "", fmt.Errorf("DNS resolution failed for %s: %v; scope audit log failed: %w", host, err, auditErr)
		}
		return "", fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses resolved for host %s", host)
	}

	// Verify all returned IPs
	var validIP net.IP
	for _, ip := range ips {
		if s.isHostExcluded(ip.String()) {
			if err := s.logAudit(host, ip.String(), "", "DNS_VALIDATION", "BLOCKED_EXCLUDED_IP", nil); err != nil {
				return "", fmt.Errorf("scope audit log failed: %w", err)
			}
			return "", fmt.Errorf("%w: host %s resolved to excluded IP %s", ErrOutOfScope, host, ip.String())
		}
		if s.targetIPAllowed(ip, domainAllowed) {
			if validIP == nil {
				validIP = ip
			}
		} else {
			if err := s.logAudit(host, ip.String(), "", "DNS_VALIDATION", "BLOCKED_UNAUTHORIZED_IP", nil); err != nil {
				return "", fmt.Errorf("scope audit log failed: %w", err)
			}
			return "", fmt.Errorf("%w: host %s resolved to unauthorized IP %s", ErrOutOfScope, host, ip.String())
		}
	}

	if validIP == nil {
		if err := s.logAudit(host, "", "", "VALIDATE", "BLOCKED_NO_MATCH", nil); err != nil {
			return "", fmt.Errorf("scope audit log failed: %w", err)
		}
		return "", fmt.Errorf("%w: neither domain %s nor its resolved IPs are allowed", ErrOutOfScope, host)
	}

	if err := s.logAudit(host, validIP.String(), "", "VALIDATE", "ALLOWED", nil); err != nil {
		return "", fmt.Errorf("scope audit log failed: %w", err)
	}
	return validIP.String(), nil
}

// DialContext connects directly to an IP-pinned socket to prevent TOCTOU / DNS Rebinding.
func (s *ScopeGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.requireWorkerProxy {
		return nil, ErrWorkerProxyRequired
	}
	// Acquire rate-limit token
	select {
	case <-s.tokens:
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if s.safeMode {
			return nil, ErrRateLimitExceeded
		}
		// In normal mode, wait for token
		select {
		case <-s.tokens:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid addr %q: %w", addr, err)
	}

	host = strings.Trim(host, "[]")

	// IP-Pinning: validate target and obtain pinned IP
	pinnedIP, err := s.ValidateTarget(ctx, host)
	if err != nil {
		return nil, err
	}

	pinnedAddr := net.JoinHostPort(pinnedIP, port)
	if err := s.logAudit(host, pinnedIP, port, "DIAL_CONNECT", "CONNECTING", nil); err != nil {
		return nil, fmt.Errorf("scope audit log failed: %w", err)
	}

	conn, err := s.dialer.DialContext(ctx, network, pinnedAddr)
	if err != nil {
		if auditErr := s.logAudit(host, pinnedIP, port, "DIAL_CONNECT", "FAILED", map[string]any{"error": err.Error()}); auditErr != nil {
			return nil, fmt.Errorf("dial failed: %v; scope audit log failed: %w", err, auditErr)
		}
		return nil, err
	}

	if err := s.logAudit(host, pinnedIP, port, "DIAL_CONNECT", "ESTABLISHED", nil); err != nil {
		conn.Close()
		return nil, fmt.Errorf("scope audit log failed: %w", err)
	}
	return conn, nil
}

type scopeCheckingRoundTripper struct {
	guard *ScopeGuard
	next  http.RoundTripper
}

func (t scopeCheckingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.guard == nil || req == nil || req.URL == nil {
		return nil, errors.New("SECURITY ENFORCEMENT: scope guard or request URL is unavailable")
	}
	if t.guard.requireWorkerProxy {
		return nil, ErrWorkerProxyRequired
	}
	if _, err := t.guard.ValidateTarget(req.Context(), req.URL.String()); err != nil {
		return nil, fmt.Errorf("request blocked by session scope: %w", err)
	}
	return t.next.RoundTrip(req)
}

func (t scopeCheckingRoundTripper) CloseIdleConnections() {
	if transport, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
}

// NewHTTPTransport validates request URLs before using ScopeGuard's IP-pinning dialer.
func (s *ScopeGuard) NewHTTPTransport() http.RoundTripper {
	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
	transport.DialContext = s.DialContext
	return scopeCheckingRoundTripper{guard: s, next: transport}
}

// NewHTTPClient returns an *http.Client protected by ScopeGuard boundaries.
func (s *ScopeGuard) NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{
		Transport: s.NewHTTPTransport(),
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}
}

// Client returns the canonical HTTP client for this engagement: every request
// goes through the IP-pinning dialer, the rate limiter and the chained audit
// log. Callers must not build their own *http.Client against a target.
func (s *ScopeGuard) Client() *http.Client {
	return s.NewHTTPClient(30 * time.Second)
}

// LogAudit records an operational decision in the chained audit log.
//
// It exists so that safety decisions which are not network actions — the
// circuit breaker aborting a scan, the scope guard degrading a session —
// still land in the same hash-chained record as the requests themselves.
// Without it, the chain would show "we made 40 requests" but not "we stopped
// because the target was degraded".
func (s *ScopeGuard) LogAudit(target, ip, port, action, status string, meta map[string]any) error {
	return s.logAudit(target, ip, port, action, status, meta)
}

func (s *ScopeGuard) auditFailure() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auditErr
}

func auditEntryHash(entry AuditEntry) (string, error) {
	entry.Hash = ""
	data, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func legacyAuditEntryHash(entry AuditEntry) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s", entry.PrevHash, entry.Timestamp.Format(time.RFC3339Nano), entry.SessionID, entry.OperationID, entry.Target, entry.IP, entry.Action, entry.Status)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func VerifyAuditLog(path string) error {
	_, err := readVerifiedAuditLog(path)
	return err
}

func VerifyAuditLogDetailed(path string) (AuditVerification, error) {
	var verification AuditVerification
	_, err := verifyAuditLog(path, &verification)
	return verification, err
}

func readVerifiedAuditLog(path string) (string, error) {
	return verifyAuditLog(path, nil)
}

func verifyAuditLog(path string, verification *AuditVerification) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open scope audit log: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxAuditEntryBytes)
	previousHash := ""
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		var entry AuditEntry
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&entry); err != nil {
			return "", fmt.Errorf("decode scope audit log line %d: %w", lineNumber, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return "", fmt.Errorf("scope audit log line %d contains trailing data", lineNumber)
		}
		if verification != nil {
			verification.Entries++
			if entry.HashVersion == 0 {
				verification.LegacyEntries++
			}
		}
		if entry.PrevHash != previousHash {
			if entry.HashVersion != 0 || entry.PrevHash != "" {
				return "", fmt.Errorf("scope audit log line %d breaks the previous-hash chain", lineNumber)
			}
			if verification != nil {
				verification.DisconnectedLegacyRuns++
			}
		}
		var expectedHash string
		switch entry.HashVersion {
		case 0:
			expectedHash = legacyAuditEntryHash(entry)
		case 1:
			expectedHash, err = auditEntryHash(entry)
			if err != nil {
				return "", fmt.Errorf("hash scope audit log line %d: %w", lineNumber, err)
			}
		default:
			return "", fmt.Errorf("scope audit log line %d uses unsupported hash version %d", lineNumber, entry.HashVersion)
		}
		if entry.Hash == "" || entry.Hash != expectedHash {
			return "", fmt.Errorf("scope audit log line %d has an invalid hash", lineNumber)
		}
		previousHash = entry.Hash
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read scope audit log: %w", err)
	}
	return previousHash, nil
}

func (s *ScopeGuard) logAudit(target, ip, port, action, status string, meta map[string]any) error {
	if s.auditLogPath == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auditErr != nil {
		return s.auditErr
	}

	entry := AuditEntry{
		Timestamp:   time.Now().UTC(),
		SessionID:   s.sessionID,
		OperationID: s.operationID,
		Target:      target,
		IP:          ip,
		Port:        port,
		Action:      action,
		Status:      status,
		PrevHash:    s.lastAuditHash,
		Meta:        meta,
		HashVersion: 1,
	}
	hash, err := auditEntryHash(entry)
	if err != nil {
		s.auditErr = err
		return err
	}
	entry.Hash = hash
	data, err := json.Marshal(entry)
	if err != nil {
		s.auditErr = err
		return err
	}
	if len(data) > maxAuditEntryBytes {
		err := fmt.Errorf("scope audit entry exceeds %d bytes", maxAuditEntryBytes)
		s.auditErr = err
		return err
	}
	line := append(data, '\n')

	f, err := os.OpenFile(s.auditLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		s.auditErr = err
		return err
	}
	n, writeErr := f.Write(line)
	closeErr := f.Close()
	if writeErr == nil && n != len(line) {
		writeErr = errors.New("short write to scope audit log")
	}
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		s.auditErr = writeErr
		return writeErr
	}
	s.lastAuditHash = hash
	return nil
}
