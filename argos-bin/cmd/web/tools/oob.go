package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	argosenv "github.com/iwiels/argos-auditor/argos-bin/internal/env"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/oob"
)

// oastMode is the source of the out-of-band callbacks.
type oastMode string

const (
	// oastModeLocal uses the collector this process owns: no callback leaves
	// the machine running the audit.
	oastModeLocal oastMode = "local"
	// oastModeSelfHosted uses the OAST domain the operator configured. The
	// callbacks still leave the host, but they land on infrastructure the
	// organization controls.
	oastModeSelfHosted oastMode = "self-hosted"
	// oastModeExternal uses a third-party OAST provider. The provider observes
	// every callback, so it requires an explicit opt-in.
	oastModeExternal oastMode = "external"
)

// oastConfig is the resolved OAST configuration of one session.
type oastConfig struct {
	Mode         oastMode
	Domain       string
	External     bool
	DNSAvailable bool
	DNSReason    string
	Notice       string
	Bind         string
}

// resolveOAST reads the OAST configuration from the environment.
//
// The default is the local collector: a public OAST provider learns which
// target is being tested and when, which is a confidentiality breach on a
// real engagement, so a third party is only reachable through an explicit
// opt-in.
func resolveOAST(toolsDir string) (oastConfig, error) {
	cfg := oastConfig{Mode: oastModeLocal, Bind: argosenv.OASTBind()}
	if cfg.Bind == "" {
		cfg.Bind = oob.DefaultBind
	}
	domain := argosenv.OASTDomain()
	external := argosenv.OASTExternal()

	switch {
	case external && domain == "":
		return cfg, fmt.Errorf(
			"%s=1 requires %s to name the OAST server to use",
			argosenv.OASTExternalEnv, argosenv.OASTDomainEnv,
		)
	case domain == "":
		cfg.DNSAvailable = false
		cfg.DNSReason = "the built-in collector speaks HTTP only: DNS callbacks are " +
			"unavailable, use HTTP callbacks only"
		if dns := oob.DetectDNS(toolsDir); dns.Server != "" {
			cfg.DNSReason += " (an interactsh server is installed at " + dns.Server +
				"; set ARGOS_OAST_DOMAIN to use it)"
		}
		return cfg, nil
	case external:
		cfg.Mode = oastModeExternal
		cfg.Domain = domain
		cfg.External = true
		cfg.DNSAvailable = true
		cfg.DNSReason = "the configured OAST server answers the DNS queries of the " +
			"interactsh protocol; no DNS event is reported if it does not"
		cfg.Notice = "external OAST provider enabled: every callback is sent to " + domain +
			", a third party that observes which target is being tested and when"
		return cfg, nil
	default:
		cfg.Mode = oastModeSelfHosted
		cfg.Domain = domain
		dns := oob.DetectDNS(toolsDir)
		cfg.DNSAvailable = dns.Available
		cfg.DNSReason = dns.Reason
		cfg.Notice = "using the OAST domain configured by the operator (" + domain +
			"): the callbacks leave this host but never reach a third-party provider; " +
			"the domain must resolve to the host running the collector (bind: " + cfg.Bind + ")"
		return cfg, nil
	}
}

type mutexWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (w *mutexWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

type oobSession struct {
	cmd      *exec.Cmd
	mu       sync.Mutex
	buf      strings.Builder
	offset   int
	started  time.Time
	registry *OOBRegistry
	token    string
}

// newLines returns the lines produced since the last read and advances the offset.
func (s *oobSession) newLines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw := s.buf.String()
	if s.offset > len(raw) {
		s.offset = len(raw)
	}
	ls := lines(raw[s.offset:])
	s.offset = len(raw)
	if len(ls) > 200 {
		ls = ls[len(ls)-200:]
	}
	return ls
}

func (s *oobSession) tailLines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ls := lines(s.buf.String())
	if len(ls) > 200 {
		ls = ls[len(ls)-200:]
	}
	return ls
}

// kill terminates the interactsh-client process bound to the session.
func (s *oobSession) kill() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
}

type OOBRegistry struct {
	mu   sync.Mutex
	live map[string]*oobSession
}

func NewOOBRegistry() *OOBRegistry {
	return &OOBRegistry{live: map[string]*oobSession{}}
}

// start launches interactsh-client bound to a correlation token.
//
// A domain makes the client register against the OAST server the operator
// configured instead of the public one.
func (r *OOBRegistry) start(ctx context.Context, bin, domain, token string) (*oobSession, error) {
	r.mu.Lock()
	if s, ok := r.live[token]; ok {
		r.mu.Unlock()
		return s, nil
	}
	args := []string{"-n", token, "-json"}
	if domain != "" {
		args = append([]string{"-server", domain}, args...)
	}
	cmd := exec.Command(bin, args...)
	s := &oobSession{cmd: cmd, started: time.Now(), registry: r, token: token}
	mw := &mutexWriter{mu: &s.mu, b: &s.buf}
	cmd.Stdout = mw
	cmd.Stderr = mw
	if err := cmd.Start(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	r.live[token] = s
	r.mu.Unlock()

	// reaper: wait for the process and drop the session when it exits
	go func() {
		cmd.Wait()
		r.mu.Lock()
		if r.live[token] == s {
			delete(r.live, token)
		}
		r.mu.Unlock()
	}()
	return s, nil
}

func (r *OOBRegistry) get(token string) *oobSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.live[token]
}

func (r *OOBRegistry) stop(token string) *oobSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.live[token]
	if s != nil {
		delete(r.live, token)
	}
	return s
}

func randomToken() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// oobServerMu guards the shared collector pointer: the MCP server dispatches
// tool calls concurrently.
var oobServerMu sync.Mutex

// oobCollector returns the shared local collector, starting it on first use.
func oobCollector(env *Env, bind string) (*oob.Server, error) {
	oobServerMu.Lock()
	defer oobServerMu.Unlock()
	if env.OOBServer != nil {
		return env.OOBServer, nil
	}
	srv, err := oob.NewServer(bind)
	if err != nil {
		return nil, err
	}
	env.OOBServer = srv
	return srv, nil
}

// oobCurrentCollector returns the shared collector when it is running.
func oobCurrentCollector(env *Env) *oob.Server {
	oobServerMu.Lock()
	defer oobServerMu.Unlock()
	return env.OOBServer
}

// oobReleaseCollector stops the shared collector and detaches it from env.
func oobReleaseCollector(env *Env, srv *oob.Server) error {
	oobServerMu.Lock()
	defer oobServerMu.Unlock()
	if env.OOBServer == srv {
		env.OOBServer = nil
	}
	return srv.Stop()
}

// StopOOBCollector releases the local collector. It is the shutdown hook of
// the process that owns the Env.
func StopOOBCollector(env *Env) {
	if env == nil {
		return
	}
	oobServerMu.Lock()
	srv := env.OOBServer
	env.OOBServer = nil
	oobServerMu.Unlock()
	if srv != nil {
		_ = srv.Stop()
	}
}

// oobInteractshStart launches interactsh-client against the configured OAST
// server. It is a package-level indirection so the tool-level tests can
// exercise the external mode without a real interactsh-client binary.
var oobInteractshStart = startInteractshSession

func startInteractshSession(ctx context.Context, env *Env, bin, domain, token string, wait int) (*oobSession, error) {
	session, err := env.OOB.start(ctx, bin, domain, token)
	if err != nil {
		return nil, err
	}
	if wait > 0 {
		time.Sleep(time.Duration(wait) * time.Second)
	}
	return session, nil
}

func RegisterOOB(s *mcp.Server, env *Env) {
	s.RegisterTool(
		mcp.ToolDefinition{
			Name: "web.oob",
			Description: "Out-of-band interaction testing with a self-hosted collector. " +
				"Actions: start (get correlation id + oast domain), poll (collect interactions), stop (shutdown). " +
				"The default collector is local: no callback leaves this host. A third-party OAST provider " +
				"requires the explicit opt-in ARGOS_OAST_EXTERNAL=1.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"action":       {Type: "string", Description: "start, poll or stop"},
					"correlation":  {Type: "string", Description: "Correlation id returned by start (for poll/stop)"},
					"wait_seconds": {Type: "integer", Description: "For start: seconds to wait for the OAST client to register with its server (default 5, ignored by the local collector)"},
					"target":       {Type: "string", Description: "Optional: target the blind vector belongs to, validated against the engagement scope"},
				},
				Required: []string{"action"},
			},
			Annotations: &mcp.ToolAnnotations{OpenWorldHint: mcp.BoolPtr(true)},
		},
		func(ctx mcp.ToolContext, params json.RawMessage) (interface{}, *mcp.ErrorObj) {
			var input struct {
				Action      string `json:"action"`
				Correlation string `json:"correlation"`
				WaitSeconds int    `json:"wait_seconds"`
				Target      string `json:"target"`
			}
			if err := json.Unmarshal(params, &input); err != nil {
				return nil, invalidParams(err)
			}
			if input.Target != "" {
				if _, errObj := validateWebTargetWithToolContext(env, ctx, input.Target); errObj != nil {
					return nil, errObj
				}
			}
			switch input.Action {
			case "start":
				callCtx := ctx.Ctx
				if callCtx == nil {
					callCtx = context.Background()
				}
				return oobStart(callCtx, env, input.WaitSeconds)
			case "poll":
				return oobPoll(env, input.Correlation)
			case "stop":
				return oobStop(env, input.Correlation)
			default:
				return nil, &mcp.ErrorObj{Code: -32602, Message: "action must be start, poll or stop"}
			}
		},
	)
}

func oobStart(ctx context.Context, env *Env, wait int) (interface{}, *mcp.ErrorObj) {
	toolsDir := ""
	if env != nil && env.Downloader != nil {
		toolsDir = env.Downloader.Dir
	}
	cfg, err := resolveOAST(toolsDir)
	if err != nil {
		return nil, &mcp.ErrorObj{Code: -32602, Message: err.Error()}
	}
	if cfg.Mode != oastModeLocal {
		return nil, &mcp.ErrorObj{Code: -32002, Message: "OAST is unavailable: remote collectors require the isolated scoped OAST gateway"}
	}
	if wait <= 0 {
		wait = 5
	}
	if wait > 30 {
		wait = 30
	}
	token := randomToken()

	switch cfg.Mode {
	case oastModeExternal:
		bin, _, errObj := env.Binary(ctx, "interactsh-client")
		if errObj != nil {
			return nil, &mcp.ErrorObj{Code: -32603, Message: "cannot start the external OAST client: " + errObj.Message}
		}
		if _, err := oobInteractshStart(ctx, env, bin, cfg.Domain, token, wait); err != nil {
			return nil, &mcp.ErrorObj{Code: -32603, Message: "cannot start the external OAST client: " + err.Error()}
		}
		res := oobStartResult(cfg, token, cfg.Domain, 0, "https://<correlation>."+cfg.Domain+"/")
		res["collector"] = "interactsh-client"
		return res, nil
	case oastModeSelfHosted:
		// The client is used only when it is already installed: pulling a
		// binary that talks to an OAST server is an operator decision.
		if bin, ok := oob.Locate("interactsh-client", toolsDir); ok {
			if _, err := oobInteractshStart(ctx, env, bin, cfg.Domain, token, wait); err != nil {
				return nil, &mcp.ErrorObj{Code: -32603, Message: "cannot start interactsh-client: " + err.Error()}
			}
			res := oobStartResult(cfg, token, cfg.Domain, 0, "https://<correlation>."+cfg.Domain+"/")
			res["collector"] = "interactsh-client"
			return res, nil
		}
	}

	// The built-in collector: the only one that keeps every callback inside
	// the host running the audit.
	srv, err := oobCollector(env, cfg.Bind)
	if err != nil {
		return nil, &mcp.ErrorObj{Code: -32603, Message: "cannot start the local OOB collector: " + err.Error()}
	}
	srv.Register(token)
	domain := cfg.Domain
	port := 0
	template := "http://<correlation>." + domain + "/"
	if domain == "" {
		domain = srv.Domain()
		port = srv.Port()
		template = "http://<correlation>." + domain + ":" + strconv.Itoa(port) + "/"
	}
	res := oobStartResult(cfg, token, domain, port, template)
	res["collector"] = "argos-builtin"
	return res, nil
}

// oobStartResult renders the payload the agent reads after a start.
func oobStartResult(cfg oastConfig, token, domain string, port int, template string) map[string]interface{} {
	res := map[string]interface{}{
		"tool":              "web.oob",
		"action":            "start",
		"status":            "started",
		"correlation":       token,
		"oast_domain":       domain,
		"oast_mode":         string(cfg.Mode),
		"dns_oast":          cfg.DNSAvailable,
		"external_oast":     cfg.External,
		"oast_url_template": template,
		"usage": "Inject " + template + " (replace <correlation> with " + token +
			") into the blind vector of the target, then call web.oob action=poll with correlation=" + token,
	}
	if port > 0 {
		res["oast_port"] = port
	}
	if cfg.DNSReason != "" {
		res["dns_oast_reason"] = cfg.DNSReason
	}
	if cfg.Notice != "" {
		res["notice"] = cfg.Notice
	}
	return res
}

func oobPoll(env *Env, token string) (interface{}, *mcp.ErrorObj) {
	if token == "" {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "correlation is required for poll"}
	}
	if srv := oobCurrentCollector(env); srv != nil && srv.Has(token) {
		return map[string]interface{}{
			"tool":         "web.oob",
			"action":       "poll",
			"status":       "ok",
			"correlation":  token,
			"interactions": oobEventsToMaps(srv.Poll(token)),
		}, nil
	}
	if env.OOB != nil {
		if session := env.OOB.get(token); session != nil {
			return map[string]interface{}{
				"tool":         "web.oob",
				"action":       "poll",
				"status":       "ok",
				"correlation":  token,
				"interactions": interactshInteractions(session.newLines()),
			}, nil
		}
	}
	return nil, &mcp.ErrorObj{Code: -32602, Message: "no active session for correlation " + token + "; call start first"}
}

func oobStop(env *Env, token string) (interface{}, *mcp.ErrorObj) {
	if token == "" {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "correlation is required for stop"}
	}
	interactions := []map[string]interface{}{}
	found := false

	if srv := oobCurrentCollector(env); srv != nil && srv.Has(token) {
		found = true
		interactions = oobEventsToMaps(srv.Poll(token))
		srv.Unregister(token)
		// The listener is released once the last session is closed.
		if srv.ActiveTokens() == 0 {
			_ = oobReleaseCollector(env, srv)
		}
	}
	if env.OOB != nil {
		if session := env.OOB.stop(token); session != nil {
			found = true
			interactions = append(interactions, interactshInteractions(session.tailLines())...)
			session.kill()
		}
	}
	if !found {
		return nil, &mcp.ErrorObj{Code: -32602, Message: "no active session for correlation " + token}
	}
	return map[string]interface{}{
		"tool":         "web.oob",
		"action":       "stop",
		"status":       "stopped",
		"correlation":  token,
		"interactions": interactions,
	}, nil
}

// oobEventsToMaps renders the collector events as the JSON payload the agent
// reads.
func oobEventsToMaps(events []oob.Event) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(events))
	for _, event := range events {
		headers := map[string][]string{}
		for name, values := range event.Headers {
			headers[name] = values
		}
		body := string(event.Body)
		if len(body) > 4096 {
			body = body[:4096] + "...[truncated]"
		}
		out = append(out, map[string]interface{}{
			"protocol":    event.Protocol,
			"method":      event.Method,
			"url":         event.URL,
			"timestamp":   event.Timestamp.Format(time.RFC3339Nano),
			"remote_addr": event.RemoteAddr,
			"headers":     headers,
			"body":        body,
		})
	}
	return out
}

// interactshInteractions renders the raw interactsh-client lines, keeping the
// parsed JSON when the client emitted a JSON record.
func interactshInteractions(raw []string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(raw))
	for _, line := range raw {
		entry := map[string]interface{}{"raw": line}
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(line), &parsed); err == nil {
			for key, value := range parsed {
				entry[key] = value
			}
			entry["raw"] = line
		}
		out = append(out, entry)
	}
	return out
}
