package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/iwiels/argos-auditor/argos-bin/internal/authvault"
	argosenv "github.com/iwiels/argos-auditor/argos-bin/internal/env"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/oob"
	"github.com/iwiels/argos-auditor/argos-bin/internal/paths"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
	"github.com/iwiels/argos-auditor/argos-bin/internal/workerprobe"
)

const (
	// CampaignEnv es la etiqueta legible de campaña (p. ej.
	// "example-target-2026-08-14"). No identifica una sesión: el store de
	// memoria es compartido entre campañas.
	CampaignEnv = "ARGOS_CAMPAIGN"
	// DefaultAgent identifica a la tool que produjo el hallazgo cuando el
	// proceso no dice lo contrario.
	DefaultAgent = "argos-web"
	// DefaultCampaign es la etiqueta de campaña usada cuando el proceso no
	// declara una.
	DefaultCampaign = "argos-web"
)

// Env holds the shared state for all web tools: the on-demand binary
// downloader, the OOB session registry, the scope boundary guard, and the effective tool specs
// (built-in defaults merged with argos.jsonc webTools overrides).
type Env struct {
	Downloader *Downloader
	OOB        *OOBRegistry
	// OOBServer is the local out-of-band collector. It listens on loopback by
	// default, so no callback of the engagement reaches a third party.
	OOBServer *oob.Server
	Scope     *scope.ScopeGuard
	// HTTP is the only client the tools may use against a target: it carries
	// the scope guard's IP-pinning dialer, rate limiter and chained audit log.
	HTTP  *http.Client
	specs []BinarySpec
	// MemoryDir es el store de memoria compartido (<memoryDir>/findings) donde
	// el backend reconcilia los hallazgos que emiten las tools.
	MemoryDir string
	// SessionID is only used by direct persistence helpers. MCP handlers use
	// the trusted per-call value from ToolContext.
	SessionID              string
	OperationID            string
	BrowserWorkerAvailable bool
	RequireWorkerProxy     bool
	WorkerScopeGateway     bool
	AuthVault              *authvault.Client
	// Campaign es la etiqueta legible de campaña que se escribe en el campo
	// `session` de cada hallazgo. Es legible, no única.
	Campaign string
	// Agent identifica la tool que produjo el hallazgo ("argos-web" por
	// defecto).
	Agent string
}

func NewEnv(toolsDir string) *Env {
	sg, scopeErr := scope.LoadFromEnv()
	if scopeErr != nil {
		log.Printf("scope configuration could not be loaded; scans will fail closed: %v", scopeErr)
	}
	if sg == nil {
		sg, _ = scope.New(scope.ScopeConfig{RequireWorkerProxy: argosenv.Get("ARGOS_REQUIRE_CONTAINER_AUDIT") == "1"})
	}
	defaultScopeGuard = sg
	bind := argosenv.OASTBind()
	if bind == "" {
		bind = oob.DefaultBind
	}
	collector, err := oob.NewServer(bind)
	if err != nil {
		// The collector is optional: web.oob reports the failure when the
		// session needs it.
		log.Printf("cannot start the local OOB collector: %v", err)
	}
	memoryDir := ""
	if home, err := os.UserHomeDir(); err == nil {
		memoryDir = paths.ResolveMemoryDir(home)
	}
	env := &Env{
		Downloader:             NewDownloader(toolsDir),
		OOB:                    NewOOBRegistry(),
		OOBServer:              collector,
		Scope:                  sg,
		HTTP:                   sg.Client(),
		specs:                  loadWebToolsConfig(),
		BrowserWorkerAvailable: argosenv.Get("ARGOS_BROWSER_WORKER_AVAILABLE") == "1",
		RequireWorkerProxy:     argosenv.Get("ARGOS_REQUIRE_CONTAINER_AUDIT") == "1",
		AuthVault:              authvault.FromEnv(),
		MemoryDir:              memoryDir,
		Campaign:               campaignLabel(),
		Agent:                  DefaultAgent,
	}
	// Los eventos del circuit-breaker son decisiones de seguridad del
	// engagement: van a la misma cadena encadenada que las peticiones, para
	// que el auditor vea tanto lo que se hizo como por qué se detuvo.
	SetBreakerAuditor(auditBreakerToChain)
	return env
}

// campaignLabel returns the campaign label of this process.
func campaignLabel() string {
	if label := strings.TrimSpace(argosenv.Get(CampaignEnv)); label != "" {
		return label
	}
	return DefaultCampaign
}

// Client returns the scope-bound HTTP client for this engagement.
//
// Invariante de seguridad: todo request contra un target sale de acá. Un
// http.Client propio se saltaría el IP-pinning, el rate limit y el audit log
// encadenado.
func (env *Env) Client() *http.Client {
	if env.HTTP != nil {
		return env.HTTP
	}
	if env.Scope != nil {
		return env.Scope.Client()
	}
	sg, _ := scope.New(scope.ScopeConfig{RequireWorkerProxy: env.RequireWorkerProxy})
	return sg.Client()
}

func scopedToolEnvironment(env *Env, call mcp.ToolContext) (*Env, func(), *mcp.ErrorObj) {
	config, ok := scopeConfigFromToolContext(call)
	if !ok {
		return nil, func() {}, &mcp.ErrorObj{Code: -32602, Message: "SECURITY ENFORCEMENT: controller session, operation, and scope snapshot are required; scan blocked"}
	}
	config.RequireWorkerProxy = env != nil && (env.RequireWorkerProxy || (env.Scope != nil && env.Scope.RequiresWorkerProxy()))
	guard, err := scope.New(config)
	if err != nil {
		return nil, func() {}, &mcp.ErrorObj{Code: -32602, Message: "SECURITY ENFORCEMENT: invalid controller scope; scan blocked: " + err.Error()}
	}
	if env == nil {
		return nil, guard.Close, &mcp.ErrorObj{Code: -32603, Message: "SECURITY ENFORCEMENT: scanner environment is unavailable"}
	}
	perCall := *env
	perCall.Scope = guard
	if !env.WorkerScopeGateway {
		perCall.HTTP = guard.Client()
	}
	perCall.SessionID = call.SessionID
	perCall.OperationID = call.OperationID
	return &perCall, guard.Close, nil
}

// Spec returns the effective spec for a tool name.
func (env *Env) Spec(name string) *BinarySpec {
	for i := range env.specs {
		if env.specs[i].Name == name {
			return &env.specs[i]
		}
	}
	return nil
}

// Binary returns the path to a tool binary, downloading it on first use.
func (env *Env) Binary(ctx context.Context, name string) (string, bool, *mcp.ErrorObj) {
	spec := env.Spec(name)
	if spec == nil {
		return "", false, &mcp.ErrorObj{Code: -32603, Message: "unknown tool: " + name}
	}
	path, installed, err := env.Downloader.Ensure(ctx, spec)
	if err != nil {
		return "", false, &mcp.ErrorObj{Code: -32603, Message: fmt.Sprintf("%s: %v", name, err)}
	}
	return path, installed, nil
}

func RegisterAll(s *mcp.Server, env *Env) {
	if env != nil && env.BrowserWorkerAvailable {
		RegisterBrowser(s, env)
	}
	RegisterScan(s, env)
	RegisterSqli(s, env)
	RegisterFuzz(s, env)
	RegisterParams(s, env)
	RegisterCrawl(s, env)
	RegisterProbe(s, env)
	RegisterTech(s, env)
	RegisterSubdomains(s, env)
	RegisterUrls(s, env)
	RegisterXSS(s, env)
	RegisterOOB(s, env)
	RegisterWAF(s, env)
	RegisterApi(s, env)
	RegisterTls(s, env)
	RegisterPorts(s, env)
	RegisterCodeScan(s, env)
	RegisterCMS(s, env)
	RegisterArtifact(s, env)
	RegisterWordlists(s, env)
	RegisterVectors(s, env)
	RegisterTraffic(s, env)
	RegisterTemplatePacks(s, env)

	// Red de seguridad: ninguna tool debe poder emitir un hallazgo que no
	// llegue al store de memoria. Las tools que ya persisten sus findings
	// lo hacen ellas mismas (y lo declaran en la respuesta), así que aquí
	// sólo se cubre el resto.
	for _, def := range s.ToolDefinitions() {
		handler := s.GetToolHandler(def.Name)
		if handler == nil {
			continue
		}
		if env != nil && env.RequireWorkerProxy && workerprobe.SupportsTool(def.Name) {
			s.SetToolHandler(def.Name, workerProbeToolHandler(def.Name))
			continue
		}
		if reason, unavailable := linuxFirstUnavailableTools[def.Name]; env != nil && env.RequireWorkerProxy && unavailable {
			name := def.Name
			message := reason
			s.SetToolHandler(name, func(mcp.ToolContext, json.RawMessage) (interface{}, *mcp.ErrorObj) {
				return nil, &mcp.ErrorObj{Code: -32002, Message: message}
			})
			continue
		}
		s.SetToolHandler(def.Name, handler)
	}
}

var linuxFirstUnavailableTools = map[string]string{
	"web.smuggle": "web.smuggle is unavailable: the isolated worker scope gateway does not support scoped raw TCP/TLS sockets; no probe was run",
	"web.sqli":    "web.sqli is unavailable: the Linux-first worker does not yet compose Nuclei/sqlmap with its native HTTP probes; no scan was run",
	"web.ssrf":    "web.ssrf is unavailable: blind SSRF confirmation requires an OOB callback service reachable by the assessed target, which this worker profile does not provide; no probe was run",
}
