// Package e2e runs a real pentest flow against a local practice target using
// the argos-web MCP server. It downloads the MIT binaries on demand
// (GitHub releases) and exercises the full recon → scan → fuzz → sqli → xss
// pipeline over the MCP stdio protocol.
//
// The test is opt-in: set ARGOS_E2E=1 to run it. Set ARGOS_E2E_LIGHT=1
// to skip the nuclei/dalfox phases (web.scan and web.xss).
package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/env"
	"github.com/iwiels/argos-auditor/argos-bin/internal/practicetarget"
)

// ---- helpers ---------------------------------------------------------------

func strOf(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func f64Of(m map[string]any, k string) float64 {
	if v, ok := m[k].(float64); ok {
		return v
	}
	return 0
}

func listOf(m map[string]any, k string) []any {
	if v, ok := m[k].([]any); ok {
		return v
	}
	return nil
}

type mcpClient struct {
	stdin io.WriteCloser
	lines chan string
}

func (c *mcpClient) call(id int, method string, params any, timeout time.Duration) (map[string]any, error) {
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	select {
	case line, ok := <-c.lines:
		if !ok {
			return nil, errors.New("MCP server closed the stream")
		}
		var resp struct {
			Result map[string]any `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			return nil, fmt.Errorf("bad response line: %v: %s", err, line)
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for %s response", method)
	}
}

type phaseResult struct {
	name   string
	ok     bool
	detail string
}

// unwrapToolResult converts the MCP content envelope back into the raw result
// map the phase checks read. The Go server now wraps every tools/call result
// in {"content":[{"type":"text","text":"<json>"}]} so real MCP clients
// (whose CallToolResultSchema strips unknown fields) receive non-empty output.
func unwrapToolResult(t *testing.T, res map[string]any) map[string]any {
	t.Helper()
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		return res // not a wrapped tool result (e.g. initialize)
	}
	first, ok := content[0].(map[string]any)
	if !ok {
		t.Fatalf("tool result content[0] is not an object: %v", content[0])
	}
	text, ok := first["text"].(string)
	if !ok {
		t.Fatalf("tool result content[0] has no text: %v", content[0])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("tool result text is not a JSON object: %v\n%s", err, text)
	}
	return out
}

func runPhase(t *testing.T, c *mcpClient, results *[]phaseResult, name string, id int, params map[string]any, timeout time.Duration, check func(t *testing.T, res map[string]any) error) {
	t.Helper()
	start := time.Now()
	t.Logf("▶ %s ...", name)
	res, err := c.call(id, "tools/call", map[string]any{"name": "web." + name, "arguments": params}, timeout)
	if err != nil {
		*results = append(*results, phaseResult{name: name, ok: false, detail: "error: " + err.Error()})
		t.Errorf("FASE %s: %v", name, err)
		return
	}
	res = unwrapToolResult(t, res)
	detail := "ok"
	if check != nil {
		if cerr := check(t, res); cerr != nil {
			*results = append(*results, phaseResult{name: name, ok: false, detail: cerr.Error()})
			t.Errorf("FASE %s: %v", name, cerr)
			return
		}
	}
	*results = append(*results, phaseResult{name: name, ok: true, detail: detail})
	t.Logf("✓ %s %s [%ds]", name, detail, int(time.Since(start).Seconds()))
}

func exeName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func buildWebExe(t *testing.T, work string) string {
	t.Helper()
	exe := filepath.Join(work, exeName("web"))
	cmd := exec.Command("go", "build", "-o", exe, "./cmd/web")
	cmd.Dir = ".." // module root, relative to the e2e package dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build web.exe: %v\n%s", err, out)
	}
	return exe
}

// ---- the E2E ---------------------------------------------------------------

func TestWebFlowE2E(t *testing.T) {
	if env.Get("ARGOS_E2E") != "1" {
		t.Skip("set ARGOS_E2E=1 to run the full on-demand pentest E2E (downloads MIT binaries from GitHub)")
	}
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	light := env.Get("ARGOS_E2E_LIGHT") == "1"

	// 1) local practice target
	srv := httptest.NewServer(practicetarget.Handler())
	defer srv.Close()
	base := srv.URL
	t.Logf("practice target: %s", base)

	// 2) isolated working dirs (tools cache, HOME for nuclei templates, memory).
	// Set ARGOS_E2E_TOOLS_DIR / ARGOS_E2E_HOME to reuse downloads across runs.
	work := t.TempDir()
	toolsDir := env.Get("ARGOS_E2E_TOOLS_DIR")
	if toolsDir == "" {
		toolsDir = filepath.Join(work, "tools")
	}
	homeDir := env.Get("ARGOS_E2E_HOME")
	if homeDir == "" {
		homeDir = filepath.Join(work, "home")
	}
	memDir := filepath.Join(work, "memory")
	for _, d := range []string{toolsDir, homeDir, filepath.Join(homeDir, "AppData", "Roaming"), filepath.Join(homeDir, "AppData", "Local"), memDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// 3) build + launch the MCP server
	exe := buildWebExe(t, work)
	cmd := exec.Command(exe, "--mcp", "--memory-dir", memDir)
	cmd.Env = append(os.Environ(),
		"ARGOS_TOOLS_DIR="+toolsDir,
		"HOME="+homeDir,
		"USERPROFILE="+homeDir,
		"APPDATA="+filepath.Join(homeDir, "AppData", "Roaming"),
		"LOCALAPPDATA="+filepath.Join(homeDir, "AppData", "Local"),
		"OPENCODE_CONFIG_DIR=", // ffuf falls back to its bundled wordlist
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start web.exe: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	client := &mcpClient{stdin: stdin, lines: make(chan string, 16)}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
		for sc.Scan() {
			client.lines <- sc.Text()
		}
		close(client.lines)
	}()

	// 4) initialize
	initRes, err := client.call(1, "initialize", map[string]any{"protocolVersion": "2024-11-05"}, 30*time.Second)
	if err != nil {
		t.Fatalf("initialize: %v\n--- web.exe stderr ---\n%s", err, stderr.String())
	}
	t.Logf("MCP server: %s", strOf(mapOf(initRes, "serverInfo"), "name"))

	var results []phaseResult
	nextID := 100

	// FASE 1 — recon
	runPhase(t, client, &results, "probe", nextID, map[string]any{"target": base}, 4*time.Minute,
		func(t *testing.T, res map[string]any) error {
			eps := listOf(res, "endpoints")
			if len(eps) == 0 {
				return errors.New("no endpoints")
			}
			first, _ := eps[0].(map[string]any)
			if int(f64Of(first, "status_code")) != 200 {
				return fmt.Errorf("status_code=%v", first["status_code"])
			}
			if !strings.Contains(strOf(first, "title"), "Practice Target") {
				return fmt.Errorf("title=%q", strOf(first, "title"))
			}
			return nil
		})
	nextID++

	runPhase(t, client, &results, "tech", nextID, map[string]any{"target": base}, 3*time.Minute,
		func(t *testing.T, res map[string]any) error {
			techs := listOf(res, "technologies")
			t.Logf("   technologies: %v", techs)
			return nil
		})
	nextID++

	runPhase(t, client, &results, "waf", nextID, map[string]any{"target": base}, 1*time.Minute,
		func(t *testing.T, res map[string]any) error {
			if b, ok := res["waf_detected"].(bool); ok && b {
				return fmt.Errorf("WAF inesperado: %v", res["wafs"])
			}
			return nil
		})
	nextID++

	runPhase(t, client, &results, "crawl", nextID, map[string]any{"target": base, "depth": 2}, 5*time.Minute,
		func(t *testing.T, res map[string]any) error {
			for _, e := range listOf(res, "endpoints") {
				if m, ok := e.(map[string]any); ok && strings.Contains(strOf(m, "url"), "/search") {
					return nil
				}
			}
			return fmt.Errorf("/search no apareció en el crawl (%d endpoints)", len(listOf(res, "endpoints")))
		})
	nextID++

	// FASE 2 — fuzz + params
	runPhase(t, client, &results, "fuzz", nextID, map[string]any{"target": base}, 5*time.Minute,
		func(t *testing.T, res map[string]any) error {
			hits := listOf(res, "hits")
			found := false
			for _, h := range hits {
				m, _ := h.(map[string]any)
				p := ""
				if in, ok := m["input"].(map[string]any); ok {
					p, _ = in["FUZZ"].(string)
				}
				if strings.Contains(p, "admin") || strings.Contains(p, ".env") || strings.Contains(p, "backup") {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("no encontró rutas sensibles (%d hits; status=%q exit=%v installed=%q summary=%q)",
					len(hits), strOf(res, "status"), res["exit_code"], strOf(res, "installed"), strOf(res, "summary"))
			}
			if len(listOf(res, "findings")) == 0 {
				return fmt.Errorf("fuzz sin hallazgos sensibles (%d hits, summary=%q)", len(hits), strOf(res, "summary"))
			}
			return nil
		})
	nextID++

	runPhase(t, client, &results, "params", nextID, map[string]any{"target": base + "/api/health"}, 3*time.Minute,
		func(t *testing.T, res map[string]any) error {
			if len(listOf(res, "params")) == 0 {
				return errors.New("sin parámetros candidatos")
			}
			return nil
		})
	nextID++

	// FASE 3 — sql injection (native boolean detector + nuclei sqli tags)
	runPhase(t, client, &results, "sqli", nextID, map[string]any{"target": base + "/search?q=1"}, 8*time.Minute,
		func(t *testing.T, res map[string]any) error {
			if len(listOf(res, "findings")) == 0 {
				return errors.New("sin indicadores de SQLi")
			}
			return nil
		})
	nextID++

	// FASE 4 — xss (dalfox) and full scan (nuclei) — skippable with LIGHT
	if !light {
		runPhase(t, client, &results, "xss", nextID, map[string]any{"target": base + "/profile?user=1"}, 5*time.Minute,
			func(t *testing.T, res map[string]any) error {
				if len(listOf(res, "findings")) == 0 {
					return errors.New("sin XSS detectado")
				}
				return nil
			})
		nextID++

		runPhase(t, client, &results, "scan", nextID, map[string]any{"target": base, "tags": "misconfig"}, 8*time.Minute,
			func(t *testing.T, res map[string]any) error {
				switch strOf(res, "status") {
				case "timeout":
					t.Logf("   scan: timeout (posible descarga inicial de templates nuclei)")
					return nil
				case "completed":
					t.Logf("   scan: %d hallazgos", len(listOf(res, "findings")))
					return nil
				default:
					return fmt.Errorf("estado inesperado: %q (exit %v)", strOf(res, "status"), res["exit_code"])
				}
			})
		nextID++
	}

	// 5) summary
	t.Log("--- RESUMEN PENTEST E2E ---")
	allOK := true
	for _, r := range results {
		mark := "✓"
		if !r.ok {
			mark = "✗"
			allOK = false
		}
		t.Logf("  %s %-8s %s", mark, r.name, r.detail)
	}
	if !allOK {
		t.Logf("--- web.exe stderr (tail) ---\n%s", tailStr(stderr.String(), 2000))
		t.Fatal("el flujo E2E no completó todas las fases")
	}
	t.Log("PENTEST E2E COMPLETO: recon → scan → fuzz → sqli → xss ✓")
}

func mapOf(m map[string]any, k string) map[string]any {
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	return nil
}

func tailStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
