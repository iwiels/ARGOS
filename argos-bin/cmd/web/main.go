package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/iwiels/argos-auditor/argos-bin/cmd/web/tools"
	"github.com/iwiels/argos-auditor/argos-bin/internal/mcp"
	"github.com/iwiels/argos-auditor/argos-bin/internal/paths"
)

func main() {
	mcpMode := flag.Bool("mcp", false, "Run as MCP stdio server")
	memoryDir := flag.String("memory-dir", "", "Directory for memory persistence")
	flag.Parse()

	if *memoryDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Cannot determine home directory: %v", err)
		}
		*memoryDir = paths.ResolveMemoryDir(home)
	}
	if err := os.MkdirAll(*memoryDir+"/findings", 0o755); err != nil {
		log.Fatalf("Cannot create memory directory: %v", err)
	}

	if *mcpMode {
		runMCPServer(*memoryDir)
		return
	}

	toolsDir, err := tools.DefaultToolsDir()
	if err != nil {
		log.Fatalf("Cannot resolve tools directory: %v", err)
	}
	fmt.Println("Argos Web Scanner v1.0.0")
	fmt.Println("Memory directory:", *memoryDir)
	fmt.Println("Tools directory: ", toolsDir)
	fmt.Println()
	fmt.Println("Usage: argos-web --mcp [--memory-dir <path>]")
	fmt.Println()
	fmt.Println("Integrated tools:")
	fmt.Println("  web.scan        Template-driven vulnerability scan (nuclei)")
	fmt.Println("  web.sqli        SQLi detection (nuclei sqli tags + native boolean detector)")
	fmt.Println("  web.fuzz        Directory/vhost fuzzing (ffuf)")
	fmt.Println("  web.params      Hidden parameter discovery (ffuf)")
	fmt.Println("  web.crawl       Crawling, incl. headless SPA (katana)")
	fmt.Println("  web.probe       Live host probing + screenshot (httpx)")
	if os.Getenv("ARGOS_BROWSER_WORKER_AVAILABLE") == "1" {
		fmt.Println("  web.browse      Containerized Playwright navigation, login, authorization, and DOM XSS checks")
	}
	fmt.Println("  web.tech        Technology fingerprinting (httpx)")
	fmt.Println("  web.subdomains  Subdomain enumeration + resolution (subfinder + dnsx)")
	fmt.Println("  web.urls        Historical URLs (gau)")
	fmt.Println("  web.xss         XSS detection (dalfox)")
	fmt.Println("  web.oob         Out-of-band interaction testing (interactsh-client)")
	fmt.Println("  web.waf         WAF fingerprinting (native)")
	fmt.Println("  web.artifact    Fetch, beautify (HTML/JS/CSS/JSON), extract endpoints/secrets")
	fmt.Println("  web.artifact.read Read paginated lines or regex search beautified artifacts")
}

func runMCPServer(memoryDir string) {
	if err := os.Setenv("ARGOS_REQUIRE_CONTAINER_AUDIT", "1"); err != nil {
		log.Fatalf("Cannot enable container-required audit mode: %v", err)
	}
	toolsDir, err := tools.DefaultToolsDir()
	if err != nil {
		log.Fatalf("Cannot resolve tools directory: %v", err)
	}
	server := mcp.NewServer(mcp.ServerInfo{
		Name:    "Argos Web Scanner",
		Version: "1.0.0",
	})
	server.SetMemoryDir(memoryDir)

	env := tools.NewEnv(toolsDir)
	// The tools persist their findings in this store so the backend can
	// reconcile them without the LLM transcribing them (ARG-013).
	env.MemoryDir = memoryDir
	tools.RegisterAll(server, env)
	// The local OOB collector holds a listener: release it on shutdown.
	defer tools.StopOOBCollector(env)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Println("Argos Web Scanner MCP server starting (stdio)...")
	log.Println("Tools directory:", toolsDir)
	if err := server.Run(ctx); err != nil {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Argos Web Scanner MCP server stopped")
}
