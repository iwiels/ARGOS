package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/iwiels/ARGOS/argos-bin/cmd/es/tools"
	"github.com/iwiels/ARGOS/argos-bin/internal/mcp"
	"github.com/iwiels/ARGOS/argos-bin/internal/paths"
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
	if err := os.MkdirAll(*memoryDir, 0o755); err != nil {
		log.Fatalf("Cannot create memory directory: %v", err)
	}

	if *mcpMode {
		runMCPServer(*memoryDir)
		return
	}

	fmt.Println(" v1.0.0")
	fmt.Println("Memory directory:", *memoryDir)
	fmt.Println()
	fmt.Println("Usage: argos-es --mcp [--memory-dir <path>]")
	fmt.Println()
	fmt.Println("Integrated tools:")
	fmt.Println("  es.info            Cluster info and version")
	fmt.Println("  es.cluster_health  Cluster health")
	fmt.Println("  es.indices         List indices (optionally filtered by pattern)")
	fmt.Println("  es.mapping         Get an index mapping")
	fmt.Println("  es.search          Search an index with query DSL")
	fmt.Println("  es.get             Get a document by id")
	fmt.Println()
	fmt.Println("Configuration (env, the cluster belongs to the customer):")
	fmt.Println("  ARGOS_ES_URL             Elasticsearch base URL (required)")
	fmt.Println("  ARGOS_ES_API_KEY         API key (base64) - preferred auth")
	fmt.Println("  ARGOS_ES_USER/PASSWORD   Basic auth fallback")
	fmt.Println("  ARGOS_ES_INSECURE        Skip TLS verification (1/true) for self-signed on-prem clusters")
}

func runMCPServer(memoryDir string) {
	server := mcp.NewServer(mcp.ServerInfo{
		Name:    "Argos Elasticsearch Connector",
		Version: "1.0.0",
	})
	server.SetMemoryDir(memoryDir)

	tools.RegisterAll(server, tools.NewEnv())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Println(" MCP server starting (stdio)...")
	if err := server.Run(ctx); err != nil {
		log.Fatalf("Server error: %v", err)
	}
	log.Println(" MCP server stopped")
}
