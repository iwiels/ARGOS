package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/iwiels/argos-auditor/argos-bin/cmd/orquestador/tools"
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
		dir := paths.ResolveMemoryDir(home)
		*memoryDir = dir
	}

	if err := os.MkdirAll(*memoryDir+"/findings", 0755); err != nil {
		log.Fatalf("Cannot create memory directory: %v", err)
	}

	if *mcpMode {
		runMCPServer(*memoryDir)
		return
	}

	showHeader()
	fmt.Println("Argos Orquestador v1.0.0")
	fmt.Println("Memory directory:", *memoryDir)
	fmt.Println()
	fmt.Println("Usage: argos --mcp [--memory-dir <path>]")
	fmt.Println()
	fmt.Println("Available commands:")
	fmt.Println("  --mcp            Run as MCP stdio server for AI agent integration")
	fmt.Println("  --memory-dir     Override default memory directory (default: ~/.argos/memory)")
	fmt.Println()
	fmt.Println("Integrated tools:")
	fmt.Println("  orchestrator.sync     Sync a security profile to the agent team")
	fmt.Println("  orchestrator.info     Show available security profiles")
	fmt.Println("  audit.scout           Reconnaissance and target profiling")
	fmt.Println("  audit.dispatch        Dispatch security specialists to a target")
	fmt.Println("  audit.run.start       Start a security audit run")
	fmt.Println("  audit.run.phase       Record a phase artifact in an audit run")
	fmt.Println("  audit.run.inspect     Inspect audit run artifacts and status")
	fmt.Println("  audit.run.correlate   Correlate findings across audit phases")
	fmt.Println("  memory.search         Search persisted findings")
	fmt.Println("  memory.context        View recent memory context")
	fmt.Println("  memory.save           Save a structured finding")
}

func showHeader() {
	fmt.Print(`
 ███████╗ ██████╗ ██╗██╗   ██╗██╗  ██╗██╗ ██████╗ ███╗   ██╗███████╗███████╗
 ╚══███╔╝██╔═══██╗██║██║   ██║╚██╗██╔╝██║██╔═══██╗████╗  ██║██╔════╝██╔════╝
   ███╔╝ ██║   ██║██║██║   ██║ ╚███╔╝ ██║██║   ██║██╔██╗ ██║█████╗  ███████╗
  ███╔╝  ██║   ██║██║╚██╗ ██╔╝ ██╔██╗ ██║██║   ██║██║╚██╗██║██╔══╝  ╚════██║
 ███████╗╚██████╔╝██║ ╚████╔╝ ██╔╝ ██╗██║╚██████╔╝██║ ╚████║███████╗███████║
 ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝
`)
}

func runMCPServer(memoryDir string) {
	server := mcp.NewServer(mcp.ServerInfo{
		Name:    "Argos Orquestador",
		Version: "1.0.0",
	})
	server.SetMemoryDir(memoryDir)

	tools.RegisterAll(server)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Println("Argos Orquestador MCP server starting (stdio)...")
	if err := server.Run(ctx); err != nil {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Argos Orquestador MCP server stopped")
}
