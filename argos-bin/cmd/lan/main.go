package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/iwiels/argos-auditor/argos-bin/cmd/lan/tools"
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
	fmt.Println("Argos LAN Scanner v1.0.0")
	fmt.Println("Memory directory:", *memoryDir)
	fmt.Println()
	fmt.Println("Usage: argos-lan --mcp [--memory-dir <path>]")
	fmt.Println()
	fmt.Println("Available commands:")
	fmt.Println("  --mcp            Run as MCP stdio server for AI agent integration")
	fmt.Println("  --memory-dir     Override default memory directory (default: ~/.argos/memory)")
	fmt.Println()
	fmt.Println("Integrated tools:")
	fmt.Println("  host_discovery    Discover active hosts on the local network")
	fmt.Println("  port_scan         Scan open ports on a target host")
	fmt.Println("  banner_grab       Grab service banners from open ports")
	fmt.Println("  snmp_query        Query SNMP agents for system information")
	fmt.Println("  mdns_discover     Discover mDNS services on the local network")
	fmt.Println("  build_topology    Build network topology from scan data")
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
		Name:    "Argos LAN Scanner",
		Version: "1.0.0",
	})
	server.SetMemoryDir(memoryDir)

	tools.RegisterAll(server)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Println("Argos LAN Scanner MCP server starting (stdio)...")
	if err := server.Run(ctx); err != nil {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Argos LAN Scanner MCP server stopped")
}
