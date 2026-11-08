package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/iwiels/ARGOS/argos-bin/internal/workerpreflight"
)

func main() {
	target := flag.String("target", "", "absolute HTTP or HTTPS target URL")
	probes := flag.Int("probes", 5, "number of health probes to run (1-20)")
	flag.Parse()
	if flag.NArg() != 0 {
		fail("unexpected positional arguments")
	}
	if *target == "" {
		fail("target URL is required")
	}
	client, err := workerpreflight.NewClient(os.Getenv("ARGOS_WORKER_PROXY_URL"))
	if err != nil {
		fail(err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := workerpreflight.Run(ctx, *target, *probes, client)
	if err != nil {
		fail(err.Error())
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fail(fmt.Sprintf("encode worker preflight result: %v", err))
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "argos-worker-preflight:", message)
	os.Exit(1)
}
