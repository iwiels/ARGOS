package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/iwiels/ARGOS/argos-bin/internal/workerrelay"
)

func main() {
	var socketPath string
	flag.StringVar(&socketPath, "gateway-socket", "/run/argos/gateway.sock", "Unix socket for the host scope gateway")
	flag.Parse()
	command := flag.Args()
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := workerrelay.Run(ctx, socketPath, command, os.Stdin, os.Stdout, os.Stderr); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() >= 0 {
			os.Exit(exitError.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
