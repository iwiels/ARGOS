package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/runner"
)

const defaultServerURL = "http://127.0.0.1:4096"
const maxPromptBytes = 1 << 20

var version = "dev"

func main() {
	os.Exit(execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func execute(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return runner.ExitError
	}
	command := args[0]
	if command == "--version" || command == "version" {
		fmt.Fprintf(stdout, "argos-runner %s\n", version)
		return runner.ExitSuccess
	}
	if command != "run" && command != "status" && command != "cancel" && command != "export" {
		fmt.Fprintf(stderr, "unknown command %q; expected run, status, cancel, export\n", command)
		usage(stderr)
		return runner.ExitError
	}

	flags := flag.NewFlagSet("argos-runner "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverDefault := os.Getenv("ARGOS_SERVER_URL")
	if serverDefault == "" {
		serverDefault = defaultServerURL
	}
	serverURL := flags.String("server", serverDefault, "Argos server URL (or ARGOS_SERVER_URL)")
	sessionID := flags.String("session", "", "existing Argos session ID; configure and verify its scope in Argos first")
	var prompt *string
	var failOn *string
	var pollInterval *time.Duration
	var timeout *time.Duration
	var format *string
	var outputPath *string
	if command == "run" {
		prompt = flags.String("prompt", "", "audit instruction; use - to read from stdin")
		failOn = flags.String("fail-on", "high", "gate threshold: critical, high, medium, low, or info")
		pollInterval = flags.Duration("poll-interval", 2*time.Second, "execution status polling interval")
		timeout = flags.Duration("timeout", 30*time.Minute, "maximum audit duration")
	}
	if command == "export" {
		format = flags.String("format", "sarif", "report format: pdf, sarif, defectdojo, junit, html, sbom, har, csv, markdown")
		outputPath = flags.String("output", "", "file path for the verified report")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return runner.ExitSuccess
		}
		return runner.ExitError
	}
	if strings.TrimSpace(*sessionID) == "" {
		fmt.Fprintln(stderr, "--session is required")
		return runner.ExitError
	}
	client, err := runner.NewClient(*serverURL, os.Getenv("ARGOS_SERVER_USERNAME"), os.Getenv("ARGOS_SERVER_PASSWORD"))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return runner.ExitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch command {
	case "run":
		text := *prompt
		if text == "-" {
			content, err := io.ReadAll(io.LimitReader(stdin, maxPromptBytes+1))
			if err != nil {
				fmt.Fprintf(stderr, "read prompt from stdin: %v\n", err)
				return runner.ExitError
			}
			if len(content) > maxPromptBytes {
				fmt.Fprintf(stderr, "prompt exceeds the %d-byte limit\n", maxPromptBytes)
				return runner.ExitError
			}
			text = string(content)
		}
		result, err := client.Run(ctx, runner.RunOptions{
			SessionID:    *sessionID,
			Prompt:       text,
			FailOn:       *failOn,
			PollInterval: *pollInterval,
			Timeout:      *timeout,
		})
		if err != nil {
			fmt.Fprintln(stderr, err)
			return runner.ExitError
		}
		if err := writeJSON(stdout, result); err != nil {
			fmt.Fprintf(stderr, "write result: %v\n", err)
			return runner.ExitError
		}
		return result.ExitCode
	case "status":
		runs, err := client.Status(ctx, *sessionID)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return runner.ExitError
		}
		if err := writeJSON(stdout, map[string]any{"sessionID": *sessionID, "runs": runs}); err != nil {
			fmt.Fprintf(stderr, "write status: %v\n", err)
			return runner.ExitError
		}
		return runner.ExitSuccess
	case "cancel":
		if err := client.Cancel(ctx, *sessionID); err != nil {
			fmt.Fprintln(stderr, err)
			return runner.ExitError
		}
		if err := writeJSON(stdout, map[string]any{"sessionID": *sessionID, "cancelled": true}); err != nil {
			fmt.Fprintf(stderr, "write cancellation result: %v\n", err)
			return runner.ExitError
		}
		return runner.ExitSuccess
	case "export":
		if strings.TrimSpace(*outputPath) == "" {
			fmt.Fprintln(stderr, "--output is required")
			return runner.ExitError
		}
		if err := client.Export(ctx, *sessionID, *format, *outputPath); err != nil {
			fmt.Fprintln(stderr, err)
			return runner.ExitError
		}
		if err := writeJSON(stdout, map[string]any{"sessionID": *sessionID, "format": *format, "output": *outputPath}); err != nil {
			fmt.Fprintf(stderr, "write export result: %v\n", err)
			return runner.ExitError
		}
		return runner.ExitSuccess
	default:
		return runner.ExitError
	}
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func usage(output io.Writer) {
	fmt.Fprintln(output, "Usage: argos-runner <run|status|cancel|export> [options]")
	fmt.Fprintln(output, "Run operates on an existing Argos session whose scope was approved in the desktop.")
}
