package workerrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const maxConnections = 64

func Run(ctx context.Context, socketPath string, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return run(ctx, socketPath, command, stdin, stdout, stderr, os.Environ())
}

func run(ctx context.Context, socketPath string, command []string, stdin io.Reader, stdout, stderr io.Writer, baseEnv []string) error {
	if ctx == nil || socketPath == "" || len(command) == 0 {
		return errors.New("worker relay requires a context, gateway socket, and command")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start worker proxy listener: %w", err)
	}
	proxyURL := "http://" + listener.Addr().String()
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	proxy := &proxyRelay{
		socketPath:  socketPath,
		listener:    listener,
		connections: make(map[net.Conn]struct{}),
		semaphore:   make(chan struct{}, maxConnections),
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- proxy.serve(relayCtx) }()

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = proxyEnvironment(baseEnv, proxyURL)
	commandErr := cmd.Run()
	cancel()
	_ = listener.Close()
	proxy.closeConnections()
	serveErr := <-serveDone
	if commandErr != nil {
		return commandErr
	}
	if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
		return serveErr
	}
	return nil
}

func proxyEnvironment(base []string, proxyURL string) []string {
	blocked := map[string]bool{
		"http_proxy": true, "https_proxy": true, "all_proxy": true, "no_proxy": true,
		"argos_worker_proxy_url": true,
	}
	out := make([]string, 0, len(base)+9)
	for _, pair := range base {
		key, _, ok := strings.Cut(pair, "=")
		if !ok || blocked[strings.ToLower(key)] {
			continue
		}
		out = append(out, pair)
	}
	out = append(out,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"ALL_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"all_proxy="+proxyURL,
		"NO_PROXY=",
		"no_proxy=",
		"ARGOS_WORKER_PROXY_URL="+proxyURL,
	)
	return out
}

type proxyRelay struct {
	socketPath  string
	listener    net.Listener
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	semaphore   chan struct{}
}

func (p *proxyRelay) serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = p.listener.Close()
		p.closeConnections()
	}()
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return err
		}
		select {
		case p.semaphore <- struct{}{}:
		case <-ctx.Done():
			client.Close()
			return ctx.Err()
		}
		gateway, err := (&net.Dialer{}).DialContext(ctx, "unix", p.socketPath)
		if err != nil {
			<-p.semaphore
			client.Close()
			continue
		}
		p.track(client, gateway)
		go func(client, gateway net.Conn) {
			defer func() {
				p.untrack(client, gateway)
				client.Close()
				gateway.Close()
				<-p.semaphore
			}()
			copyDone := make(chan struct{}, 2)
			go func() {
				_, _ = io.Copy(gateway, client)
				copyDone <- struct{}{}
			}()
			go func() {
				_, _ = io.Copy(client, gateway)
				copyDone <- struct{}{}
			}()
			<-copyDone
		}(client, gateway)
	}
}

func (p *proxyRelay) track(connections ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range connections {
		p.connections[conn] = struct{}{}
	}
}

func (p *proxyRelay) untrack(connections ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range connections {
		delete(p.connections, conn)
	}
}

func (p *proxyRelay) closeConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for conn := range p.connections {
		_ = conn.Close()
	}
}
