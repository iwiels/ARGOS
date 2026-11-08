package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type UnixServer struct {
	server   *http.Server
	listener net.Listener
	path     string
	done     chan error
	close    sync.Once
}

func ListenUnix(ctx context.Context, socketPath string, handler http.Handler) (*UnixServer, error) {
	if ctx == nil || handler == nil || socketPath == "" {
		return nil, errors.New("gateway context, socket path, and handler are required")
	}
	parent := filepath.Dir(socketPath)
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect private gateway directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("gateway socket must be placed in a private, non-symlink directory")
	}
	if _, err := os.Lstat(socketPath); err == nil {
		return nil, errors.New("gateway socket path already exists")
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect gateway socket path: %w", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on gateway socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o666); err != nil {
		listener.Close()
		os.Remove(socketPath)
		return nil, fmt.Errorf("set gateway socket permissions: %w", err)
	}
	server := &UnixServer{
		server:   &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second},
		listener: listener,
		path:     socketPath,
		done:     make(chan error, 1),
	}
	go func() {
		server.done <- server.server.Serve(listener)
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-server.done:
		}
	}()
	return server, nil
}

func (s *UnixServer) Close() error {
	var closeErr error
	s.close.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		closeErr = s.server.Shutdown(ctx)
		if closeErr != nil {
			_ = s.server.Close()
		}
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}
