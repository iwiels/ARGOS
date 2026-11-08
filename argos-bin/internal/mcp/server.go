package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/env"
)

var writeMu sync.Mutex

// Server is a JSON-RPC 2.0 MCP server over stdio.
//
// Concurrency: requests are read sequentially from stdin, but `tools/call`
// invocations are dispatched in goroutines bounded by a semaphore, so a
// long-running tool no longer blocks every other request (the "saturated MCP"
// failure mode). Responses are written under a mutex and may arrive in any
// order — MCP clients correlate them by request id.
//
// Cancellation: `$/cancelRequest` marks the request id as canceled AND cancels
// its context, so handlers honoring ToolContext.Ctx stop promptly. Responses
// for canceled ids are suppressed.
//
// Tuning (env vars, read at startup):
//
//	ARGOS_MCP_CONCURRENCY       max concurrent tool executions (default 4, min 1)
//	ARGOS_MCP_TIMEOUT_MS        per-call timeout (default 300000 = 5 min, matches the client)
type Server struct {
	tools     map[string]ToolHandler
	defs      []ToolDefinition
	reader    *bufio.Reader
	writer    *bufio.Writer
	memoryDir string
	info      ServerInfo

	sem     chan struct{}
	timeout time.Duration

	cancelMu sync.Mutex
	canceled map[string]struct{}
	cancels  map[string]context.CancelFunc
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type auditEvent struct {
	Time       string `json:"time"`
	Server     string `json:"server"`
	Tool       string `json:"tool"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

const (
	errTimeoutCode     = -32000
	defaultConcurrency = 4
	defaultTimeoutMS   = 300000
)

func NewServer(info ServerInfo) *Server {
	return NewServerWithIO(info, os.Stdin, os.Stdout)
}

// NewServerWithIO is NewServer with injectable transports (used by tests).
func NewServerWithIO(info ServerInfo, r io.Reader, w io.Writer) *Server {
	log.SetOutput(os.Stderr)
	log.SetPrefix("")
	log.SetFlags(log.LstdFlags)

	concurrency := envInt("ARGOS_MCP_CONCURRENCY", defaultConcurrency)
	if concurrency < 1 {
		concurrency = 1
	}
	timeoutMS := envInt("ARGOS_MCP_TIMEOUT_MS", defaultTimeoutMS)
	if timeoutMS <= 0 {
		timeoutMS = defaultTimeoutMS
	}

	return &Server{
		tools:    make(map[string]ToolHandler),
		defs:     make([]ToolDefinition, 0),
		reader:   bufio.NewReader(r),
		writer:   bufio.NewWriter(w),
		info:     info,
		sem:      make(chan struct{}, concurrency),
		timeout:  time.Duration(timeoutMS) * time.Millisecond,
		canceled: make(map[string]struct{}),
		cancels:  make(map[string]context.CancelFunc),
	}
}

// SetLimits overrides the concurrency and per-call timeout (used by tests).
func (s *Server) SetLimits(concurrency int, timeout time.Duration) {
	if concurrency < 1 {
		concurrency = 1
	}
	s.sem = make(chan struct{}, concurrency)
	if timeout > 0 {
		s.timeout = timeout
	}
}

func envInt(key string, def int) int {
	v := env.Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func (s *Server) SetMemoryDir(dir string) {
	s.memoryDir = dir
}

func (s *Server) RegisterTool(def ToolDefinition, handler ToolHandler) {
	s.tools[def.Name] = handler
	s.defs = append(s.defs, def)
}

// SetToolHandler replaces the handler of an already registered tool.
//
// It exists so a server can wrap the handlers it registered — for example to
// persist what they emit — without registering the tool a second time:
// RegisterTool appends to the definition list, so re-registering would show
// the tool twice in tools/list.
func (s *Server) SetToolHandler(name string, handler ToolHandler) {
	s.tools[name] = handler
}

// ToolDefinitions returns the registered tool definitions in registration order.
func (s *Server) ToolDefinitions() []ToolDefinition {
	return s.defs
}

func (s *Server) GetToolHandler(name string) ToolHandler {
	return s.tools[name]
}

func (s *Server) Run(ctx context.Context) error {
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			log.Printf("Invalid JSON-RPC: %v", err)
			continue
		}

		s.handleRequest(ctx, req)
	}
}

func (s *Server) handleRequest(ctx context.Context, req Request) {
	toolCtx := ToolContext{
		MemoryDir: s.memoryDir,
		Log:       func(format string, args ...interface{}) { log.Printf(format, args...) },
	}

	var resp Response
	resp.JSONRPC = "2.0"
	resp.ID = req.ID

	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &params)

		resp.Result = map[string]interface{}{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": s.info,
		}

	case "notifications/initialized":
		return

	case "$/cancelRequest":
		var params struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		json.Unmarshal(req.Params, &params)
		if len(params.RequestID) > 0 {
			key := string(params.RequestID)
			s.cancelMu.Lock()
			if cancel, ok := s.cancels[key]; ok {
				cancel()
				delete(s.cancels, key)
			}
			s.canceled[key] = struct{}{}
			s.cancelMu.Unlock()
		}
		return // notifications carry no response

	case "tools/list":
		resp.Result = map[string]interface{}{
			"tools": s.defs,
		}

	case "tools/call":
		var params struct {
			Name      string                     `json:"name"`
			Arguments json.RawMessage            `json:"arguments"`
			Meta      map[string]json.RawMessage `json:"_meta"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = ErrInvalidParams
			break
		}

		handler, ok := s.tools[params.Name]
		if !ok {
			resp.Error = ErrMethodNotFound
			s.writeAuditEvent(params.Name, time.Now(), "error", ErrMethodNotFound.Message)
			break
		}
		if rawSessionID := params.Meta["argos/session_id"]; len(rawSessionID) > 0 {
			_ = json.Unmarshal(rawSessionID, &toolCtx.SessionID)
		}
		if rawRunID := params.Meta["argos/run_id"]; len(rawRunID) > 0 {
			if err := json.Unmarshal(rawRunID, &toolCtx.RunID); err != nil {
				resp.Error = ErrInvalidParams
				break
			}
		}
		if rawOperationID := params.Meta["argos/operation_id"]; len(rawOperationID) > 0 {
			_ = json.Unmarshal(rawOperationID, &toolCtx.OperationID)
		}
		if rawScope := params.Meta["argos/scope"]; len(rawScope) > 0 {
			var snapshot ScopeSnapshot
			if err := json.Unmarshal(rawScope, &snapshot); err != nil {
				resp.Error = ErrInvalidParams
				break
			}
			toolCtx.Scope = &snapshot
		}

		s.dispatchTool(ctx, req.ID, params.Name, handler, toolCtx, params.Arguments)
		return

	default:
		resp.Error = ErrMethodNotFound
	}

	s.writeResponse(resp)
}

// dispatchTool runs a tool call in a goroutine bounded by the concurrency
// semaphore, applying the per-call timeout and honoring $/cancelRequest.
func (s *Server) dispatchTool(
	ctx context.Context,
	id json.RawMessage,
	name string,
	handler ToolHandler,
	toolCtx ToolContext,
	args json.RawMessage,
) {
	started := time.Now()
	key := string(id)

	go func() {
		// Register the cancel handle before queueing on the semaphore so
		// $/cancelRequest works even while the call is waiting for a slot.
		callCtx, cancel := context.WithTimeout(ctx, s.timeout)
		defer cancel()

		s.cancelMu.Lock()
		s.cancels[key] = cancel
		_, alreadyCanceled := s.canceled[key]
		s.cancelMu.Unlock()

		release := func() {
			s.cancelMu.Lock()
			delete(s.cancels, key)
			delete(s.canceled, key)
			s.cancelMu.Unlock()
		}

		if alreadyCanceled {
			release()
			s.writeAuditEvent(name, started, "canceled", "canceled before execution")
			log.Printf("tools/call %s (id %s) canceled before execution, response suppressed", name, key)
			return
		}

		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		case <-callCtx.Done():
			// Timed out (or canceled) while waiting for a concurrency slot.
			s.cancelMu.Lock()
			_, wasCanceled := s.canceled[key]
			s.cancelMu.Unlock()
			release()
			if wasCanceled {
				s.writeAuditEvent(name, started, "canceled", "canceled while queued")
				log.Printf("tools/call %s (id %s) canceled while queued, response suppressed", name, key)
				return
			}
			resp := Response{
				JSONRPC: "2.0",
				ID:      id,
				Error: &ErrorObj{
					Code:    errTimeoutCode,
					Message: fmt.Sprintf("Tool %s timed out after %s (queued)", name, s.timeout),
				},
			}
			s.writeAuditEvent(name, started, "timeout", "queued past timeout")
			s.writeResponse(resp)
			return
		}

		callCtxValue := toolCtx
		callCtxValue.Ctx = callCtx

		type outcome struct {
			result interface{}
			err    *ErrorObj
		}
		done := make(chan outcome, 1)
		go func() {
			result, errObj := handler(callCtxValue, args)
			done <- outcome{result: result, err: errObj}
		}()

		var resp Response
		resp.JSONRPC = "2.0"
		resp.ID = id

		select {
		case res := <-done:
			if res.err != nil {
				resp.Error = res.err
				s.writeAuditEvent(name, started, "error", res.err.Message)
			} else {
				resp.Result = ToolResultText(res.result)
				s.writeAuditEvent(name, started, "success", "")
			}
		case <-callCtx.Done():
			resp.Error = &ErrorObj{
				Code:    errTimeoutCode,
				Message: fmt.Sprintf("Tool %s timed out after %s", name, s.timeout),
			}
			s.writeAuditEvent(name, started, "timeout", "request timed out")
		}

		s.cancelMu.Lock()
		_, isCanceled := s.canceled[key]
		delete(s.canceled, key)
		delete(s.cancels, key)
		s.cancelMu.Unlock()

		if isCanceled {
			log.Printf("tools/call %s (id %s) canceled by client, response suppressed", name, key)
			return
		}
		s.writeResponse(resp)
	}()
}

func (s *Server) writeResponse(resp Response) {
	writeMu.Lock()
	defer writeMu.Unlock()
	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Marshal error: %v", err)
		return
	}
	s.writer.Write(data)
	s.writer.Write([]byte("\n"))
	s.writer.Flush()
}

func (s *Server) writeAuditEvent(tool string, started time.Time, status string, message string) {
	if s.memoryDir == "" {
		return
	}
	file, err := os.OpenFile(filepath.Join(s.memoryDir, "audit-log.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("Audit log open error: %v", err)
		return
	}
	defer file.Close()

	entry := auditEvent{
		Time:       time.Now().UTC().Format(time.RFC3339Nano),
		Server:     s.info.Name,
		Tool:       tool,
		Status:     status,
		DurationMS: time.Since(started).Milliseconds(),
		Error:      message,
	}
	if err := json.NewEncoder(file).Encode(entry); err != nil {
		log.Printf("Audit log write error: %v", err)
	}
}
