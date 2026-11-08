package traffic

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/iwiels/ARGOS/argos-bin/internal/env"
	"github.com/iwiels/ARGOS/argos-bin/internal/paths"
)

const (
	// DefaultMaxExchanges is how many exchanges a session keeps before the
	// oldest ones are evicted.
	DefaultMaxExchanges = 5000
	// MaxExchangesEnv overrides the per-session cap.
	MaxExchangesEnv = "ARGOS_TRAFFIC_MAX_EXCHANGES"
	MaxBodySize = 4 << 20
	maxBodySize = MaxBodySize
)

// Doer performs an HTTP request. *http.Client satisfies it.
//
// El cliente que se le pasa al store es SIEMPRE el cliente atado al
// ScopeGuard: un http.Client propio se saltaría el IP-pinning, el rate limit
// y el audit log encadenado.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ScopeValidator validates a target against the scope of the engagement.
// *scope.ScopeGuard satisfies it.
type ScopeValidator interface {
	ValidateTarget(ctx context.Context, rawTarget string) (string, error)
}

// Store is the traffic store of an engagement.
//
// On disk: <memoryDir>/traffic/<sessionID>/<exchangeID>.json
type Store struct {
	// BaseDir is the root of the store (<memoryDir>/traffic).
	BaseDir string

	client       Doer
	scope        ScopeValidator
	maxExchanges int
}

// NewStore returns a store rooted at <memoryDir>/traffic.
//
// Sin memoryDir usa el mismo criterio que el resto de los binarios
// (paths.ResolveMemoryDir), así que el store es el compartido con el
// backend.
func NewStore(memoryDir string) *Store {
	if strings.TrimSpace(memoryDir) == "" {
		home, _ := os.UserHomeDir()
		memoryDir = paths.ResolveMemoryDir(home)
	}
	return &Store{
		BaseDir:      filepath.Join(memoryDir, "traffic"),
		maxExchanges: MaxExchangesFromEnv(),
	}
}

// NewStoreWithScope returns a store that can replay exchanges.
//
// El cliente y el validador de scope se inyectan atados al ScopeGuard de la
// sesión: el store no puede emitir tráfico por su cuenta.
func NewStoreWithScope(memoryDir string, client Doer, validator ScopeValidator) *Store {
	store := NewStore(memoryDir)
	store.client = client
	store.scope = validator
	return store
}

// MaxExchangesFromEnv returns the per-session cap of exchanges.
func MaxExchangesFromEnv() int {
	raw := strings.TrimSpace(env.Get(MaxExchangesEnv))
	if raw == "" {
		return DefaultMaxExchanges
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return DefaultMaxExchanges
	}
	return value
}

// sessionDir is the directory of the exchanges of a session.
func (s *Store) sessionDir(sessionID string) string {
	return filepath.Join(s.BaseDir, sanitizeSegment(sessionID))
}

// sanitizeSegment keeps a session id usable as a directory name.
func sanitizeSegment(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_' || r == '.':
			return r
		default:
			return '-'
		}
	}, strings.TrimSpace(value))
	cleaned = strings.Trim(cleaned, "-")
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}

// persistedExchange is the on-disk shape of an exchange.
//
// Los cuerpos van en texto (o base64 si no son UTF-8) con su sha256: el hash
// permite comparar dos responses sin releerlas enteras.
type persistedExchange struct {
	ID              string              `json:"id"`
	SessionID       string              `json:"session_id"`
	Timestamp       string              `json:"timestamp"`
	Method          string              `json:"method"`
	URL             string              `json:"url"`
	Host            string              `json:"host"`
	RequestHeaders  map[string][]string `json:"request_headers,omitempty"`
	RequestBody     *storedBody         `json:"request_body,omitempty"`
	Status          int                 `json:"status"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	ResponseBody    *storedBody         `json:"response_body,omitempty"`
	DurationMs      int64               `json:"duration_ms"`
	SourceTool      string              `json:"source_tool,omitempty"`
	Target          string              `json:"target,omitempty"`
	ScopeAllowed    bool                `json:"scope_allowed"`
}

// storedBody is a body as it goes to disk.
type storedBody struct {
	Text   string `json:"text,omitempty"`
	Base64 string `json:"base64,omitempty"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// encodeBody serializes a body for disk.
func encodeBody(body []byte) *storedBody {
	if len(body) == 0 {
		return nil
	}
	stored := &storedBody{SHA256: BodyHash(body), Size: len(body)}
	if utf8.Valid(body) {
		stored.Text = string(body)
		return stored
	}
	stored.Base64 = base64.StdEncoding.EncodeToString(body)
	return stored
}

// decodeBody reads a body back from disk.
func decodeBody(stored *storedBody) []byte {
	if stored == nil {
		return nil
	}
	if stored.Base64 != "" {
		data, err := base64.StdEncoding.DecodeString(stored.Base64)
		if err != nil {
			return nil
		}
		return data
	}
	return []byte(stored.Text)
}

// toPersisted applies the redaction and serializes an exchange.
func toPersisted(ex Exchange) persistedExchange {
	timestamp := ex.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	return persistedExchange{
		ID:              ex.ID,
		SessionID:       ex.SessionID,
		Timestamp:       timestamp.UTC().Format(time.RFC3339Nano),
		Method:          strings.ToUpper(strings.TrimSpace(ex.Method)),
		URL:             RedactURL(ex.URL),
		Host:            HostOfURL(ex.URL),
		RequestHeaders:  RedactHeaders(ex.Headers),
		RequestBody:     encodeBody(RedactRequestBody(ex.RequestBody)),
		Status:          ex.Status,
		ResponseHeaders: RedactHeaders(ex.ResponseHeaders),
		ResponseBody:    encodeBody(ex.ResponseBody),
		DurationMs:      ex.DurationMs,
		SourceTool:      ex.SourceTool,
		Target:          RedactURL(ex.Target),
		ScopeAllowed:    ex.ScopeAllowed,
	}
}

// fromPersisted reads an exchange back from disk.
func fromPersisted(stored persistedExchange) Exchange {
	timestamp, _ := time.Parse(time.RFC3339Nano, stored.Timestamp)
	return Exchange{
		ID:              stored.ID,
		SessionID:       stored.SessionID,
		Timestamp:       timestamp,
		Method:          stored.Method,
		URL:             stored.URL,
		Headers:         stored.RequestHeaders,
		RequestBody:     decodeBody(stored.RequestBody),
		Status:          stored.Status,
		ResponseHeaders: stored.ResponseHeaders,
		ResponseBody:    decodeBody(stored.ResponseBody),
		DurationMs:      stored.DurationMs,
		SourceTool:      stored.SourceTool,
		Target:          stored.Target,
		ScopeAllowed:    stored.ScopeAllowed,
	}
}

// Record writes an exchange to the store.
//
// La request se guarda con las credenciales enmascaradas: el store sobrevive
// al engagement y no puede convertirse en un repositorio de tokens.
func (s *Store) Record(ex Exchange) error {
	ex.SessionID = strings.TrimSpace(ex.SessionID)
	if ex.SessionID == "" {
		return errors.New("traffic: missing session id: the exchange would never reach the Argos panels")
	}
	if ex.Timestamp.IsZero() {
		ex.Timestamp = time.Now().UTC()
	}
	if strings.TrimSpace(ex.ID) == "" {
		ex.ID = ExchangeID(ex)
	}
	dir := s.sessionDir(ex.SessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("traffic: cannot create the session directory: %w", err)
	}
	data, err := json.MarshalIndent(toPersisted(ex), "", "  ")
	if err != nil {
		return fmt.Errorf("traffic: cannot encode the exchange: %w", err)
	}
	path := filepath.Join(dir, sanitizeSegment(ex.ID)+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("traffic: cannot write the exchange: %w", err)
	}
	s.evict(ex.SessionID)
	return nil
}

// read loads one exchange from disk.
func (s *Store) read(path string) (Exchange, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Exchange{}, err
	}
	var stored persistedExchange
	if err := json.Unmarshal(data, &stored); err != nil {
		return Exchange{}, fmt.Errorf("traffic: cannot decode %s: %w", path, err)
	}
	return fromPersisted(stored), nil
}

// List returns the exchanges of a session that pass the filter, plus the
// total number of exchanges the session has.
//
// El listado viene en orden cronológico: es un historial.
func (s *Store) List(sessionID string, filter Filter) ([]Exchange, int) {
	dir := s.sessionDir(sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0
	}
	all := make([]Exchange, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		ex, err := s.read(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		all = append(all, ex)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Timestamp.Equal(all[j].Timestamp) {
			return all[i].ID < all[j].ID
		}
		return all[i].Timestamp.Before(all[j].Timestamp)
	})
	filtered := make([]Exchange, 0, len(all))
	for _, ex := range all {
		if ex.Matches(filter) {
			filtered = append(filtered, ex)
		}
	}
	return filtered, len(all)
}

// Get returns one exchange of a session.
func (s *Store) Get(sessionID, id string) (Exchange, bool) {
	if strings.TrimSpace(id) == "" {
		return Exchange{}, false
	}
	ex, err := s.read(filepath.Join(s.sessionDir(sessionID), sanitizeSegment(id)+".json"))
	if err != nil {
		return Exchange{}, false
	}
	return ex, true
}

// Diff compares two exchanges of a session.
func (s *Store) Diff(sessionID, aID, bID string) (DiffResult, error) {
	a, ok := s.Get(sessionID, aID)
	if !ok {
		return DiffResult{}, fmt.Errorf("traffic: exchange %q not found", aID)
	}
	b, ok := s.Get(sessionID, bID)
	if !ok {
		return DiffResult{}, fmt.Errorf("traffic: exchange %q not found", bID)
	}
	return DiffExchanges(a, b), nil
}

// Replay re-sends an exchange with the given overrides and returns the new
// response as an exchange.
//
// El reenvío sale del cliente atado al ScopeGuard (IP-pinning, rate limit y
// audit log encadenado) y el target nuevo se valida contra el scope ANTES
// de emitir la request: un override que apunte fuera de scope no genera
// ni un paquete.
//
// El store guarda las credenciales enmascaradas, así que un replay de una
// request autenticada tiene que reenviarlas explícitamente con el override
// `headers`.
func (s *Store) Replay(ctx context.Context, sessionID, id string, overrides Overrides) (Exchange, error) {
	original, ok := s.Get(sessionID, id)
	if !ok {
		return Exchange{}, fmt.Errorf("traffic: exchange %q not found", id)
	}
	if s.client == nil {
		return Exchange{}, errors.New("traffic: no scope-bound client configured: the replay cannot be issued")
	}

	method := strings.ToUpper(strings.TrimSpace(overrides.Method))
	if method == "" {
		method = original.Method
	}
	target := strings.TrimSpace(overrides.URL)
	if target == "" {
		target = original.URL
	}

	// El scope se valida antes de la request: si el override saca el replay
	// del alcance autorizado, no se emite nada.
	if s.scope != nil {
		if _, err := s.scope.ValidateTarget(ctx, target); err != nil {
			return Exchange{}, fmt.Errorf("SCOPE ENFORCEMENT: %w", err)
		}
	}

	body := original.RequestBody
	if overrides.HasBody() {
		body = overrides.Body
	}

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return Exchange{}, fmt.Errorf("traffic: cannot build the replay request: %w", err)
	}
	for name, values := range original.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	for name, value := range overrides.Headers {
		req.Header.Set(name, value)
	}
	if len(body) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	started := time.Now()
	resp, err := s.client.Do(req)
	if err != nil {
		return Exchange{}, fmt.Errorf("traffic: the replay request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	replayed := Exchange{
		ID:              "",
		SessionID:       sessionID,
		Timestamp:       time.Now().UTC(),
		Method:          method,
		URL:             target,
		Headers:         req.Header.Clone(),
		RequestBody:     body,
		Status:          resp.StatusCode,
		ResponseHeaders: resp.Header.Clone(),
		ResponseBody:    responseBody,
		DurationMs:      time.Since(started).Milliseconds(),
		SourceTool:      original.SourceTool,
		Target:          original.Target,
		ScopeAllowed:    true,
	}
	if replayed.SourceTool == "" {
		replayed.SourceTool = "web.replay"
	}
	replayed.ID = ExchangeID(replayed)
	if err := s.Record(replayed); err != nil {
		return Exchange{}, err
	}
	return replayed, nil
}

// evict drops the oldest exchanges of a session when it grows past the cap.
func (s *Store) evict(sessionID string) {
	dir := s.sessionDir(sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	limit := s.maxExchanges
	if limit <= 0 {
		limit = DefaultMaxExchanges
	}
	if len(paths) <= limit {
		return
	}
	type aged struct {
		path      string
		timestamp time.Time
	}
	items := make([]aged, 0, len(paths))
	for _, path := range paths {
		ex, err := s.read(path)
		if err != nil {
			continue
		}
		items = append(items, aged{path: path, timestamp: ex.Timestamp})
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].timestamp.Before(items[j].timestamp)
	})
	for i := 0; i < len(items)-limit; i++ {
		_ = os.Remove(items[i].path)
	}
}

// HostOfURL returns the hostname of a URL, lowercased.
func HostOfURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}
