// Package traffic guarda el tráfico HTTP de un engagement para que el
// auditor pueda volver a ver la request exacta que una tool emitió,
// compararla con una segunda respuesta y reenviarla con una modificación.
//
// Es el precedente de `internal/artifact`: el binario Go escribe el store en
// disco (<memoryDir>/traffic/<sessionID>/<exchangeID>.json) y el backend lo
// indexa en la base para la UI. El store en disco es la única fuente de
// verdad; la tabla SQL es un caché de lectura.
//
// Lo que este paquete NO hace es emitir tráfico: todo request sale del
// cliente atado al ScopeGuard (IP-pinning, rate limit y audit log
// encadenado). Un cliente propio se saltaría el control de alcance, así que
// el replay recibe el cliente ya atado desde afuera.
package traffic

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Exchange es una request HTTP y su respuesta, tal como la vio la tool.
//
// Los cuerpos son los que el servidor devolvió (o el que la tool envió), y
// las cabeceras ya vienen enmascaradas cuando el exchange se persistió: el
// store nunca guarda credenciales en claro.
type Exchange struct {
	ID              string
	SessionID       string
	Timestamp       time.Time
	Method          string
	URL             string
	Headers         map[string][]string
	RequestBody     []byte
	Status          int
	ResponseHeaders map[string][]string
	ResponseBody    []byte
	DurationMs      int64
	SourceTool      string
	Target          string
	ScopeAllowed    bool
}

// Filter acota el historial de una sesión.
//
// Los cuatro campos son opcionales: un filtro vacío devuelve todo el
// tráfico de la sesión.
type Filter struct {
	Host       string
	Method     string
	Status     string
	SourceTool string
}

// Overrides son las modificaciones de un replay: qué método, qué URL, qué
// cabeceras y qué body usa la request reenviada.
//
// Un campo vacío significa "usar el valor del exchange original".
type Overrides struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// HasBody reports whether the override replaces the body.
func (o Overrides) HasBody() bool { return o.Body != nil }

// ExchangeID derives a stable identifier for an exchange.
//
// El hash incluye el timestamp con nanosegundos: dos requests idénticas
// seguidas siguen siendo dos exchanges distintos.
func ExchangeID(ex Exchange) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		ex.SessionID,
		strings.ToUpper(ex.Method),
		ex.URL,
		ex.Timestamp.UTC().Format(time.RFC3339Nano),
		BodyHash(ex.RequestBody),
		BodyHash(ex.ResponseBody),
	}, "|")))
	return "ex_" + hex.EncodeToString(sum[:])[:16]
}

// BodyHash returns the hex sha256 of a body.
//
// El hash se guarda junto al body para comparar dos responses sin releerlos
// enteros: si los hashes coinciden, los bodies son idénticos.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// HostOf returns the host of the URL of an exchange, lowercased.
func HostOf(ex Exchange) string {
	host := HostOfURL(ex.URL)
	if host == "" {
		return strings.ToLower(strings.TrimSpace(ex.Target))
	}
	return host
}

// Matches reports whether an exchange passes a filter.
func (ex Exchange) Matches(f Filter) bool {
	if f.Host != "" && !strings.Contains(HostOf(ex), strings.ToLower(f.Host)) {
		return false
	}
	if f.Method != "" && !strings.EqualFold(f.Method, ex.Method) {
		return false
	}
	if f.Status != "" && !statusMatches(f.Status, ex.Status) {
		return false
	}
	if f.SourceTool != "" && !strings.EqualFold(f.SourceTool, ex.SourceTool) {
		return false
	}
	return true
}

// statusMatches accepts an exact status ("404") or a class ("4xx").
func statusMatches(filter string, status int) bool {
	filter = strings.TrimSpace(strings.ToLower(filter))
	if filter == "" {
		return true
	}
	if len(filter) == 3 && strings.HasSuffix(filter, "xx") {
		class := filter[0]
		if class < '0' || class > '9' {
			return false
		}
		return int(status/100) == int(class-'0')
	}
	return filter == strconv.Itoa(status)
}
