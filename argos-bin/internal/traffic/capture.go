package traffic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/iwiels/ARGOS/argos-bin/internal/env"
)

const (
	// CaptureEnv turns the traffic capture on.
	//
	// Por defecto está apagado: escribir el tráfico de cada scan a disco
	// costs I/O y guarda material sensible del engagement. El operador lo
	// enciende cuando va a hacer trabajo fino sobre las requests.
	CaptureEnv = "ARGOS_TRAFFIC_CAPTURE"
)

var captureWarnOnce sync.Once

// CaptureEnabled reports whether the operator enabled the traffic capture.
func CaptureEnabled() bool {
	return strings.TrimSpace(env.Get(CaptureEnv)) == "1"
}

// WarnCaptureEnabled logs, once per process, that the capture is on.
//
// Es un aviso y no un error: capturar el tráfico es una decisión del
// operador, pero tiene que saber que el store existe y que las
// credenciales quedan enmascaradas.
func WarnCaptureEnabled() {
	captureWarnOnce.Do(func() {
		log.Printf("argos-web: traffic capture is ON (%s=1): HTTP request and response bodies are persisted up to the capture limit; credential headers, URLs, and recognized request-body secrets are masked, while response bodies remain evidence", CaptureEnv)
	})
}

// Meta describes the context of a captured exchange.
type Meta struct {
	// SessionID is the Argos Session ID (ses_...).
	SessionID string
	// SourceTool is the tool that produced the traffic ("web.probe", …).
	SourceTool string
	// Target is the engagement target the request belongs to.
	Target string
	// Duration is how long the request took.
	Duration time.Duration
	// ScopeAllowed records that the target was inside the authorized scope.
	ScopeAllowed bool
}

// Capture builds an exchange out of a request and its response.
//
// El body de la respuesta se lee y se vuelve a dejar en su sitio: el caller
// sigue poder leerlo como si nadie lo hubiera tocado.
//
// El cliente va en la firma a propósito: un exchange sin cliente no puede
// declararse dentro del scope, porque nadie lo validó.
func Capture(client Doer, req *http.Request, resp *http.Response, meta Meta) Exchange {
	ex := Exchange{
		SessionID:    meta.SessionID,
		Timestamp:    time.Now().UTC(),
		SourceTool:   meta.SourceTool,
		Target:       meta.Target,
		ScopeAllowed: meta.ScopeAllowed && client != nil,
	}
	if meta.Duration > 0 {
		ex.DurationMs = meta.Duration.Milliseconds()
	}
	if req != nil {
		ex.Method = req.Method
		if req.URL != nil {
			ex.URL = req.URL.String()
		}
		ex.Headers = req.Header.Clone()
		ex.RequestBody = requestBody(req)
	}
	if resp != nil {
		ex.Status = resp.StatusCode
		ex.ResponseHeaders = resp.Header.Clone()
		if resp.Body != nil {
			originalBody := resp.Body
			body, _ := io.ReadAll(io.LimitReader(originalBody, maxBodySize))
			resp.Body = struct {
				io.Reader
				io.Closer
			}{Reader: io.MultiReader(bytes.NewReader(body), originalBody), Closer: originalBody}
			ex.ResponseBody = body
		}
	}
	return ex
}

// requestBody reads the body of a request without consuming it.
//
// http.NewRequest guarda una copia reproducible en GetBody cuando el body
// viene de un reader en memoria; si no, no hay forma de leerlo sin romper
// el request, así que se devuelve nil.
func requestBody(req *http.Request) []byte {
	if req == nil || req.GetBody == nil {
		return nil
	}
	reader, err := req.GetBody()
	if err != nil {
		return nil
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, maxBodySize))
	if err != nil {
		return nil
	}
	return body
}

// CaptureAndRecord captures an exchange and writes it to the store.
func CaptureAndRecord(store *Store, client Doer, req *http.Request, resp *http.Response, meta Meta) (Exchange, error) {
	ex := Capture(client, req, resp, meta)
	if store == nil {
		return ex, nil
	}
	if err := store.Record(ex); err != nil {
		return ex, err
	}
	return ex, nil
}

// Probe issues a scope-bound GET against the target and records the
// exchange in the store.
//
// Es el camino de las tools que no tienen la request y la response a mano
// porque delegan en un binario externo (httpx, tlsx): la tool hace su
// trabajo con su binario y, aparte, deja en el store una request
// reproducible que el auditor puede reenviar y comparar.
//
// La request sale del cliente atado al ScopeGuard, así que cuenta para el
// rate limit y para el audit log encadenado.
func Probe(ctx context.Context, store *Store, client Doer, target string, meta Meta) (Exchange, error) {
	if client == nil {
		return Exchange{}, errors.New("traffic: no scope-bound client configured: the probe cannot be issued")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Exchange{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")

	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Exchange{}, err
	}
	defer resp.Body.Close()

	meta.Duration = time.Since(started)
	meta.ScopeAllowed = true
	return CaptureAndRecord(store, client, req, resp, meta)
}
