package tools

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/iwiels/argos-auditor/argos-bin/internal/guard"
	"github.com/iwiels/argos-auditor/argos-bin/internal/scope"
)

// BreakerEvent is the record of a circuit-breaker verdict.
//
// It is emitted on every degradation and on every abort: a circuit breaker
// that nobody can see is worse than no circuit breaker, because the operator
// cannot tell the difference between "the scan found nothing" and "the scan
// was stopped to protect the target".
type BreakerEvent struct {
	Time   time.Time   `json:"time"`
	Tool   string      `json:"tool"`
	Target string      `json:"target"`
	Action string      `json:"action"`
	Reason string      `json:"reason"`
	Stats  guard.Stats `json:"stats"`
}

var (
	breakerMu sync.Mutex
	// sessionBreakers holds one breaker per engagement scope. The scope guard
	// is the identity of the engagement, so the breaker is shared by every
	// tool of the session and never leaks into another one.
	sessionBreakers = map[breakerKey]*guard.Breaker{}
	// breakerAuditor is the sink that receives the breaker events. The
	// wiring in tools.go can point it at the chained audit log of the
	// engagement; until then every event is written to the structured log.
	breakerAuditor func(env *Env, event BreakerEvent)
)

type breakerKey struct {
	sessionID string
	scope     *scope.ScopeGuard
}

func keyForBreaker(env *Env) breakerKey {
	if env.SessionID != "" {
		return breakerKey{sessionID: env.SessionID}
	}
	return breakerKey{scope: env.Scope}
}

// SessionBreaker returns the circuit breaker of the engagement.
//
// It is created lazily and shared by every tool that runs under the same
// scope guard, so an abort decided by one tool is visible to the next one:
// once the target is degraded, the session does not keep hammering it.
func SessionBreaker(env *Env) *guard.Breaker {
	if env == nil {
		return guard.New(guard.Options{})
	}
	key := keyForBreaker(env)
	breakerMu.Lock()
	defer breakerMu.Unlock()
	if breaker, ok := sessionBreakers[key]; ok {
		return breaker
	}
	breaker := guard.New(guard.Options{})
	sessionBreakers[key] = breaker
	return breaker
}

// SetBreakerAuditor registers the sink that receives the breaker events.
//
// The chained audit log of the engagement lives behind the ScopeGuard, whose
// audit writer is not exported yet; the hook is the seam that lets the
// wiring in tools.go chain the events as soon as it is.
func SetBreakerAuditor(auditor func(env *Env, event BreakerEvent)) {
	breakerMu.Lock()
	defer breakerMu.Unlock()
	breakerAuditor = auditor
}

// auditBreakerToChain points the breaker events at the engagement's chained
// audit log, so a safety decision is as traceable as a request.
func auditBreakerToChain(env *Env, event BreakerEvent) {
	if env == nil || env.Scope == nil {
		return
	}
	status := "TRIPPED"
	if event.Action == guard.ActionDegrade {
		status = "DEGRADED"
	}
	env.Scope.LogAudit(event.Target, "", "", "CIRCUIT_BREAKER", status, map[string]any{
		"tool":   event.Tool,
		"action": event.Action,
		"reason": event.Reason,
		"stats":  event.Stats,
	})
}

// emitBreakerEvent records a breaker verdict in the structured log and
// forwards it to the auditor.
func emitBreakerEvent(env *Env, tool, target string, decision guard.Decision, breaker *guard.Breaker) {
	if breaker == nil || decision.Action == guard.ActionNone {
		return
	}
	event := BreakerEvent{
		Time:   time.Now().UTC(),
		Tool:   tool,
		Target: target,
		Action: decision.Action,
		Reason: decision.Reason,
	}
	if breaker != nil {
		event.Stats = breaker.Stats()
	}
	if payload, err := json.Marshal(event); err == nil {
		log.Printf("argos-web: circuit-breaker %s", payload)
	} else {
		log.Printf("argos-web: circuit-breaker action=%s tool=%s target=%s reason=%s", event.Action, event.Tool, event.Target, event.Reason)
	}
	breakerMu.Lock()
	auditor := breakerAuditor
	breakerMu.Unlock()
	if auditor != nil {
		auditor(env, event)
	}
}
