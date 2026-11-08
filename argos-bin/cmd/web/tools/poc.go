package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
)

// pocSnippetChars is the size of the fragment of the original body that
// travels with the PoC: enough to compare the response without persisting
// the whole body.
const pocSnippetChars = 2048

// pocRecord is the Go mirror of the TS PocRecord
// (packages/core/src/security/poc.ts).
//
// The canonical Finding struct has no field for the proof of concept — and it
// must not grow one, because the contract is shared with the rest of the
// scanners — so the PoC travels inside the evidence, under "poc". The backend
// lifts it from there into the `poc` column of the finding and the re-test
// engine replays it.
type pocRecord struct {
	Kind     string            `json:"kind"`
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
	Payload  string            `json:"payload,omitempty"`
	Matcher  pocMatcher        `json:"matcher"`
	Baseline *pocBaseline      `json:"baseline,omitempty"`
}

// pocMatcher is the Go mirror of the TS PocMatcher: it says how the response
// of the replay is compared with the original one.
type pocMatcher struct {
	Kind     string `json:"kind"`
	Expected any    `json:"expected,omitempty"`
	Needle   string `json:"needle,omitempty"`
	Header   string `json:"header,omitempty"`
	Ms       int    `json:"ms,omitempty"`
}

// pocBaseline is the Go mirror of the TS PocBaseline.
type pocBaseline struct {
	Status      int    `json:"status"`
	BodyDigest  string `json:"bodyDigest,omitempty"`
	BodySnippet string `json:"bodySnippet,omitempty"`
}

// pocMatcherBodyAbsent fires when the needle is no longer reflected.
func pocMatcherBodyAbsent(needle string) pocMatcher {
	return pocMatcher{Kind: "body_absent", Needle: needle}
}

// pocMatcherValueAbsent fires when the reflected value is no longer there.
func pocMatcherValueAbsent(needle string) pocMatcher {
	return pocMatcher{Kind: "value_absent", Needle: needle}
}

// pocMatcherBodyChanged fires when the response differs from the original.
func pocMatcherBodyChanged() pocMatcher {
	return pocMatcher{Kind: "body_changed"}
}

// pocMatcherTimingUnder fires when the response is no longer delayed.
func pocMatcherTimingUnder(ms int) pocMatcher {
	return pocMatcher{Kind: "timing_under", Ms: ms}
}

// pocMatcherStatus fires when the endpoint answers with the status that
// proves the vulnerability.
func pocMatcherStatus(expected ...int) pocMatcher {
	if len(expected) == 1 {
		return pocMatcher{Kind: "status", Expected: expected[0]}
	}
	return pocMatcher{Kind: "status", Expected: expected}
}

// pocDigest is the SHA-256 of a body: the same hash the backend computes, so
// both sides compare the same thing.
func pocDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// pocSnippet is the fragment of the original body that travels with the PoC.
func pocSnippet(body string) string {
	if len(body) <= pocSnippetChars {
		return body
	}
	return body[:pocSnippetChars]
}

// pocBaselineOf builds the baseline of a PoC from the original response.
func pocBaselineOf(status int, body string) *pocBaseline {
	return &pocBaseline{
		Status:      status,
		BodyDigest:  pocDigest(body),
		BodySnippet: pocSnippet(body),
	}
}

// attachPoc stores the proof of concept inside the evidence of a finding.
func attachPoc(evidence map[string]any, poc *pocRecord) {
	if evidence == nil || poc == nil {
		return
	}
	evidence["poc"] = poc
}

// pocRequestOf describes the request of a PoC: the method, the URL, the body
// and the headers that reproduce it.
type pocRequestOf struct {
	Method  string
	URL     string
	Body    string
	Headers map[string]string
}

// httpRequestToPoc describes an *http.Request as the replayable request of a
// PoC.
func httpRequestToPoc(req *http.Request) (pocRequestOf, bool) {
	if req == nil || req.URL == nil {
		return pocRequestOf{}, false
	}
	out := pocRequestOf{
		Method:  strings.ToUpper(req.Method),
		URL:     req.URL.String(),
		Headers: map[string]string{},
	}
	for name, values := range req.Header {
		if len(values) > 0 {
			out.Headers[name] = values[0]
		}
	}
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err == nil {
			out.Body = string(raw)
		}
	}
	return out, true
}
