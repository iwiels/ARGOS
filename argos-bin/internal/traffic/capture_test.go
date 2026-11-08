package traffic

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

type captureTestDoer struct{}

func (captureTestDoer) Do(*http.Request) (*http.Response, error) { return nil, nil }

type captureTestBody struct {
	*bytes.Reader
	closed bool
}

func (b *captureTestBody) Close() error {
	b.closed = true
	return nil
}

func TestCapturePreservesResponseBodyAfterCaptureLimit(t *testing.T) {
	want := []byte(strings.Repeat("x", maxBodySize+37))
	originalBody := &captureTestBody{Reader: bytes.NewReader(want)}
	response := &http.Response{StatusCode: http.StatusOK, Body: originalBody}
	request, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}

	exchange := Capture(captureTestDoer{}, request, response, Meta{ScopeAllowed: true})
	afterCapture, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterCapture, want) {
		t.Fatalf("response body changed after capture: got %d bytes, want %d", len(afterCapture), len(want))
	}
	if len(exchange.ResponseBody) != maxBodySize {
		t.Fatalf("captured response body has %d bytes, want the %d byte capture limit", len(exchange.ResponseBody), maxBodySize)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !originalBody.closed {
		t.Fatal("closing the captured response body did not close the original body")
	}
}
