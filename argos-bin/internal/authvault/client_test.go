package authvault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const profileID = "auth_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestClientUsesLocalAuthenticatedBridgeAndRetriesUnavailableAddresses(t *testing.T) {
	var methods []string
	var values []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer vault-token" {
			t.Errorf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}
		methods = append(methods, r.Method)
		if r.Method == http.MethodPut {
			var payload struct {
				Value string `json:"value"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode payload: %v", err)
			}
			values = append(values, payload.Value)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":"cookie=session-secret"}`))
	}))
	defer server.Close()

	client := NewClient([]string{"http://127.0.0.1:1", server.URL}, "vault-token")
	if err := client.Put(context.Background(), profileID, "cookie=session-secret"); err != nil {
		t.Fatal(err)
	}
	value, err := client.Get(context.Background(), profileID)
	if err != nil || value == nil || *value != "cookie=session-secret" {
		t.Fatalf("Get() = %v, %v", value, err)
	}
	if err := client.Delete(context.Background(), profileID); err != nil {
		t.Fatal(err)
	}
	if strings.Join(methods, ",") != "PUT,GET,DELETE" {
		t.Fatalf("methods = %v", methods)
	}
	if len(values) != 1 || values[0] != "cookie=session-secret" {
		t.Fatalf("stored values = %v", values)
	}
}

func TestClientRejectsPublicEndpointWithoutSendingToken(t *testing.T) {
	client := NewClient([]string{"http://vault.example.com"}, "vault-token")
	if _, err := client.Get(context.Background(), profileID); err == nil || err.Error() != "secure vault is unavailable" {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestClientReturnsNilForUnknownSecret(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client := NewClient([]string{server.URL}, "vault-token")
	value, err := client.Get(context.Background(), "auth_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil || value != nil {
		t.Fatalf("Get() = %v, %v", value, err)
	}
}
