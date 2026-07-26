// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: Webhook; TECH(8]: go test,httptest]
// @purpose Verify WebhookChannel delivery against a local httptest server: JSON POST, envelope
//
//	fields, optional HMAC signature, and error cases (missing url, non-2xx).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, webhook, channel, httptest, json, hmac, signature
// STRUCTURE: ▶ ┌httptest┐ → ○ Deliver(url=server) → 〈2xx? sig? fields?〉 → ⎋ assert
package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestWebhookChannel_Deliver(t *testing.T) {
	var (
		gotMethod, gotCT, gotSig string
		rawBody                  []byte
		mu                       sync.Mutex
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotSig = r.Header.Get("X-VMPulse-Signature")
		rawBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch := &WebhookChannel{}
	msg := Message{Severity: "critical", RuleName: "down", CheckType: "tcp", CheckID: 7,
		Title: "tcp is critical", Body: "status=critical"}
	err := ch.Deliver(context.Background(), map[string]any{
		"url": srv.URL, "secret": "s3cr3t",
	}, msg)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotMethod != http.MethodPost {
		t.Fatalf("method want POST, got %s", gotMethod)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type want application/json, got %s", gotCT)
	}
	// Envelope fields (parse the captured raw body).
	var body map[string]any
	if err := json.Unmarshal(rawBody, &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["source"] != "vmpulse" || body["severity"] != "critical" ||
		body["title"] != "tcp is critical" || body["rule"] != "down" {
		t.Fatalf("unexpected envelope: %+v", body)
	}
	// HMAC signature must equal sha256(secret, rawBody) — computed over the EXACT bytes sent.
	mac := hmac.New(sha256.New, []byte("s3cr3t"))
	mac.Write(rawBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature mismatch:\n got %s\nwant %s", gotSig, want)
	}
}

func TestWebhookChannel_NoSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ch := &WebhookChannel{}
	// No secret -> no signature header; still delivers.
	if err := ch.Deliver(context.Background(), map[string]any{"url": srv.URL}, Message{}); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
}

func TestWebhookChannel_Errors(t *testing.T) {
	ch := &WebhookChannel{}
	// Missing url.
	if err := ch.Deliver(context.Background(), map[string]any{}, Message{}); err == nil {
		t.Fatal("expected error for missing url")
	}
	// Non-2xx response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := ch.Deliver(context.Background(), map[string]any{"url": srv.URL}, Message{}); err == nil {
		t.Fatal("expected error for non-2xx")
	}
}
