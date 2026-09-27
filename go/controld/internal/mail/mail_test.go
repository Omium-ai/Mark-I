package mail

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func reply(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func TestSendTurnsTrackingAndRetentionOff(t *testing.T) {
	var got map[string]any
	var url, auth string
	c := CustomerIO{Key: "k", Region: "eu", HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		url, auth = r.URL.String(), r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		return reply(200, `{"delivery_id":"d1","queued_at":1}`), nil
	})}}
	id, err := c.Send(context.Background(), Message{To: "a@b.example", Subject: "s", HTML: "<p>h</p>", Text: "h", Headers: map[string]string{"List-Unsubscribe": "<https://x>"}})
	if err != nil || id != "d1" {
		t.Fatalf("send: %q %v", id, err)
	}
	if url != "https://api-eu.customer.io/v1/send/email" || auth != "Bearer k" {
		t.Fatalf("request: %s %s", url, auth)
	}
	if got["tracked"] != false || got["disable_message_retention"] != true || got["from"] != DefaultFrom || got["body_plain"] != "h" {
		t.Fatalf("body: %v", got)
	}
	if got["identifiers"].(map[string]any)["email"] != "a@b.example" || got["headers"].(map[string]any)["List-Unsubscribe"] != "<https://x>" {
		t.Fatalf("identifiers/headers: %v", got)
	}
}

func TestSendRefusalNamesStatusNotKey(t *testing.T) {
	c := CustomerIO{Key: "secret-key", HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.customer.io" {
			t.Errorf("default region host: %s", r.URL.Host)
		}
		return reply(401, `{"meta":{"error":"unauthorized"}}`), nil
	})}}
	_, err := c.Send(context.Background(), Message{To: "a@b.example"})
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "secret-key") {
		t.Fatalf("refusal: %v", err)
	}
}

// One bare recipient or nothing leaves: a list, a display name or a group never reaches Customer.io.
func TestSendRefusesAnythingButOneBareRecipient(t *testing.T) {
	c := CustomerIO{Key: "k", HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		t.Errorf("sent to Customer.io: %s", r.URL)
		return reply(200, `{}`), nil
	})}}
	for _, to := range []string{"a@b.example, c@d.example", "Eve <e@b.example>", "<e@b.example>", "team: a@b.example, c@d.example;", "", "nope"} {
		if _, err := c.Send(context.Background(), Message{To: to}); err == nil {
			t.Errorf("to %q was accepted", to)
		}
	}
}
