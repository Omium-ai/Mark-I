// Package mail sends Mark 1's transactional email through Customer.io's App API (16-release L3): no template, click/open tracking off and message retention off, so an invite's #token is never rewritten into a tracking redirect nor kept in delivery history.
package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
)

const DefaultFrom = "noreply@mail.omium.ai"

// Message is one email; Headers ride as extra MIME headers (List-Unsubscribe).
type Message struct {
	To      string
	Subject string
	HTML    string
	Text    string
	Headers map[string]string
}

type CustomerIO struct {
	Key    string
	From   string
	Region string
	HTTP   *http.Client
}

func (c CustomerIO) endpoint() string {
	if c.Region == "eu" {
		return "https://api-eu.customer.io/v1/send/email"
	}
	return "https://api.customer.io/v1/send/email"
}

// Send answers Customer.io's delivery_id; a refusal carries the status and a bounded body, never the key.
func (c CustomerIO) Send(ctx context.Context, m Message) (string, error) {
	if a, err := mail.ParseAddress(m.To); err != nil || a.Name != "" || a.Address != m.To {
		return "", fmt.Errorf("mail: recipient must be exactly one bare address")
	}
	from := c.From
	if from == "" {
		from = DefaultFrom
	}
	body := map[string]any{
		"to": m.To, "identifiers": map[string]string{"email": m.To}, "from": from,
		"subject": m.Subject, "body": m.HTML, "body_plain": m.Text,
		"tracked": false, "disable_message_retention": true,
	}
	if len(m.Headers) > 0 {
		body["headers"] = m.Headers
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("customer.io: %d %s", resp.StatusCode, bytes.TrimSpace(out))
	}
	var ok struct {
		DeliveryID string `json:"delivery_id"`
	}
	_ = json.Unmarshal(out, &ok)
	return ok.DeliveryID, nil
}
