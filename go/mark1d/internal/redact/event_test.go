package redact

import (
	"strings"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// TestRedactEventSubstitutesStringFields: a planted secret inside a nested
// string field is `⟨redacted:class:hash⟩` before the event ever reaches a
// spool append (04 §2.0 stage order), and clean fields are untouched.
func TestRedactEventSubstitutesStringFields(t *testing.T) {
	sc, err := NewScanner([]byte("test-tenant-redaction-key"))
	if err != nil {
		t.Fatal(err)
	}
	const secret = "AKIAIOSFODNN7EXAMPLE"
	ev := &m1pv1.Event{
		SessionId: make([]byte, 16),
		Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
			Model:       "claude-fable-5",
			ServiceTier: "key " + secret + " leaked",
		}},
	}
	if err := sc.RedactEvent(ev); err != nil {
		t.Fatalf("admit axis refused a redactable event: %v", err)
	}
	got := ev.GetUsage().GetServiceTier()
	if strings.Contains(got, secret) {
		t.Fatalf("planted secret survives in the event (CON-008): %q", got)
	}
	if !strings.Contains(got, "⟨redacted:api_key:") || !strings.HasPrefix(got, "key ") || !strings.HasSuffix(got, " leaked") {
		t.Fatalf("span-not-field substitution violated: %q", got)
	}
	if ev.GetUsage().GetModel() != "claude-fable-5" {
		t.Fatal("clean sibling field was mutated")
	}
}

// TestAdmitQuarantineOnPanic: the panic-caught leg — an internal failure maps
// to Quarantine, never to "no findings" (F-35). A nil-rule scanner is the
// cheapest deterministic way to make findAll unwind.
func TestAdmitQuarantineOnPanic(t *testing.T) {
	sc := &Scanner{rules: []compiledRule{{anchors: [][]byte{[]byte("x")}}}} // nil reAt ⇒ panic at confirm
	_, outcome, _ := sc.Admit([]byte("x marks the spot"))
	if outcome != Quarantine {
		t.Fatalf("internal failure returned %v, want Quarantine", outcome)
	}
}

// TestTokenCorrelation pins the in-tenant correlation property (04 §7.1):
// equal spans under one key yield byte-identical tokens; a different key
// yields a different hash leg.
func TestTokenCorrelation(t *testing.T) {
	a, _ := NewScanner([]byte("tenant-a"))
	b, _ := NewScanner([]byte("tenant-b"))
	span := []byte("AKIAIOSFODNN7EXAMPLE")
	first := string(a.token(ClassAPIKey, span))
	second := string(a.token(ClassAPIKey, span))
	if first != second {
		t.Fatal("equal spans under one key must correlate")
	}
	if first == string(b.token(ClassAPIKey, span)) {
		t.Fatal("tokens must not correlate across keys")
	}
}
