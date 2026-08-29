package scanner

import (
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func event(t *testing.T, body *m1pv1.Event_Usage) (*m1pv1.Event, uuid.UUID) {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return &m1pv1.Event{
		EventId:    id[:],
		Seq:        1,
		OccurredAt: timestamppb.Now(),
		Body:       body,
	}, id
}

func TestHighConfidenceClassesHit(t *testing.T) {
	cases := []struct {
		class string
		value string
	}{
		{"aws_access_key_id", "export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"},
		{"github_token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
		{"slack_token", "xoxb-1234567890-abcdefghij"},
		{"stripe_secret_key", "sk_live_abcdefghijklmnopqrst"},
		{"anthropic_api_key", "sk-ant-api03-abcdefghijklmnopqrst"},
		{"private_key_block", "-----BEGIN OPENSSH PRIVATE KEY-----\nxxx"},
		{"google_api_key", "AIzaSyA1234567890abcdefghijklmnopqrstuv"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
	}
	for _, tc := range cases {
		t.Run(tc.class, func(t *testing.T) {
			ev, id := event(t, &m1pv1.Event_Usage{Usage: &m1pv1.Usage{ServiceTier: tc.value}})
			hits := ScanBatch(&m1pv1.Batch{Events: []*m1pv1.Event{ev}})
			if len(hits) == 0 {
				t.Fatalf("class %s did not hit on %q", tc.class, tc.value)
			}
			if hits[0].Class != tc.class {
				t.Fatalf("want class %s, got %s", tc.class, hits[0].Class)
			}
			if hits[0].EventID != id {
				t.Fatalf("hit must name the event: want %s got %s", id, hits[0].EventID)
			}
		})
	}
}

// Precision matters: quarantining ordinary agent traffic would train tenants
// to ignore quarantines (05 §2.3's alert only pages if it is rare).
func TestOrdinaryStringsDoNotHit(t *testing.T) {
	for _, s := range []string{
		"", "standard", "claude-sonnet-4-6", "https://api.anthropic.com/v1/messages",
		"error: connection refused at 10.0.0.1:5432",
		"AKIA is the AWS prefix", // prefix without the 16-char body
		"user@example.com",
	} {
		ev, _ := event(t, &m1pv1.Event_Usage{Usage: &m1pv1.Usage{ServiceTier: s}})
		if hits := ScanBatch(&m1pv1.Batch{Events: []*m1pv1.Event{ev}}); len(hits) != 0 {
			t.Fatalf("false positive on %q: %+v", s, hits)
		}
	}
}

// The walk is protoreflect-recursive: a secret in a NESTED message's string
// field (not a top-level one) must still hit.
func TestNestedStringFieldsScanned(t *testing.T) {
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	ev := &m1pv1.Event{
		EventId: id[:],
		Seq:     1,
		Body: &m1pv1.Event_GuardDecision{GuardDecision: &m1pv1.GuardDecision{
			ReasonCode: "leaked ghp_abcdefghijklmnopqrstuvwxyz0123456789 in a reason",
		}},
	}
	if hits := ScanBatch(&m1pv1.Batch{Events: []*m1pv1.Event{ev}}); len(hits) != 1 {
		t.Fatalf("nested string field not scanned: %+v", hits)
	}
}
