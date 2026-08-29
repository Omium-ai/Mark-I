// Package scanner is stage 7 of the ingest pipeline: the pre-egress secret
// scan (05 §2.1). It is an INDEPENDENT second ruleset from the edge's
// mark1-redact — different pattern source, different review cadence — so two
// teams' mistakes have to coincide for a secret to pass (08 §2.1: client-side
// redaction never gets to be the last line).
//
// A high-confidence hit FLAGS the batch: the caller quarantines it whole
// (05 §2.3), it never silently strips — stripping would ack bytes we did not
// land, and the landing object must stay byte-identical to what was sent.
package scanner

import (
	"regexp"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
)

// Hit names what was found and in which event — event_ids feed the 202
// response's quarantined[] list (08 §2.4); the matched text itself is never
// logged, echoed, or stored outside the quarantine object.
type Hit struct {
	EventID uuid.UUID
	Class   string
}

// rule: high-confidence patterns only. False positives quarantine a customer
// batch (recoverable via triage release, 05 §2.3); false negatives put a
// secret in the replay log forever — so the set skews conservative-precise:
// structured prefixes and key blocks, no entropy guessing.
type rule struct {
	class string
	re    *regexp.Regexp
}

var rules = []rule{
	{"aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,250}\b`)},
	{"stripe_secret_key", regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{20,247}\b`)},
	{"anthropic_api_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{"openai_api_key", regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{20,}\b`)},
	{"private_key_block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
}

// ScanBatch walks every string field of every event (05 §2.1 stage 7),
// recursively through nested messages, via protoreflect — so a new event
// family is scanned the day it exists, with no per-family plumbing to forget.
func ScanBatch(b *m1pv1.Batch) []Hit {
	var hits []Hit
	for _, ev := range b.GetEvents() {
		eventID, err := uuid.FromBytes(ev.GetEventId())
		if err != nil {
			// Invariant stage 6 already rejected unparseable event_ids;
			// belt-and-suspenders: a hit with no id still flags the batch.
			eventID = uuid.Nil
		}
		for _, class := range scanMessage(ev.ProtoReflect()) {
			hits = append(hits, Hit{EventID: eventID, Class: class})
		}
	}
	return hits
}

// scanMessage returns the classes hit anywhere in m's string fields.
func scanMessage(m protoreflect.Message) []string {
	var classes []string
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList():
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				classes = append(classes, scanValue(fd, list.Get(i))...)
			}
		case fd.IsMap():
			mv := v.Map()
			mv.Range(func(_ protoreflect.MapKey, mval protoreflect.Value) bool {
				classes = append(classes, scanValue(fd.MapValue(), mval)...)
				return true
			})
		default:
			classes = append(classes, scanValue(fd, v)...)
		}
		return true
	})
	return classes
}

func scanValue(fd protoreflect.FieldDescriptor, v protoreflect.Value) []string {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return scanString(v.String())
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return scanMessage(v.Message())
	default:
		return nil
	}
}

func scanString(s string) []string {
	if s == "" {
		return nil
	}
	var classes []string
	for _, r := range rules {
		if r.re.MatchString(s) {
			classes = append(classes, r.class)
		}
	}
	return classes
}

// Classes exposes the rule classes for the scanner_hits_total{class} metric's
// documentation; the ruleset itself stays private.
func Classes() []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.class
	}
	return out
}

// compile-time proof the generated types are what we walk.
var _ proto.Message = (*m1pv1.Batch)(nil)
