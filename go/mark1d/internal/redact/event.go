// The event-shaped door of the admit axis: capture.RedactFunc's Go
// implementation (04 §2.0 redactAdmit). Secrets ride the wire in string
// fields (prompts, tool output, model/tier/id text); bytes fields in m1p.v1
// are structural identifiers (session_id, event_id, idem_key) — same field
// discipline as controld's ingest twin, which also walks StringKind only.
package redact

import (
	"errors"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ErrQuarantine: the scanner refused or failed on some field — the caller
// must quarantine the WHOLE event (capture accounts it Dropped{LOCAL_QUARANTINE}),
// never admit it raw (F-35).
var ErrQuarantine = errors.New("redact: event quarantined by the admit axis")

// RedactEvent rewrites every flagged span in ev's string fields in place —
// BEFORE the seq stamp and the spool append (04 §2.0: stage order is
// load-bearing). Any error ⇒ quarantine; there is no bypass parameter.
func (s *Scanner) RedactEvent(ev *m1pv1.Event) error {
	return s.redactMessage(ev.ProtoReflect())
}

func (s *Scanner) redactMessage(m protoreflect.Message) error {
	var walkErr error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList():
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				nv, err := s.redactValue(fd, list.Get(i))
				if err != nil {
					walkErr = err
					return false
				}
				if nv.IsValid() {
					list.Set(i, nv)
				}
			}
		case fd.IsMap():
			// Keys collected before mutation: protoreflect leaves Set-during-
			// Range undefined for maps.
			mv := v.Map()
			var keys []protoreflect.MapKey
			mv.Range(func(k protoreflect.MapKey, _ protoreflect.Value) bool {
				keys = append(keys, k)
				return true
			})
			for _, k := range keys {
				nv, err := s.redactValue(fd.MapValue(), mv.Get(k))
				if err != nil {
					walkErr = err
					return false
				}
				if nv.IsValid() {
					mv.Set(k, nv)
				}
			}
		default:
			nv, err := s.redactValue(fd, v)
			if err != nil {
				walkErr = err
				return false
			}
			if nv.IsValid() {
				m.Set(fd, nv)
			}
		}
		return true
	})
	return walkErr
}

// redactValue returns the replacement value (invalid Value = unchanged), or
// ErrQuarantine when the scanner failed internally.
func (s *Scanner) redactValue(fd protoreflect.FieldDescriptor, v protoreflect.Value) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		str := v.String()
		if str == "" {
			return protoreflect.Value{}, nil
		}
		out, outcome, _ := s.Admit([]byte(str))
		switch outcome {
		case Clean:
			return protoreflect.Value{}, nil
		case Redacted:
			return protoreflect.ValueOfString(string(out)), nil
		default:
			return protoreflect.Value{}, ErrQuarantine
		}
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return protoreflect.Value{}, s.redactMessage(v.Message())
	default:
		return protoreflect.Value{}, nil
	}
}
