package adapters

import (
	"errors"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
)

// Redact runs the mark1-redact admit axis over b under key (the token's hash leg is
// HMAC(key, span)); n is the substitution count. The recording lane in go/mark1 reaches the
// rule table through this one door because internal/redact is module-private to mark1d.
// A quarantine is an error: the caller never writes the raw bytes.
func Redact(key, b []byte) (out []byte, n uint32, err error) {
	s, err := redact.NewScanner(key)
	if err != nil {
		return nil, 0, err
	}
	out, outcome, n := s.Admit(b)
	if outcome == redact.Quarantine {
		return nil, 0, errors.New("redact: quarantine, the scanner could not admit these bytes")
	}
	return out, n, nil
}
