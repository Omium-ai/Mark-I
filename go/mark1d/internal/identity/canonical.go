// Canonical receipt bytes — the Go rendering of the estate's canonical.py
// (vendored from core-services/recovery-orchestrator/app/receipts/canonical.py,
// copied 2026-08-29), with the mark1 domain prefix per 07's receipts section.
// NORMATIVE in the same sense the Python is: if these bytes and another
// implementation's ever disagree by one character, every origin signature the
// device minted reads as a forgery. conformance/vectors/receipt/ is the
// referee; nothing here is re-derivable from prose alone.

package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"unicode/utf16"
)

// DomainPrefix separates mark1 receipt signatures from every other signing
// domain, estate discipline kept: the trailing NUL stops "mark1-label-v1"
// from being a prefix of some future "mark1-label-v1x" scheme.
const DomainPrefix = "mark1-label-v1\x00"

// GenesisHash anchors seq 1: a chain has to start somewhere provable, and
// all-zeroes is a value no SHA-256 output will ever collide into by accident.
var GenesisHash [32]byte

// CanonicalJSON reproduces Python's
// json.dumps(v, sort_keys=True, separators=(",",":"), ensure_ascii=True)
// byte-for-byte. Accepted values are the JSON tree types a decoded payload
// has (nil, bool, string, json.Number, map[string]any, []any) plus Go integer
// scalars for payload construction. Any float — float64 from a stock
// json.Unmarshal, or a json.Number in non-integer form — is REFUSED:
// cross-language float rendering is not deterministic, so a float in a
// payload is a forgery generator (vectors README, "integers only").
func CanonicalJSON(v any) (string, error) {
	buf, err := appendCanonical(nil, v)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// CanonicalBytes is the signing input: DomainPrefix || CanonicalJSON(v).
func CanonicalBytes(v any) ([]byte, error) {
	buf, err := appendCanonical([]byte(DomainPrefix), v)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// ReceiptHash is SHA-256 over the SIGNING INPUT, prefix included —
// deliberately not over the JSON alone (estate canonical.py rule): a verifier
// that has recomputed the hash has, by construction, recomputed the exact
// bytes it must hand to the signature check, so there is no way to verify the
// chain against one serialisation and the signature against another.
func ReceiptHash(v any) ([32]byte, error) {
	buf, err := CanonicalBytes(v)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(buf), nil
}

func appendCanonical(buf []byte, v any) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return append(buf, "null"...), nil
	case bool:
		if t {
			return append(buf, "true"...), nil
		}
		return append(buf, "false"...), nil
	case string:
		return appendEscapedString(buf, t), nil
	case json.Number:
		// Strict integer grammar (optional '-', no leading zeros, no
		// '.', 'e', 'E'): json.Number carries source text verbatim, so
		// "1.0", "1e2" and "007" would otherwise ride straight into the
		// signing input as non-canonical forms Python never emits.
		if !integerForm(string(t)) {
			return nil, fmt.Errorf("identity: non-integer number %q in payload; receipts carry integers only (vectors README)", string(t))
		}
		return append(buf, string(t)...), nil
	case int:
		return fmt.Appendf(buf, "%d", t), nil
	case int64:
		return fmt.Appendf(buf, "%d", t), nil
	case uint64:
		return fmt.Appendf(buf, "%d", t), nil
	case []any:
		buf = append(buf, '[')
		for i, e := range t {
			if i > 0 {
				buf = append(buf, ',')
			}
			var err error
			if buf, err = appendCanonical(buf, e); err != nil {
				return nil, err
			}
		}
		return append(buf, ']'), nil
	case map[string]any:
		// Byte sort == code-point sort == Python's key order; the
		// "unicode" vector proves the three agree (vectors README).
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf = append(buf, '{')
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = appendEscapedString(buf, k)
			buf = append(buf, ':')
			var err error
			if buf, err = appendCanonical(buf, t[k]); err != nil {
				return nil, err
			}
		}
		return append(buf, '}'), nil
	case float64:
		return nil, fmt.Errorf("identity: float64 %v in payload; receipts carry integers only — decode with UseNumber (vectors README)", t)
	default:
		return nil, fmt.Errorf("identity: unsupported payload type %T", v)
	}
}

// appendEscapedString mirrors CPython's ensure_ascii escaper exactly: the
// five short escapes JSON defines (\b \t \n \f \r) plus \" and \\, \u00xx
// for the remaining controls, raw bytes for printable ASCII (0x20..0x7e),
// and lowercase \uxxxx — astral runes as surrogate PAIRS — for everything
// above 0x7e (including DEL, which Python escapes).
func appendEscapedString(buf []byte, s string) []byte {
	buf = append(buf, '"')
	for _, r := range s {
		switch r {
		case '"':
			buf = append(buf, '\\', '"')
		case '\\':
			buf = append(buf, '\\', '\\')
		case '\b':
			buf = append(buf, '\\', 'b')
		case '\t':
			buf = append(buf, '\\', 't')
		case '\n':
			buf = append(buf, '\\', 'n')
		case '\f':
			buf = append(buf, '\\', 'f')
		case '\r':
			buf = append(buf, '\\', 'r')
		default:
			switch {
			case r >= 0x20 && r <= 0x7e:
				buf = append(buf, byte(r))
			case r > 0xffff:
				hi, lo := utf16.EncodeRune(r)
				buf = fmt.Appendf(buf, `\u%04x\u%04x`, hi, lo)
			default:
				buf = fmt.Appendf(buf, `\u%04x`, r)
			}
		}
	}
	return append(buf, '"')
}

func integerForm(s string) bool {
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
		// "-0" is a form Python's int never prints; letting it through
		// would let two byte-distinct texts claim the same value.
		if s == "0" {
			return false
		}
	}
	if len(s) == 0 || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// DecodePayload parses stored payload text into the tree CanonicalJSON
// accepts, numbers kept as json.Number so 2^53+1 survives the round trip
// (the big_int vector exists to catch any f64 detour). Trailing bytes after
// the value are an error: "parses, plus garbage" must not re-canonicalise
// cleanly.
func DecodePayload(text []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("identity: trailing data after payload JSON")
	}
	return v, nil
}
