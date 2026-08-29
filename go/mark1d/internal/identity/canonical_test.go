// Edge cases the vectors gesture at but do not enumerate: the escaping
// boundary rows (0x7e raw / 0x7f escaped — CPython escapes DEL), the
// number-form refusals, and code-point key ordering. Each expectation was
// checked against CPython's json.dumps before being frozen here.

package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustCanonical(t *testing.T, v any) string {
	t.Helper()
	s, err := CanonicalJSON(v)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	return s
}

func TestCanonicalStringEscaping(t *testing.T) {
	cases := []struct{ in, want string }{
		// DEL is ASCII but CPython's ensure_ascii escaper emits \u007f;
		// 0x7e is the last raw byte. 0x0b has no short escape in JSON.
		{"\x7f\x1f\x08\x0b\x0c", "\"\\u007f\\u001f\\b\\u000b\\f\""},
		{"~", "\"~\""},
		{"/", "\"/\""},                       // Python does not escape the solidus
		{"\U0001f600", "\"\\ud83d\\ude00\""}, // astral rune, surrogate pair, lowercase hex
		{"caf\u00e9", "\"caf\\u00e9\""},      // BMP non-ASCII
		{"a\"b\\c", "\"a\\\"b\\\\c\""},       // the two mandatory escapes
		{"\r\n\t", "\"\\r\\n\\t\""},          // short escapes, never \u000a etc.
	}
	for _, c := range cases {
		if got := mustCanonical(t, c.in); got != c.want {
			t.Errorf("CanonicalJSON(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestCanonicalNestedKeySort(t *testing.T) {
	v := map[string]any{
		"z":      map[string]any{"b": 1, "a": 2, "\u00e9": 3},
		"a":      []any{map[string]any{"y": nil, "x": true}},
		"\u00e0": "after-z", // code-point order: a < z < à (vectors README)
	}
	want := "{\"a\":[{\"x\":true,\"y\":null}],\"z\":{\"a\":2,\"b\":1,\"\\u00e9\":3},\"\\u00e0\":\"after-z\"}"
	if got := mustCanonical(t, v); got != want {
		t.Errorf("nested sort:\n got %s\nwant %s", got, want)
	}
}

func TestCanonicalNumberForms(t *testing.T) {
	// 2^53+1: exact in int64, silently rounded by any f64 detour.
	if got := mustCanonical(t, map[string]any{"big": int64(9007199254740993)}); got != "{\"big\":9007199254740993}" {
		t.Errorf("big int: %s", got)
	}
	if got := mustCanonical(t, json.Number("-42")); got != "-42" {
		t.Errorf("json.Number(-42): %s", got)
	}
	// Every non-integer or non-canonical numeric form is a refusal, not a
	// best-effort rendering (vectors README: a float is a forgery generator).
	for _, bad := range []any{
		float64(1.5), float64(1), // even a whole float64 is a decode-path smell
		json.Number("1.5"), json.Number("1e3"), json.Number("007"), json.Number("-0"), json.Number(""),
	} {
		if _, err := CanonicalJSON(bad); err == nil {
			t.Errorf("CanonicalJSON(%#v) must refuse", bad)
		}
	}
	// The refusal must reach through containers.
	if _, err := CanonicalJSON(map[string]any{"x": []any{float64(0.1)}}); err == nil {
		t.Error("nested float must refuse")
	}
}

func TestDecodePayloadRejectsTrailingData(t *testing.T) {
	if _, err := DecodePayload([]byte("{\"a\":1} {\"b\":2}")); err == nil {
		t.Error("trailing JSON value must not decode cleanly")
	}
	v, err := DecodePayload([]byte("{\"big\":9007199254740993}"))
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	// Round trip must not lose precision: UseNumber keeps the digits.
	if got := mustCanonical(t, v); !strings.Contains(got, "9007199254740993") {
		t.Errorf("big int lost in decode round trip: %s", got)
	}
}
