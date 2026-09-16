package memory

import "testing"

// One vector, two languages: python/intel/tests/test_memory_retrieve.py pins the same strings.
const (
	rawSignature = "Exit Code 1\n  FAIL test_x at /home/u/proj/y.py:12   sha 3fa9c2e71 C:\\Users\\me\\a.txt\nthird line is ignored"
	normalized   = "exit code 0 fail test_x at <path>:0 sha <hex> <path>"
	digest       = "2f79e42f04bbe23e9adbd014553c6a7fe2ec5c79272129862df66fdd3aa4f753"
)

func TestNormalizeSignatureAgreesWithPython(t *testing.T) {
	if got := NormalizeSignature(rawSignature); got != normalized {
		t.Fatalf("normalized %q, want %q", got, normalized)
	}
	if got := SignatureDigest(normalized); got != digest {
		t.Fatalf("digest %s, want %s", got, digest)
	}
}

func TestNormalizeSignatureRules(t *testing.T) {
	cases := map[string]string{
		"":                             "",
		"\n  \n":                       "",
		"A\nB\nC":                      "a b",
		"A\r\nB\rC":                    "a b",
		"deadbe facade 0xdeadbeef":     "deadbe facade 0xdeadbeef",
		"id a1b2c3 and 12 items":       "id <hex> and 0 items",
		"see /a/b.txt or /one":         "see <path> or /one",
		"Exit code 1\nFAIL x  y\tz\n!": "exit code 0 fail x y z",
	}
	for in, want := range cases {
		if got := NormalizeSignature(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'y'
	}
	if got := NormalizeSignature(string(long)); len(got) != signatureMaxChars {
		t.Fatalf("cap: %d chars", len(got))
	}
}

func TestTokensRoundsUp(t *testing.T) {
	for text, want := range map[string]uint32{"": 0, "abc": 1, "abcd": 1, "abcde": 2} {
		if got := Tokens(text); got != want {
			t.Errorf("Tokens(%q) = %d, want %d", text, got, want)
		}
	}
}
