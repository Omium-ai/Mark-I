//go:build darwin

package anchors

import (
	"errors"
	"os"
	"testing"
)

// TestSeatbeltProfile pins the profile text sandbox-exec is handed: allow-default, network* denied, writes confined to the two realpath'd dirs plus /dev/null, quotes escaped.
func TestSeatbeltProfile(t *testing.T) {
	got := seatbelt([]string{`/private/tmp/w"t`, "/private/tmp/scratch"})
	want := "(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n" +
		"(allow file-write* (subpath \"/private/tmp/w\\\"t\") (subpath \"/private/tmp/scratch\") (literal \"/dev/null\"))\n"
	if got != want {
		t.Fatalf("profile:\n%s\nwant:\n%s", got, want)
	}
}

func TestStripSandboxExecWarning(t *testing.T) {
	warn := "WARNING: sandbox-exec is deprecated. Consider adopting the App Sandbox instead.\n"
	for in, want := range map[string]string{
		warn + "tool: boom\n": "tool: boom\n",
		warn:                  "",
		"tool: boom\n" + warn: "tool: boom\n" + warn, // only the leading line is the sandbox's
		"":                    "",
	} {
		if got := string(stripSandboxExecWarning([]byte(in))); got != want {
			t.Errorf("strip(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDarwinSandboxRefusesWithoutSandboxExec: absence is a named refusal, never a degraded run.
func TestDarwinSandboxRefusesWithoutSandboxExec(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	_, statErr := os.Stat(sandboxExec)
	if present := statErr == nil; sb.FSConfined() != present || sb.Status().Available != present {
		t.Fatalf("sandbox-exec present=%v but FSConfined=%v Status=%+v", present, sb.FSConfined(), sb.Status())
	}
	sb.reason = "forced"
	if st := sb.Status(); sb.FSConfined() || st.Available || st.Reason != "forced" {
		t.Fatalf("refusing sandbox reports %+v", st)
	}
	if _, err := sb.Run(t.Context(), probeSpec(t, t.TempDir(), "env", nil)); !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("run without sandbox-exec: %v, want ErrSandboxUnavailable", err)
	}
}
