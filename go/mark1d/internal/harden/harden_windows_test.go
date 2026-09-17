package harden

import "testing"

// The Windows arm's whole contract: WER's user-mode dump is declined for this exe and Apply
// says so with a nil error — the daemon must boot on this leg (the v0.1.0 build never did).
func TestApplyExcludesThisExeFromWER(t *testing.T) {
	if err := Apply(); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
}
