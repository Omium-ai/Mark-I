package harden

import (
	"errors"
	"testing"
)

// The Windows arm's whole contract: a named refusal, never a silent Ok that
// would make NFR-SECURITY-002 a claim that is false on exactly one platform.
func TestApplyIsNamedRefusal(t *testing.T) {
	if err := Apply(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Apply() = %v, want ErrUnsupported", err)
	}
}
