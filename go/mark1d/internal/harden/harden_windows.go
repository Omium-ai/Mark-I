package harden

import "errors"

// ErrUnsupported is the Windows answer, named so the caller can decide: there
// is no rlimit and no dumpable flag, and crash dumps are Windows Error
// Reporting's. The WER exclusion (WerAddExcludedApplication, 04 §11.6) is
// built for the Rust edge processes in rust/mark1-harden and not here, because
// mark1d has no Windows fabric listener yet (NFR-PORTABILITY-002, D-CA) and
// cannot run past main on that leg. CEILING: even with the exclusion, a
// kernel/complete-memory dump can still image the process (10 §4.2).
var ErrUnsupported = errors.New("harden: no core-dump suppression on windows (dumps are WER; 04 §11.6)")

// Apply is a no-op that says so.
func Apply() error { return ErrUnsupported }
