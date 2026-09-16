package harden

// notDumpable is RLIMIT_CORE-only on macOS: 04 §11.6 records that the
// dumpable flag has no equivalent there.
func notDumpable() error { return nil }
