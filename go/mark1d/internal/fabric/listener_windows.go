// The Windows half of 07 §5's transport endpoint, and it is a refusal.
//
// 07 §5 specifies a named pipe at \\.\pipe\omium-mark1-<user-SID> with a
// security descriptor granting only that SID. That is not a rename of the unix
// path: it needs the caller's SID, an explicitly-constructed DACL, and a pipe
// server that re-listens per connection. Approximating it — a TCP loopback
// listener, a pipe with a default descriptor — would put the fabric's whole
// threat model (other users on the same machine) on a control nobody wrote,
// while reporting success. So this refuses, which is the house rule the anchor
// registry already states: an unimplemented kind is refused, never faked.
//
// The refusal is what lets the windows-2022 CI leg stay armed. Before this
// file, the package simply did not compile there, so the leg was red for a
// reason that had already been decided and the OTHER portability regressions
// it exists to catch could not surface behind it.
package fabric

import (
	"errors"
	"net"
)

// ErrNoWindowsFabric is what every entry point here returns, exported so a
// caller can tell "not built yet on this platform" apart from "your machine is
// misconfigured" — the two deserve different words in `mark1 doctor`.
var ErrNoWindowsFabric = errors.New(
	"fabric: the M1PL local transport is not implemented on Windows yet — 07 §5's named pipe " +
		"(\\\\.\\pipe\\omium-mark1-<user-SID>) needs a per-SID security descriptor, and mark1d will not " +
		"substitute a weaker listener for it; run mark1d under WSL2 or on Linux/macOS")

func SocketPath() (string, error) { return "", ErrNoWindowsFabric }

func Listen(string) (net.Listener, error) { return nil, ErrNoWindowsFabric }
