// Package off is the CLI half of 08 §7.6, the uncircumventable kill switch:
// write the OFF marker at the state root ATOMICALLY, then verify the daemon
// observed it when reachable. The marker path must byte-equal what
// go/mark1d/internal/off and rust/mark1-hookshim stat (<state>/OFF) — every
// gate checks it BEFORE reading any policy, bundle, or verdict cache, so no
// server or config state can re-enable gating while off. There is no server
// round-trip on the critical path: off works with the network down.
package off

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
)

type Options struct {
	Workspace string // scope label only until mark1d grows per-workspace markers
	All       bool
	Duration  time.Duration // 0 = until `mark1 on`

	// Test seams for the daemon-observation poll (mark1d checks the marker
	// once per second; 5s is five chances before we call it partial).
	Socket       string
	ObserveGrace time.Duration
	// Profile is the ADR-0013 host profile of the session this off acts for; nil
	// is provision.DefaultProfile. A declared host that owns the config surface has
	// nothing of ours to revert: reported as HostOwned (M1E-7107), not as a
	// partial off.
	Profile *provision.Profile
}

// Result is §7.6's --json shape. coverage_receipt_seq is minted by the
// receipt chain in mark1d; until that wiring lands the journal entry is the
// attributable record and the field is absent, never faked.
type Result struct {
	OK           bool   `json:"ok"`
	Scope        string `json:"scope"`
	ByteEquality bool   `json:"byte_equality"`
	Until        string `json:"until,omitempty"`
	Daemon       string `json:"daemon"` // "observed" | "not running" | "still capturing"
	// Reverted is additive to §7.6's shape: byte_equality is one bool for the
	// whole command, and a user whose file came back surgically rather than
	// verbatim deserves to know which file and why, not just `false`.
	Reverted    []Reverted `json:"reverted,omitempty"`
	NotReverted []string   `json:"not_reverted,omitempty"`
	// HostOwned is the M1E-7107 reason when the session's declared host owns the
	// config surface (ADR-0014 §4): nothing was reverted because nothing of
	// ours is there.
	HostOwned string `json:"host_owned,omitempty"`
	// StopGate: removed | not_opted_in | opted_in (removal failed, listed in NotReverted).
	StopGate string `json:"stop_gate"`
}

// Reverted is one fragment taken back out, in 08 §8.4's own vocabulary.
type Reverted = provision.Reverted

// marker is what lands in <state>/OFF. The daemon and shim only stat the
// file (existence IS the switch), so the content is free — it makes the off
// window auditable from the file itself.
type marker struct {
	Scope     string `json:"scope"`
	WrittenAt string `json:"written_at"`
	Until     string `json:"until,omitempty"`
}

func Run(env *cli.Env, opts Options) error {
	scope := "all"
	if opts.Workspace != "" && !opts.All {
		// ponytail: per-workspace off collapses to the global marker — the
		// daemon and shim only honor <state>/OFF today, and a kill switch
		// that under-kills is the one unacceptable failure. Narrowing the
		// scope is mark1d's per-workspace-marker row.
		scope = opts.Workspace
	}

	m := marker{Scope: scope, WrittenAt: time.Now().UTC().Format(time.RFC3339)}
	res := Result{OK: true, Scope: scope, ByteEquality: true}
	if opts.Duration > 0 {
		m.Until = time.Now().UTC().Add(opts.Duration).Format(time.RFC3339)
		res.Until = m.Until
	}

	socket := opts.Socket
	if socket == "" {
		if s, err := cli.SocketPath(); err == nil {
			socket = s
		}
	}
	// Reachability is sampled BEFORE the marker lands: afterwards a dead
	// socket is indistinguishable from a daemon that observed and closed.
	wasReachable := socket != "" && cli.DaemonReachable(socket)

	data, err := json.Marshal(m)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "encoding marker: %v", err)
	}
	// Atomic (temp + rename): the daemon's 1 Hz stat must never see a
	// half-written file it could mis-read as absent. Idempotent: rename
	// over an existing marker just refreshes its content.
	if err := cli.WriteFileAtomic(env.OffMarkerPath(), data, 0o600); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "writing OFF marker: %v", err)
	}

	res.Daemon = verifyDaemonObserved(socket, wasReachable, opts.ObserveGrace)

	// §7.6 step 2: revert every provisioned fragment through the §8.4 engine
	// that applied it. A manifest we cannot revert is LISTED as partial
	// (exit 1, §7.6) — never silently skipped. Reverting is defense in depth,
	// not the off mechanism: the shim hits the marker check and no-ops
	// regardless (08 §8.4 note), which is why a failed revert does not stop
	// the marker from landing above.
	profile := provision.DefaultProfile
	if opts.Profile != nil {
		profile = *opts.Profile
	}
	res.Reverted, res.NotReverted, res.HostOwned = provision.RevertUnless(profile, env.StateDir)
	// FR-POLICY-006: a paused install must not block; the exploration sibling (D-EF) is a contract, not an arming, and stays.
	res.StopGate = "not_opted_in"
	was := env.ReadOptIn().StopGate
	who := ""
	if u, err := user.Current(); err == nil {
		who = u.Username
	}
	switch err := env.UpdateOptIn(m.WrittenAt, who, func(a *cli.OptIn) { a.StopGate = false }); {
	case err != nil:
		res.StopGate = "opted_in"
		res.NotReverted = append(res.NotReverted, env.StopGateOptInPath())
	case was:
		res.StopGate = "removed"
	}
	for _, r := range res.Reverted {
		if !r.ByteEquality {
			res.ByteEquality = false
		}
	}
	if len(res.NotReverted) > 0 {
		res.ByteEquality = false
	}

	// §7.6 step 4: the disable window stays attributable. Journal locally;
	// the signed CoverageTransition receipt is mark1d's wiring row.
	if err := env.AppendCoverageTransition(map[string]any{
		"ts": m.WrittenAt, "kind": "disable", "scope": scope, "until": m.Until,
	}); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "journaling coverage transition: %v", err)
	}

	partial := len(res.NotReverted) > 0 || res.Daemon == "still capturing"
	res.OK = !partial
	emitErr := env.Emit(res, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "mark1 is OFF (scope: %s, daemon: %s)\n", scope, res.Daemon)
		for _, r := range res.Reverted {
			_, _ = fmt.Fprintf(w, "reverted      %s %s (%s)\n", r.Agent, r.Target, r.Kind)
		}
		for _, p := range res.NotReverted {
			_, _ = fmt.Fprintf(w, "NOT REVERTED: %s (run `mark1 doctor`)\n", p)
		}
		if res.HostOwned != "" {
			_, _ = fmt.Fprintf(w, "host          %s\n", res.HostOwned)
		}
		if res.StopGate == "removed" {
			_, _ = fmt.Fprintln(w, "stop gate     opt-in removed; re-arm with `mark1 enable --stop-gate`")
		}
	})
	if emitErr != nil {
		return cli.Failf(cli.ExitRuntime, "", "emit: %v", emitErr)
	}
	if partial {
		ee := cli.Failf(cli.ExitRuntime, "", "off is in force but partial: %d fragment(s) not reverted, daemon %s", len(res.NotReverted), res.Daemon)
		ee.Emitted = true // the Result above already carries the full story
		return ee
	}
	return nil
}

// verifyDaemonObserved is §7.6's "verified": mark1d re-checks the marker at
// 1 Hz and closes its fabric listener when off, so a previously-accepting
// socket that stops accepting IS the observation. A daemon that never
// answered is honestly "not running" — off still holds (the marker precedes
// every gate), exit stays 0.
func verifyDaemonObserved(socket string, wasReachable bool, grace time.Duration) string {
	if !wasReachable {
		return "not running"
	}
	if grace <= 0 {
		grace = 5 * time.Second
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if !cli.DaemonReachable(socket) {
			return "observed"
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "still capturing"
}

// On is §7.6's inverse (`mark1 on`): remove the marker, journal the enable
// transition. Fragment re-provisioning is `mark1 enable`'s reconcile
// (daemon §8 engine); the marker removal alone re-arms every gate.
func On(env *cli.Env) error {
	err := os.Remove(env.OffMarkerPath())
	if err != nil && !os.IsNotExist(err) {
		return cli.Failf(cli.ExitRuntime, "", "removing OFF marker: %v", err)
	}
	removed := err == nil
	if removed {
		if err := env.AppendCoverageTransition(map[string]any{
			"ts": time.Now().UTC().Format(time.RFC3339), "kind": "enable", "scope": "all",
		}); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "journaling coverage transition: %v", err)
		}
	}
	return env.Emit(map[string]any{"ok": true, "was_off": removed}, func(w io.Writer) {
		if removed {
			_, _ = fmt.Fprintln(w, "mark1 is ON")
		} else {
			_, _ = fmt.Fprintln(w, "mark1 was already on")
		}
	})
}
