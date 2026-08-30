// Package status is 08 §7.3, the live read surface — the product's
// transparency promise: what is enrolled, what is enabled, what is being
// read, and whether the daemon is even running. It must always answer
// (exit 0 even degraded; 3 only when not enrolled), and it never invents a
// number it cannot read: the daemon's counter/gauge tables are not
// queryable over the fabric yet (04 §2.11 row), so live tailer/verdict
// figures are reported as unavailable rather than zero.
package status

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

type Options struct {
	Socket string // test seam
}

type Report struct {
	OK         bool        `json:"ok"`
	Enrollment *Enrollment `json:"enrollment"`
	Daemon     Daemon      `json:"daemon"`
	Workspaces []Workspace `json:"workspaces"`
	Spool      Spool       `json:"spool"`
	Bundle     *Bundle     `json:"bundle"` // null until the policy client persists one
	Off        Off         `json:"off"`
}

type Enrollment struct {
	State          string `json:"state"`
	DeviceID       string `json:"device_id"`
	TenantID       string `json:"tenant_id"`
	TokenFresh     bool   `json:"token_fresh"`
	TokenExpiresAt string `json:"token_expires_at"`
}

type Daemon struct {
	Running bool   `json:"running"`
	Socket  string `json:"socket"`
}

// Workspace: the reading sub-object of §7.3 lists live tailer targets; the
// daemon cannot be asked yet, so the honest surface is the allow-list entry
// plus "live read surface pending daemon query support".
type Workspace struct {
	Path      string `json:"path"`
	EnabledAt string `json:"enabled_at"`
}

type Spool struct {
	Segments    int   `json:"segments"`
	Bytes       int64 `json:"bytes"`
	Quarantined int   `json:"quarantined"`
}

type Bundle struct {
	Channel   string `json:"channel"`
	Seq       uint64 `json:"seq"`
	AgeS      int64  `json:"age_s"`
	Stale     bool   `json:"stale"`
	AppliedAt string `json:"applied_at"`
}

type Off struct {
	Active bool   `json:"active"`
	Scope  string `json:"scope,omitempty"`
	Until  string `json:"until,omitempty"`
}

func Run(env *cli.Env, opts Options) error {
	doc, err := env.LoadEnrollment()
	if err != nil {
		if errors.Is(err, cli.ErrNotEnrolled) {
			return cli.Failf(cli.ExitNotEnrolled, "M1E-1002", "not enrolled — run `mark1 enroll`")
		}
		return cli.Failf(cli.ExitRuntime, "", "reading enrollment: %v", err)
	}

	rep := Report{OK: true}
	rep.Enrollment = &Enrollment{
		// LiveState, not the stored string: a doc past its token expiry or
		// stamped revoked (cli.NoteAuthRefusal) must say so here — status is
		// the transparency surface (08 §7.3), and "active" from a dead doc
		// would hide exactly the state that needs `mark1 enroll` re-run.
		State:          doc.LiveState(time.Now()),
		DeviceID:       doc.DeviceID,
		TenantID:       doc.TenantID,
		TokenFresh:     time.Now().Before(doc.TokenExpiresAt),
		TokenExpiresAt: doc.TokenExpiresAt.UTC().Format(time.RFC3339),
	}

	socket := opts.Socket
	if socket == "" {
		if s, err := cli.SocketPath(); err == nil {
			socket = s
		}
	}
	rep.Daemon = Daemon{Running: socket != "" && cli.DaemonReachable(socket), Socket: socket}

	// Degradation never silences status (§7.3 exit rule) — unreadable
	// sub-surfaces report empty, and the daemon line already says why.
	if ws, err := env.LoadWorkspaces(); err == nil {
		for _, w := range ws.Workspaces {
			rep.Workspaces = append(rep.Workspaces, Workspace{Path: w.Path, EnabledAt: w.EnabledAt.UTC().Format(time.RFC3339)})
		}
	}
	rep.Spool.Segments, rep.Spool.Bytes = dirTally(env.SpoolDir(), ".m1s")
	rep.Spool.Quarantined, _ = dirTally(env.QuarantineDir(), "")
	rep.Bundle = readBundleMeta(env)
	rep.Off = readOff(env)

	return env.Emit(rep, func(w io.Writer) { renderHuman(w, &rep) })
}

// dirTally counts files (optionally by extension) and their bytes — the
// honest on-disk proxy for spool depth until the daemon's gauge tables are
// queryable. Spool segments are mark1d's seg-*.m1s (07 §6).
func dirTally(dir, ext string) (int, int64) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	var n int
	var bytes int64
	for _, e := range entries {
		if e.IsDir() || (ext != "" && filepath.Ext(e.Name()) != ext) {
			continue
		}
		n++
		if fi, err := e.Info(); err == nil {
			bytes += fi.Size()
		}
	}
	return n, bytes
}

// readBundleMeta reads the last-applied bundle sidecar (<state>/bundle/,
// 04 §2.6 "bytes + seq + applied-at"). The policy client that writes it is
// a mark1d row; until then the surface reports null, not seq 0.
func readBundleMeta(env *cli.Env) *Bundle {
	data, err := os.ReadFile(env.BundleMetaPath())
	if err != nil {
		return nil
	}
	var meta struct {
		Channel   string    `json:"channel"`
		Seq       uint64    `json:"seq"`
		AppliedAt time.Time `json:"applied_at"`
		MaxAgeS   int64     `json:"max_age_s"`
	}
	if json.Unmarshal(data, &meta) != nil {
		return nil
	}
	age := int64(time.Since(meta.AppliedAt).Seconds())
	return &Bundle{
		Channel:   meta.Channel,
		Seq:       meta.Seq,
		AgeS:      age,
		Stale:     meta.MaxAgeS > 0 && age > meta.MaxAgeS,
		AppliedAt: meta.AppliedAt.UTC().Format(time.RFC3339),
	}
}

func readOff(env *cli.Env) Off {
	data, err := os.ReadFile(env.OffMarkerPath())
	if err != nil {
		return Off{Active: false}
	}
	o := Off{Active: true}
	var m struct {
		Scope string `json:"scope"`
		Until string `json:"until"`
	}
	// An unreadable/empty marker is still OFF — existence is the switch
	// (mark1d off.Off stats, never parses).
	if json.Unmarshal(data, &m) == nil {
		o.Scope, o.Until = m.Scope, m.Until
	}
	return o
}

func renderHuman(w io.Writer, r *Report) {
	daemon := "not running"
	if r.Daemon.Running {
		daemon = "running"
	}
	fmt.Fprintf(w, "mark1d        %s (socket %s)\n", daemon, r.Daemon.Socket)
	fresh := "STALE"
	if r.Enrollment.TokenFresh {
		fresh = "fresh"
	}
	fmt.Fprintf(w, "enrollment    %s device %s tenant %s (token %s)\n",
		r.Enrollment.State, r.Enrollment.DeviceID, r.Enrollment.TenantID, fresh)
	if len(r.Workspaces) == 0 {
		fmt.Fprintf(w, "workspaces    none enabled\n")
	}
	for _, ws := range r.Workspaces {
		fmt.Fprintf(w, "workspaces    %s (enabled %s)\n", ws.Path, ws.EnabledAt)
	}
	fmt.Fprintf(w, "spool         %d segments / %d bytes, quarantined: %d\n",
		r.Spool.Segments, r.Spool.Bytes, r.Spool.Quarantined)
	if r.Bundle == nil {
		fmt.Fprintf(w, "policy        no bundle applied yet\n")
	} else {
		fmt.Fprintf(w, "policy        bundle seq %d (%s), age %ds, stale: %v\n",
			r.Bundle.Seq, r.Bundle.Channel, r.Bundle.AgeS, r.Bundle.Stale)
	}
	if r.Off.Active {
		fmt.Fprintf(w, "off           ACTIVE (scope %s)\n", r.Off.Scope)
	} else {
		fmt.Fprintf(w, "off           inactive\n")
	}
}
