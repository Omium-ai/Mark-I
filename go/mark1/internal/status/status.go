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
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

type Options struct {
	Socket string // test seam
}

type Report struct {
	OK         bool        `json:"ok"`
	Enrollment *Enrollment `json:"enrollment"`
	KeyCustody KeyCustody  `json:"key_custody"`
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

// KeyCustody is NFR-PORTABILITY-004 made visible: which rung of 04 §2.9's
// ladder holds the device key, whether a key is stored at all, and — when the
// rung is not the top — why. A fallback nobody can see is exactly the silent
// downgrade the requirement forbids.
type KeyCustody struct {
	Tier     string `json:"tier"`
	Present  bool   `json:"present"`
	Degraded bool   `json:"degraded"`
	Reason   string `json:"reason,omitempty"`
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
	Quarantined int   `json:"quarantined"` // batches, i.e. len(Quarantine)
	// Quarantine is NFR-OPERABILITY-003's listing: every 4xx-parked batch with
	// the reason the daemon recorded beside its sealed bytes. Additive to
	// §7.3's counts; nothing is renamed.
	Quarantine []Quarantined `json:"quarantine"`
	// QuarantineRetention is stated on every report because 08 §2.5 fixes only
	// "never silently discarded and never auto-retried" — no doc names a
	// retention window, so none is claimed.
	QuarantineRetention string `json:"quarantine_retention"`
}

// quarantineRetention is the honest answer until a product decision names a
// window: the bytes stay until an operator removes them.
const quarantineRetention = "none — kept until removed by an operator (never auto-retried, 08 §2.5)"

// Quarantined is one parked batch, read from the daemon's
// <state>/quarantine/<batch_id>.manifest.json (go/mark1d/internal/uplink/
// quarantine.go: manifest) plus the size of the sealed payload beside it.
// Status/ErrCode/Note are the manifest's own fields, verbatim; Reason is the
// operator line composed from them.
type Quarantined struct {
	BatchID       string `json:"batch_id"`
	QuarantinedAt string `json:"quarantined_at"`
	Bytes         int64  `json:"bytes"` // sealed payload on disk; 0 when it is gone
	Events        int    `json:"events"`
	Status        int    `json:"status,omitempty"`
	ErrCode       string `json:"err_code,omitempty"`
	Note          string `json:"note,omitempty"`
	Reason        string `json:"reason"`
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

	// Stat, never read: status is a read-only transparency surface and has no
	// business pulling a private seed into its address space to print a bool.
	_, keyErr := os.Stat(env.DeviceKeyPath())
	tier, degradation := cli.KeyCustody()
	rep.KeyCustody = KeyCustody{
		Tier: tier, Present: keyErr == nil,
		Degraded: degradation != "", Reason: degradation,
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
	rep.Spool.Quarantine = readQuarantine(env.QuarantineDir())
	rep.Spool.Quarantined = len(rep.Spool.Quarantine)
	rep.Spool.QuarantineRetention = quarantineRetention
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

// readQuarantine lists parked batches by their manifests — the daemon writes
// the sealed payload first and the manifest second (quarantine.go:59-74), so
// the manifest is the durable "report" half 08 §2.5 promises. A manifest that
// will not parse is still listed (a torn write after a crash is exactly the
// batch an operator most needs to see), with the parse error as its reason.
func readQuarantine(dir string) []Quarantined {
	manifests, _ := filepath.Glob(filepath.Join(dir, "*.manifest.json"))
	var out []Quarantined
	for _, path := range manifests {
		id := strings.TrimSuffix(filepath.Base(path), ".manifest.json")
		q := Quarantined{BatchID: id}
		if fi, err := os.Stat(filepath.Join(dir, id+".m1p.zst.sealed")); err == nil {
			q.Bytes = fi.Size()
		}
		var m struct {
			Status        int    `json:"status"`
			ErrCode       string `json:"err_code"`
			EventCount    int    `json:"event_count"`
			QuarantinedAt string `json:"quarantined_at"`
			Note          string `json:"note"`
		}
		data, err := os.ReadFile(path)
		if err == nil {
			err = json.Unmarshal(data, &m)
		}
		switch {
		case err != nil:
			q.Reason = "manifest unreadable: " + err.Error()
		default:
			q.QuarantinedAt, q.Events = m.QuarantinedAt, m.EventCount
			q.Status, q.ErrCode, q.Note = m.Status, m.ErrCode, m.Note
			q.Reason = quarantineReason(m.Status, m.ErrCode, m.Note)
		}
		out = append(out, q)
	}
	return out
}

// quarantineReason renders the 08 §2.4 verdict the manifest carries. Every
// daemon-written manifest has a status; the fallback names the absence rather
// than inventing a verdict.
func quarantineReason(status int, code, note string) string {
	var parts []string
	if status != 0 {
		parts = append(parts, fmt.Sprintf("HTTP %d", status))
	}
	if code != "" {
		parts = append(parts, code)
	}
	if note != "" {
		parts = append(parts, note)
	}
	if len(parts) == 0 {
		return "not recorded by daemon"
	}
	return strings.Join(parts, " ")
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
	_, _ = fmt.Fprintf(w, "mark1d        %s (socket %s)\n", daemon, r.Daemon.Socket)
	fresh := "STALE"
	if r.Enrollment.TokenFresh {
		fresh = "fresh"
	}
	_, _ = fmt.Fprintf(w, "enrollment    %s device %s tenant %s (token %s)\n",
		r.Enrollment.State, r.Enrollment.DeviceID, r.Enrollment.TenantID, fresh)
	custody := "key custody   " + r.KeyCustody.Tier
	if !r.KeyCustody.Present {
		custody += ", no key stored yet"
	}
	if r.KeyCustody.Degraded {
		custody += " — DEGRADED: " + r.KeyCustody.Reason
	}
	_, _ = fmt.Fprintln(w, custody)
	if len(r.Workspaces) == 0 {
		_, _ = fmt.Fprintf(w, "workspaces    none enabled\n")
	}
	for _, ws := range r.Workspaces {
		_, _ = fmt.Fprintf(w, "workspaces    %s (enabled %s)\n", ws.Path, ws.EnabledAt)
	}
	_, _ = fmt.Fprintf(w, "spool         %d segments / %d bytes, quarantined: %d\n",
		r.Spool.Segments, r.Spool.Bytes, r.Spool.Quarantined)
	for _, q := range r.Spool.Quarantine {
		_, _ = fmt.Fprintf(w, "quarantine    %s parked %s, %d bytes, %d events — reason: %s\n",
			q.BatchID, q.QuarantinedAt, q.Bytes, q.Events, q.Reason)
	}
	if len(r.Spool.Quarantine) > 0 {
		_, _ = fmt.Fprintf(w, "quarantine    retention: %s\n", r.Spool.QuarantineRetention)
	}
	if r.Bundle == nil {
		_, _ = fmt.Fprintf(w, "policy        no bundle applied yet\n")
	} else {
		_, _ = fmt.Fprintf(w, "policy        bundle seq %d (%s), age %ds, stale: %v\n",
			r.Bundle.Seq, r.Bundle.Channel, r.Bundle.AgeS, r.Bundle.Stale)
	}
	if r.Off.Active {
		_, _ = fmt.Fprintf(w, "off           ACTIVE (scope %s)\n", r.Off.Scope)
	} else {
		_, _ = fmt.Fprintf(w, "off           inactive\n")
	}
}
