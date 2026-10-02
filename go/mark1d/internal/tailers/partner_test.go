package tailers

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

// partnerRig is one Partner over a temp drop dir with a recording Emit.
type partnerRig struct {
	t        *testing.T
	dir      string
	state    string
	p        *Partner
	got      []*m1pv1.Event
	bound    []string
	sessions [][16]byte
	profiles []hostprofile.Profile
	drops    int
}

func newPartnerRig(t *testing.T, dir, state string) *partnerRig {
	t.Helper()
	r := &partnerRig{t: t, dir: dir, state: state}
	p, err := NewPartner(PartnerConfig{
		Dir:      dir,
		StateDir: state,
		Emit: func(_ context.Context, ev *m1pv1.Event) error {
			r.got = append(r.got, ev)
			return nil
		},
		OnBind: func(session [16]byte, component, corr string, p hostprofile.Profile) {
			r.bound = append(r.bound, component+"|"+corr)
			r.sessions = append(r.sessions, session)
			r.profiles = append(r.profiles, p)
		},
		Drop: func() { r.drops++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.p = p
	// Handles stay open until drained; Windows cannot remove the temp dir under an open file.
	t.Cleanup(func() { _ = p.CloseFlush(context.Background()) })
	return r
}

func (r *partnerRig) sweep() { r.p.Sweep(context.Background()) }

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

const goodManifest = `{"component":"ext:acme/runner@1.2.3","host_correlation_id":"run-7781","schema_version":"m1p.v1"}`

const turnLine = `{"eventId":"4AEAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:01Z","turn":{"initiator":"INITIATOR_HUMAN"}}` + "\n"

// TestPartnerBindsAndStampsTheSession: the sidecar is the file's Hello — the
// component and correlation id reach OnBind, every line is stamped with the
// one minted session, seq/epoch are zeroed, an unknown field is ignored, a
// blank line is nothing, and a line naming a foreign session is quarantined.
func TestPartnerBindsAndStampsTheSession(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "run.manifest.json"), goodManifest)
	writeFile(t, filepath.Join(dir, "run.jsonl"),
		turnLine+
			"\n"+
			`{"eventId":"4AIAAAAAAAAAAAAAAAAAAA==","seq":"99","sessionEpoch":7,"futureField":true,"toolUse":{"toolName":"Bash"}}`+"\n"+
			`{"eventId":"4AMAAAAAAAAAAAAAAAAAAA==","sessionId":"7u7u7u7u7u7u7u7u7u7u7g==","turn":{}}`+"\n"+
			`not json`+"\n")
	r := newPartnerRig(t, dir, state)
	r.sweep()
	if len(r.bound) != 1 || r.bound[0] != "ext:acme/runner@1.2.3|run-7781" {
		t.Fatalf("OnBind saw %q", r.bound)
	}
	if len(r.got) != 2 {
		t.Fatalf("emitted %d events, want the two well-formed lines", len(r.got))
	}
	sid := r.sessions[0]
	if sid == ([16]byte{}) || sid[6]>>4 != 7 {
		t.Fatalf("minted session %x is not a UUIDv7", sid)
	}
	for i, ev := range r.got {
		if !bytes.Equal(ev.GetSessionId(), sid[:]) || ev.GetSeq() != 0 || ev.GetSessionEpoch() != 0 {
			t.Fatalf("event %d: session %x seq %d epoch %d, want the bound session and zeroed daemon fields", i, ev.GetSessionId(), ev.GetSeq(), ev.GetSessionEpoch())
		}
	}
	if r.got[1].GetToolUse().GetToolName() != "Bash" {
		t.Fatalf("line with an unknown field did not decode: %v", r.got[1])
	}
	if r.drops != 2 {
		t.Fatalf("%d quarantined lines, want 2 (foreign session, not JSON)", r.drops)
	}
}

// TestPartnerResumesTheSameSessionAfterRestart: the minted session rides the
// cursor, so a second Partner over the same state dir continues the stream
// from the saved offset under the SAME session — the file-tail's
// HelloAck.session_id survives a daemon restart where a socket's cannot.
func TestPartnerResumesTheSameSessionAfterRestart(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "run.manifest.json"), goodManifest)
	writeFile(t, filepath.Join(dir, "run.jsonl"), turnLine)
	first := newPartnerRig(t, dir, state)
	first.sweep()
	if len(first.got) != 1 {
		t.Fatalf("first run emitted %d, want 1", len(first.got))
	}
	if err := first.p.CloseFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	appendFile(t, filepath.Join(dir, "run.jsonl"), turnLine)

	second := newPartnerRig(t, dir, state)
	second.sweep()
	if len(second.got) != 1 {
		t.Fatalf("after restart emitted %d, want only the appended line (no replay)", len(second.got))
	}
	if second.sessions[0] != first.sessions[0] {
		t.Fatalf("restart minted a second session %x, want the cursor's %x", second.sessions[0], first.sessions[0])
	}
	c, ok := loadCursor(state, second.p.ts[filepath.Join(dir, "run.jsonl")].id)
	if !ok || c.SessionIDHex != hex.EncodeToString(first.sessions[0][:]) {
		t.Fatalf("cursor session_id_hex = %q, want the minted session", c.SessionIDHex)
	}
}

// TestPartnerTornTailAndRotation: a line without its newline waits; once
// completed it emits once. A rotation (rename, new file at the path) drains
// the old inode and follows the new file from offset 0.
func TestPartnerTornTailAndRotation(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	path := filepath.Join(dir, "run.jsonl")
	writeFile(t, filepath.Join(dir, "run.manifest.json"), goodManifest)
	writeFile(t, path, turnLine+`{"eventId":"4AIAAAAAAAAAAAAAAAAAAA==","turn":`)
	r := newPartnerRig(t, dir, state)
	r.sweep()
	if len(r.got) != 1 {
		t.Fatalf("torn tail: emitted %d, want 1", len(r.got))
	}
	appendFile(t, path, `{"initiator":"INITIATOR_AGENT"}}`+"\n")
	r.sweep()
	if len(r.got) != 2 || r.got[1].GetTurn().GetInitiator() != m1pv1.Initiator_INITIATOR_AGENT {
		t.Fatalf("completed line: emitted %d, want the completed AGENT turn second", len(r.got))
	}

	// Rotation: the old file moves aside with one more line the tailer has
	// not read; the new file at the path starts fresh. Windows refuses to
	// rename a file the tailer holds open; the follow logic is shared with the
	// transcript tailers, whose rotation suite is unix-tagged for the same reason.
	if runtime.GOOS == "windows" {
		t.Skip("rename of an open file is refused on Windows; rotation is covered on unix")
	}
	appendFile(t, path, turnLine)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, `{"eventId":"4AQAAAAAAAAAAAAAAAAAAA==","toolUse":{"toolName":"Edit"}}`+"\n")
	r.sweep()
	if len(r.got) != 4 {
		t.Fatalf("rotation: emitted %d, want 4 (old inode drained, new file from 0)", len(r.got))
	}
	if r.got[2].GetTurn() == nil || r.got[3].GetToolUse().GetToolName() != "Edit" {
		t.Fatalf("rotation order wrong: %v then %v", r.got[2], r.got[3])
	}
	if !bytes.Equal(r.got[3].GetSessionId(), r.sessions[0][:]) {
		t.Fatal("the rotated file left the bound session")
	}
}

// TestPartnerRefusesABadSidecar: no ext: prefix, a wrong schema_version, or
// an over-long correlation id ⇒ the file is not tailed and nothing emits;
// fixing the sidecar makes the next sweep bind it. A missing sidecar is
// simply "not yet".
func TestPartnerRefusesABadSidecar(t *testing.T) {
	for _, tc := range []struct{ name, manifest string }{
		{"not ext", `{"component":"mark1-hookshim","schema_version":"m1p.v1"}`},
		{"wrong schema", `{"component":"ext:acme/runner@1","schema_version":"m1p.v2"}`},
		{"long correlation id", `{"component":"ext:acme/runner@1","host_correlation_id":"` + string(bytes.Repeat([]byte{'x'}, 257)) + `","schema_version":"m1p.v1"}`},
		{"not json", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, state := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(dir, "run.jsonl"), turnLine)
			writeFile(t, filepath.Join(dir, "run.manifest.json"), tc.manifest)
			r := newPartnerRig(t, dir, state)
			r.sweep()
			if len(r.got) != 0 || len(r.bound) != 0 {
				t.Fatalf("a refused sidecar was tailed: %d events, bound %v", len(r.got), r.bound)
			}
			writeFile(t, filepath.Join(dir, "run.manifest.json"), goodManifest)
			r.sweep()
			if len(r.got) != 1 {
				t.Fatalf("after the fix: emitted %d, want 1", len(r.got))
			}
		})
	}
	t.Run("missing sidecar waits", func(t *testing.T) {
		dir, state := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(dir, "run.jsonl"), turnLine)
		r := newPartnerRig(t, dir, state)
		r.sweep()
		if len(r.got) != 0 {
			t.Fatal("tailed without a sidecar")
		}
	})
}

// TestPartnerExplicitPathsAndPollRun: --partner-events paths outside the
// drop dir are tailed too, and Run's tick picks up appends.
func TestPartnerExplicitPathsAndPollRun(t *testing.T) {
	outside, state := t.TempDir(), t.TempDir()
	path := filepath.Join(outside, "cem.jsonl")
	writeFile(t, filepath.Join(outside, "cem.manifest.json"), goodManifest)
	writeFile(t, path, turnLine)
	var got []*m1pv1.Event
	p, err := NewPartner(PartnerConfig{
		Paths: []string{path}, StateDir: state, PollInterval: 10 * time.Millisecond,
		Emit: func(_ context.Context, ev *m1pv1.Event) error { got = append(got, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("Run emitted %d, want 1", len(got))
	}
}

// TestPartnerSidecarHostManifestResolvesLikeTheSocket is FR-SPINE-034: the
// sidecar's host_manifest block goes through hostprofile.FromManifest exactly
// as Hello.host_manifest does, so the same input yields the same Profile; an
// invalid block leaves the file untailed (M1E-4007), and no block is Default.
func TestPartnerSidecarHostManifestResolvesLikeTheSocket(t *testing.T) {
	manifest := `{"component":"ext:cem888/runner@2.0.1","host_correlation_id":"run-7781","schema_version":"m1p.v1",` +
		`"host_manifest":{"hostId":"cem888","hostVersion":"2.0.1","ownsExecution":true,"ownsConfigSurface":true,"ownsMemory":true,"arrestMode":"ARREST_MODE_RECOMMEND","suppliesIdentity":true,"schemaVersion":"m1p.v1"}}`
	dir, state := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "run.manifest.json"), manifest)
	writeFile(t, filepath.Join(dir, "run.jsonl"), turnLine)
	r := newPartnerRig(t, dir, state)
	r.sweep()
	want, err := hostprofile.FromManifest(&m1pv1.HostManifest{HostId: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: m1pv1.ArrestMode_ARREST_MODE_RECOMMEND, SuppliesIdentity: true, SchemaVersion: "m1p.v1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.profiles) != 1 || r.profiles[0] != want {
		t.Fatalf("sidecar profile %+v, want the socket's %+v", r.profiles, want)
	}

	t.Run("absent block is Default", func(t *testing.T) {
		dir, state := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(dir, "run.manifest.json"), goodManifest)
		writeFile(t, filepath.Join(dir, "run.jsonl"), turnLine)
		r := newPartnerRig(t, dir, state)
		r.sweep()
		if len(r.profiles) != 1 || r.profiles[0] != hostprofile.Default {
			t.Fatalf("profile %+v, want Default", r.profiles)
		}
	})
	t.Run("invalid block is refused", func(t *testing.T) {
		dir, state := t.TempDir(), t.TempDir()
		bad := strings.Replace(manifest, `"ownsExecution":true`, `"ownsExecution":false`, 1)
		writeFile(t, filepath.Join(dir, "run.manifest.json"), bad)
		writeFile(t, filepath.Join(dir, "run.jsonl"), turnLine)
		r := newPartnerRig(t, dir, state)
		r.sweep()
		if len(r.got) != 0 || len(r.bound) != 0 {
			t.Fatal("a file with an invalid host_manifest was tailed")
		}
	})
}
