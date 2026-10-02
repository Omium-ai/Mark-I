package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/conformance/emitter"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

// The extmanifest conformance family (conformance/vectors/extmanifest/README.md).

const extmanifestVectors = "../../../conformance/vectors/extmanifest"

// TestConfVectorsExtmanifestEmitterIsPinned: the Go emitter's events equal the
// ext family's and its manifest-bearing sidecar equals the frozen one.
func TestConfVectorsExtmanifestEmitterIsPinned(t *testing.T) {
	got, err := emitter.JSONL()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(extmanifestVectors, "sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("emitter.JSONL drifted from the frozen extmanifest sample.jsonl")
	}
	ext, err := os.ReadFile(filepath.Join(extVectors, "sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ext, want) {
		t.Fatal("the extmanifest events must equal the ext family's: declaring a profile changes no event")
	}
	wantM, err := os.ReadFile(filepath.Join(extmanifestVectors, "sample.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(emitter.ManifestWithHost(), wantM) {
		t.Fatalf("emitter.ManifestWithHost drifted: %s", emitter.ManifestWithHost())
	}
}

// TestConfVectorsExtmanifestTransportsAgree is FR-SPINE-033/034 end to end:
// the sample pushed with Hello.host_manifest into one assembled daemon and
// tailed from the frozen sidecar by another resolve the identical Profile —
// the cem888 profile, compared by Canonical as each daemon logged it at
// bind — and produce identical internal streams.
func TestConfVectorsExtmanifestTransportsAgree(t *testing.T) {
	profileLine := regexp.MustCompile(`profile="?(\{[^}]*\})"?`)

	socketState := t.TempDir()
	var logA bytes.Buffer
	stopA := bootDaemonLog(t, socketState, "", &logA)
	c := dialEndpoint(t, lastEndpoint)
	sidA, err := emitter.PushWithManifest(c, emitter.HostManifest())
	if err != nil {
		t.Fatal(err)
	}
	stopA()

	drop := t.TempDir()
	for _, name := range []string{"sample.manifest.json", "sample.jsonl"} {
		b, err := os.ReadFile(filepath.Join(extmanifestVectors, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(drop, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fileState := t.TempDir()
	var logB bytes.Buffer
	stopB := bootDaemonLog(t, fileState, filepath.Join(drop, "sample.jsonl"), &logB)
	fi, err := os.Stat(filepath.Join(drop, "sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for cursorAt(t, filepath.Join(fileState, "cursors"), filepath.Join(drop, "sample.jsonl")) != fi.Size() {
		if time.Now().After(deadline) {
			t.Fatal("partner file never fully tailed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	stopB()

	// slog's text handler quotes the JSON value and escapes its quotes; undo that.
	unq := func(m [][]byte) string {
		if m == nil {
			return ""
		}
		return strings.ReplaceAll(string(m[1]), `\"`, `"`)
	}
	pA := profileLine.FindSubmatch(logA.Bytes())
	pB := profileLine.FindSubmatch(logB.Bytes())
	if pA == nil || pB == nil {
		t.Fatalf("a daemon did not log the resolved profile at bind\n--- socket ---\n%s\n--- file ---\n%s", logA.String(), logB.String())
	}
	want, err := hostprofile.FromManifest(emitter.HostManifest(), true)
	if err != nil {
		t.Fatal(err)
	}
	if unq(pA) != string(hostprofile.Canonical(want)) || unq(pB) != unq(pA) {
		t.Fatalf("resolved profiles differ\nsocket: %s\nfile:   %s\nwant:   %s", unq(pA), unq(pB), hostprofile.Canonical(want))
	}
	if !bytes.Contains(logA.Bytes(), []byte("known host declared a profile")) {
		t.Fatalf("the registry did not recognise cem888: %s", logA.String())
	}

	writerIDs := map[[16]byte]bool{}
	for _, ev := range emitter.Session() {
		var id [16]byte
		copy(id[:], ev.GetEventId())
		writerIDs[id] = true
	}
	streamA, leavesA := sessionStream(t, socketState, sidA[:], writerIDs)
	streamB, leavesB := sessionStream(t, fileState, nil, writerIDs)
	if streamA != streamB || leavesA != leavesB {
		t.Fatalf("socket and file-tail streams differ under a declared profile\n--- socket ---\n%s\n--- file ---\n%s", streamA, streamB)
	}
}

// bootDaemonLog is bootDaemon with the daemon's log captured.
func bootDaemonLog(t *testing.T, state, partner string, log *bytes.Buffer) (stop func()) {
	t.Helper()
	endpoint := testEndpoint(t)
	lastEndpoint = endpoint
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, slog.New(slog.NewTextHandler(log, nil)), config{
			stateDir:      state,
			spoolDir:      filepath.Join(state, "spool"),
			socket:        endpoint,
			saltHex:       "aa",
			offPoll:       10 * time.Millisecond,
			partnerEvents: partner,
			diskUsage:     func(string) (float64, error) { return 0.10, nil },
		})
	}()
	return func() {
		t.Helper()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("run returned %v, want clean exit", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("daemon did not exit on cancellation")
		}
	}
}
