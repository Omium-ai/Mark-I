//go:build unix

package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// writeEnrollmentDoc lays the document `mark1 enroll` persists (08 §7.1, the
// go/mark1/internal/cli.Enrollment shape) under stateDir, 0600 unless told
// otherwise, and returns the identity it carries.
func writeEnrollmentDoc(t *testing.T, stateDir, ingest string, perm os.FileMode) (tenant, device uuid.UUID) {
	t.Helper()
	tenant, device = uuid.New(), uuid.New()
	doc := map[string]any{
		"version": 1, "state": "active",
		"device_id": device.String(), "tenant_id": tenant.String(),
		"device_token":     "tok-from-doc",
		"token_expires_at": time.Now().Add(23 * time.Hour).UTC().Format(time.RFC3339),
		"tenant_root_hex":  strings.Repeat("a5", 32),
		"server":           "https://api.test.example",
		"channel":          "stable",
		"endpoints":        map[string]string{"ingest": ingest},
		"enrolled_at":      time.Now().UTC().Format(time.RFC3339),
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(enrollmentPath(stateDir), raw, perm); err != nil {
		t.Fatal(err)
	}
	return tenant, device
}

// TestDaemonBootsFromEnrollmentDocument is D-ED's product gap closed: with
// only --state-dir, the daemon takes its identity from the enrollment document
// `mark1 enroll` wrote (token, tenant, device, tenant root, ingest endpoint)
// and the first upload leaves the machine under THAT bearer; a DEV SEAM flag
// still wins over the document; a device with neither is refused naming
// `mark1 enroll`; a loose-mode document is refused like a loose device key.
func TestDaemonBootsFromEnrollmentDocument(t *testing.T) {
	tap := newWireTap(t)
	var bearer atomic.Value
	front := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		bearer.Store(r.Header.Get("Authorization"))
		tap.serve(rw, r)
	}))
	t.Cleanup(front.Close)
	ingest := front.URL + "/m1p/v1/ingest"
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	t.Run("no_document_no_flags_boots_local_only", func(t *testing.T) {
		stateDir, _, _ := uplinkPaths(t)
		cfg := config{stateDir: stateDir}
		// The desktop app spawns the daemon before sign-in (spec §3.2): no document is local-only capture, not a refusal.
		if err := applyEnrollment(&cfg, log); err != nil || cfg.identity() != (identityFlags{}) {
			t.Fatalf("want a local-only boot with an empty identity, got err=%v identity=%+v", err, cfg.identity())
		}
		// A DEV SEAM flag is an identity: the seam tests use still boots.
		cfg = config{stateDir: stateDir, saltHex: "aa"}
		if err := applyEnrollment(&cfg, log); err != nil {
			t.Fatalf("flag-only identity refused: %v", err)
		}
	})

	t.Run("loose_mode_document_is_refused", func(t *testing.T) {
		stateDir, _, _ := uplinkPaths(t)
		writeEnrollmentDoc(t, stateDir, ingest, 0o644)
		cfg := config{stateDir: stateDir}
		if err := applyEnrollment(&cfg, log); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("want a mode refusal, got %v", err)
		}
	})

	t.Run("flags_override_the_document", func(t *testing.T) {
		stateDir, _, _ := uplinkPaths(t)
		tenant, device := writeEnrollmentDoc(t, stateDir, ingest, 0o600)
		cfg := config{stateDir: stateDir, deviceToken: "tok-from-flag", saltHex: "bb"}
		if err := applyEnrollment(&cfg, log); err != nil {
			t.Fatal(err)
		}
		if cfg.deviceToken != "tok-from-flag" || cfg.saltHex != "bb" {
			t.Fatalf("flags lost to the document: %+v", cfg)
		}
		if cfg.tenantID != tenant.String() || cfg.deviceID != device.String() || cfg.ingestURL != ingest {
			t.Fatalf("unset fields not filled from the document: %+v", cfg)
		}
	})

	t.Run("document_alone_boots_and_uploads_under_its_token", func(t *testing.T) {
		stateDir, spoolDir, socket := uplinkPaths(t)
		tenant, device := writeEnrollmentDoc(t, stateDir, ingest, 0o600)
		cfg := config{stateDir: stateDir, spoolDir: spoolDir, socket: socket, offPoll: 10 * time.Millisecond}
		if err := applyEnrollment(&cfg, log); err != nil {
			t.Fatal(err)
		}
		if cfg.deviceToken != "tok-from-doc" || cfg.tenantID != tenant.String() ||
			cfg.deviceID != device.String() || cfg.saltHex != strings.Repeat("a5", 32) || cfg.ingestURL != ingest {
			t.Fatalf("identity not taken from the document: %+v", cfg)
		}
		stop := runDaemon(t, cfg)
		defer stop()
		waitFor(t, "fabric socket", func() bool {
			_, err := os.Stat(socket)
			return err == nil
		})
		session := uuid.New()
		c := dialFabric(t, socket, session)
		c.prompt(session)
		waitUpTo(t, 20*time.Second, "the first batch to reach the wire", func() bool {
			tap.mu.Lock()
			defer tap.mu.Unlock()
			return len(tap.batches) > 0
		})
		if got, _ := bearer.Load().(string); got != "Bearer tok-from-doc" {
			t.Fatalf("upload authorized with %q, want the document's token", got)
		}
	})

	t.Run("refresh_adopts_a_rewritten_document", func(t *testing.T) {
		stateDir, _, _ := uplinkPaths(t)
		writeEnrollmentDoc(t, stateDir, ingest, 0o600)
		d := &docTokens{stateDir: stateDir, current: "tok-from-doc"}
		if err := d.Refresh(t.Context()); err == nil {
			t.Fatal("unchanged document must not count as a refresh (08 §2.4: park, do not loop)")
		}
		raw, _ := os.ReadFile(filepath.Join(stateDir, "enrollment.json"))
		raw = []byte(strings.Replace(string(raw), "tok-from-doc", "tok-refreshed", 1))
		if err := os.WriteFile(enrollmentPath(stateDir), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := d.Refresh(t.Context()); err != nil {
			t.Fatalf("rewritten document not adopted: %v", err)
		}
		if tok, _ := d.Token(t.Context()); tok != "tok-refreshed" {
			t.Fatalf("Token after refresh = %q", tok)
		}
	})
}
