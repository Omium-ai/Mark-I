//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/contrib"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/control"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/memory"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// seedSpool leaves one durable billing event in spoolDir, the backlog a tenant switch must never hand to the new identity.
func seedSpool(t *testing.T, spoolDir string) []byte {
	t.Helper()
	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := uuid.NewV7()
	session := uuid.New()
	payload, err := proto.Marshal(&m1pv1.Event{
		EventId: id[:], SessionId: session[:], Seq: 1, SessionEpoch: 1,
		Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Append(context.Background(), [16]byte(id), spool.ClassBilling, payload); err != nil {
		t.Fatal(err)
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	return id[:]
}

// ctlCall is the desktop app's side of the loopback control API, discovered the way the app finds it.
func ctlCall(t *testing.T, stateDir, method, path string, body any) []byte {
	t.Helper()
	raw, err := os.ReadFile(control.Path(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Port  int    `json:"port"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, "http://127.0.0.1:"+strconv.Itoa(d.Port)+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+d.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, out)
	}
	return out
}

// 15-teams edge contract: old events drain or park under the old token only; the old tenant's cache, LKG and receipt head go.
func TestTenantSwitchNeverUploadsOldEventsUnderTheNewToken(t *testing.T) {
	was := parkedRetry
	parkedRetry = 50 * time.Millisecond
	t.Cleanup(func() { parkedRetry = was })
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dec.Close)

	for _, drains := range []bool{true, false} {
		name := map[bool]string{true: "old_token_drains_at_switch", false: "undrained_is_parked_under_the_old_token"}[drains]
		t.Run(name, func(t *testing.T) {
			var oldOK atomic.Bool
			var mu sync.Mutex
			sent := map[string][][]byte{} // bearer -> event ids that landed (2xx)
			tried := map[string]int{}
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/m1p/v1/ingest" {
					rw.WriteHeader(http.StatusNotFound)
					return
				}
				bearer := r.Header.Get("Authorization")
				body, _ := io.ReadAll(r.Body)
				raw, err := dec.DecodeAll(body, nil)
				b := &m1pv1.Batch{}
				if err != nil || proto.Unmarshal(raw, b) != nil {
					rw.WriteHeader(http.StatusBadRequest)
					return
				}
				mu.Lock()
				tried[bearer]++
				ok := bearer != "Bearer tok-from-doc" || oldOK.Load()
				if ok {
					for _, ev := range b.GetEvents() {
						sent[bearer] = append(sent[bearer], ev.GetEventId())
					}
				}
				mu.Unlock()
				if !ok {
					rw.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				rw.Header().Set("Content-Type", "application/json")
				_, _ = rw.Write([]byte(`{"batch_id":"` + r.Header.Get("M1P-Batch-Id") + `"}`))
			}))
			defer srv.Close()
			ingest := srv.URL + "/m1p/v1/ingest"
			landed := func(bearer string, id []byte) bool {
				mu.Lock()
				defer mu.Unlock()
				for _, got := range sent[bearer] {
					if bytes.Equal(got, id) {
						return true
					}
				}
				return false
			}

			stateDir, spoolDir, socket := uplinkPaths(t)
			oldEvent := seedSpool(t, spoolDir)
			writeEnrollmentDoc(t, stateDir, ingest, 0o600)
			for _, p := range []string{filepath.Join(stateDir, "policy", "lkg.cbor"), filepath.Join(stateDir, "receipt", "last-head"), memory.CustodyPath(stateDir)} {
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("old tenant"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := config{stateDir: stateDir, spoolDir: spoolDir, socket: socket, offPoll: 10 * time.Millisecond, flagsSet: true} // main()'s order: no flags, identity from the document only
			if err := applyEnrollment(&cfg, slog.New(slog.NewTextHandler(os.Stderr, nil))); err != nil {
				t.Fatal(err)
			}
			stop := runDaemon(t, cfg)
			defer stop()
			waitUpTo(t, 20*time.Second, "the old identity's first upload attempt", func() bool {
				mu.Lock()
				defer mu.Unlock()
				return tried["Bearer tok-from-doc"] > 0
			})

			var kg struct {
				KeyID string `json:"key_id"`
			}
			if err := json.Unmarshal(ctlCall(t, stateDir, http.MethodPost, "/v1/enroll/keygen", nil), &kg); err != nil {
				t.Fatal(err)
			}
			tenantB, deviceB := uuid.New().String(), uuid.New().String()
			claims, _ := json.Marshal(map[string]string{"tenant_id": tenantB, "device_id": deviceB, "key_id": kg.KeyID})
			tokB := "m1tok.v1." + base64.RawURLEncoding.EncodeToString(claims) + ".c2ln"
			oldOK.Store(drains)
			ctlCall(t, stateDir, http.MethodPost, "/v1/enroll", map[string]any{
				"status": "active", "device_id": deviceB, "tenant_id": tenantB, "device_token": tokB, "expires_in": 86400,
				"tenant_root_hex": strings.Repeat("b6", 32), "endpoints": map[string]string{"ingest": ingest},
			})
			waitUpTo(t, 20*time.Second, "the switch to settle", func() bool {
				_, err := os.Stat(prevEnrollmentPath(stateDir))
				return os.IsNotExist(err)
			})
			parked, _ := filepath.Glob(filepath.Join(parkedRoot(stateDir), "*"))
			if drains != (len(parked) == 0) {
				t.Fatalf("drains=%v but parked=%v", drains, parked)
			}
			if drains && !landed("Bearer tok-from-doc", oldEvent) {
				t.Fatal("the switch drains the old spool under the old token first")
			}
			for _, p := range []string{filepath.Join(stateDir, "policy", "lkg.cbor"), filepath.Join(stateDir, "receipt", "last-head")} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatalf("%s survived the tenant switch", p)
				}
			}
			if b, _ := os.ReadFile(memory.CustodyPath(stateDir)); string(b) == "old tenant" {
				t.Fatal("the old tenant's memory cache survived the switch")
			}

			waitFor(t, "the new session's fabric socket", func() bool {
				_, err := os.Stat(socket)
				return err == nil
			})
			session := uuid.New()
			dialFabric(t, socket, session).prompt(session)
			waitUpTo(t, 20*time.Second, "the new identity's first upload", func() bool {
				mu.Lock()
				defer mu.Unlock()
				return len(sent["Bearer "+tokB]) > 0
			})
			if !drains {
				time.Sleep(200 * time.Millisecond)
				if landed("Bearer tok-from-doc", oldEvent) {
					t.Fatal("the old token is refusing; nothing of the parked spool can have landed")
				}
				oldOK.Store(true)
				waitUpTo(t, 20*time.Second, "the parked spool to drain under the old token", func() bool {
					_, err := os.Stat(parked[0])
					return os.IsNotExist(err)
				})
				if !landed("Bearer tok-from-doc", oldEvent) {
					t.Fatal("the parked event landed under no token")
				}
			}
			if landed("Bearer "+tokB, oldEvent) {
				t.Fatal("an old-tenant event was uploaded under the new tenant's token")
			}
		})
	}
}

// A retired document for the SAME tenant only drops the file: backlog, policy, memory and receipt head stay.
func TestSameTenantReEnrollIsNotASwitch(t *testing.T) {
	stateDir, spoolDir, _ := uplinkPaths(t)
	seedSpool(t, spoolDir)
	writeEnrollmentDoc(t, stateDir, "https://api.test.example/m1p/v1/ingest", 0o600)
	raw, _ := os.ReadFile(enrollmentPath(stateDir))
	if err := os.WriteFile(prevEnrollmentPath(stateDir), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	kept := []string{filepath.Join(stateDir, "policy", "lkg.cbor"), filepath.Join(stateDir, "receipt", "last-head"), memory.CustodyPath(stateDir)}
	for _, p := range kept {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := settleTenantSwitch(slog.New(slog.NewTextHandler(io.Discard, nil)), config{stateDir: stateDir, spoolDir: spoolDir}); err != nil {
		t.Fatal(err)
	}
	if switching(stateDir) {
		t.Fatal("the retired document is dropped")
	}
	if parked, _ := filepath.Glob(filepath.Join(parkedRoot(stateDir), "*")); len(parked) != 0 {
		t.Fatalf("same tenant parked %v", parked)
	}
	for _, p := range kept {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s must survive a same-tenant re-enroll: %v", p, err)
		}
	}
	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	if ack, write := sp.Cursors(); ack == write {
		t.Fatal("the backlog stays in the live spool")
	}
}

func TestSettleRerunAfterACrashFinishesTheSwitch(t *testing.T) {
	stateDir, spoolDir, _ := uplinkPaths(t)
	writeEnrollmentDoc(t, stateDir, "https://api.test.example/m1p/v1/ingest", 0o600)
	raw, _ := os.ReadFile(enrollmentPath(stateDir))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["tenant_id"] = "0191a000-0000-7000-8000-00000000dead"
	old, _ := json.Marshal(doc)
	if err := os.WriteFile(prevEnrollmentPath(stateDir), old, 0o600); err != nil {
		t.Fatal(err)
	}
	// the crash landed after the spool moved and before the old tenant's state was cleared
	dst := filepath.Join(parkedRoot(stateDir), "0191a000-0000-7000-8000-00000000dead_1")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "enrollment.json"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	seedSpool(t, filepath.Join(dst, "spool"))
	stale := []string{filepath.Join(stateDir, "policy", "lkg.cbor"), filepath.Join(stateDir, "receipt", "last-head"), memory.CustodyPath(stateDir), filepath.Join(contrib.Dir(stateDir), "task.json")}
	for _, p := range stale {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := settleTenantSwitch(slog.New(slog.NewTextHandler(io.Discard, nil)), config{stateDir: stateDir, spoolDir: spoolDir}); err != nil {
		t.Fatal(err)
	}
	for _, p := range append(stale, prevEnrollmentPath(stateDir)) {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s must be gone after the rerun: %v", p, err)
		}
	}
	for _, p := range []string{filepath.Join(dst, "enrollment.json"), filepath.Join(dst, "spool")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("the parked identity must survive the rerun: %v", err)
		}
	}
}
