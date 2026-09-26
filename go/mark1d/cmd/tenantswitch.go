package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/memory"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spill"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/uplink"
)

// switchDrain bounds the outgoing identity's last upload pass at a tenant switch (15-teams, Edge).
// ponytail: one Flush pass of 10 s; whatever misses it is parked and drained under its own token by drainParked.
const switchDrain = 10 * time.Second

// parkedRetry paces a parked spool's upload attempts; a var so tests need not wait a minute.
var parkedRetry = time.Minute

// prevEnrollmentPath is control's retire() target: the document a re-enroll into another tenant (or a sign-out) replaced.
func prevEnrollmentPath(stateDir string) string {
	return filepath.Join(stateDir, "enrollment.prev.json")
}

func parkedRoot(stateDir string) string { return filepath.Join(stateDir, "parked") }

func switching(stateDir string) bool {
	_, err := os.Stat(prevEnrollmentPath(stateDir))
	return err == nil
}

// settleTenantSwitch runs between sessions, after the outgoing one drained: the same tenant just drops the retired document; another tenant parks the spool it could not drain beside that document and resets what was the old tenant's.
func settleTenantSwitch(log *slog.Logger, cfg config) error {
	prevPath := prevEnrollmentPath(cfg.stateDir)
	prev, err := readEnrollmentFile(prevPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		log.Error("mark1d: retired enrollment unreadable; the spool it owned is parked and never uploaded", "err", err)
		prev = &enrollment{}
	}
	if cur, err := readEnrollment(cfg.stateDir); err == nil && cur.TenantID == prev.TenantID {
		return os.Remove(prevPath)
	}
	sp, err := spool.Open(spool.Config{Dir: cfg.spoolDir})
	if err != nil {
		return err
	}
	ack, write := sp.Cursors()
	if err := sp.Close(); err != nil {
		return err
	}
	if ack != write {
		dst := filepath.Join(parkedRoot(cfg.stateDir), prev.TenantID+"_"+strconv.FormatInt(time.Now().UnixNano(), 10))
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return err
		}
		// crash-safe order: the document lands beside the spool first, the retired one is removed last, so a rerun redoes, never strands
		doc, err := os.ReadFile(prevPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, "enrollment.json"), doc, 0o600); err != nil {
			return err
		}
		if err := os.Rename(cfg.spoolDir, filepath.Join(dst, "spool")); err != nil {
			return err // ponytail: a --spool-dir on another filesystem (EXDEV) refuses to start rather than upload old events under the new token
		}
		log.Warn("mark1d: tenant switch: undrained spool parked under the old identity", "tenant_id", prev.TenantID, "dir", dst)
	}
	stale, _ := filepath.Glob(filepath.Join(cfg.stateDir, "policy", "lkg*"))
	stale = append(stale, filepath.Join(cfg.stateDir, "receipt", "last-head"), memory.CustodyPath(cfg.stateDir), prevPath)
	for _, p := range stale {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	log.Info("mark1d: tenant switch settled", "from", prev.TenantID)
	return nil
}

// drainParked uploads every parked spool under the token it was captured under, never the live one, until it empties (then it is removed) or that token expires (then it stays on disk).
func drainParked(ctx context.Context, log *slog.Logger, stateDir string) <-chan struct{} {
	done := make(chan struct{})
	dirs, _ := filepath.Glob(filepath.Join(parkedRoot(stateDir), "*"))
	var wg sync.WaitGroup
	for _, dir := range dirs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := os.Stat(filepath.Join(dir, "spool")); errors.Is(err, os.ErrNotExist) {
				_ = os.RemoveAll(dir) // a settle interrupted before its spool moved; the rerun parked it elsewhere
				return
			}
			sp, err := spool.Open(spool.Config{Dir: filepath.Join(dir, "spool")})
			if err != nil {
				log.Error("mark1d: parked spool unreadable", "dir", dir, "err", err)
				return
			}
			emptied := drainParkedSpool(ctx, log, stateDir, dir, sp)
			if err := sp.Close(); err == nil && emptied {
				_ = os.RemoveAll(dir)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
}

func drainParkedSpool(ctx context.Context, log *slog.Logger, stateDir, dir string, sp *spool.Spool) bool {
	empty := func() bool {
		ack, write := sp.Cursors()
		return ack == write
	}
	if empty() {
		return true
	}
	doc, err := readEnrollmentFile(filepath.Join(dir, "enrollment.json"))
	if err == nil && (doc.State == "revoked" || doc.DeviceToken == "" || doc.Endpoints.Ingest == "" || !time.Now().Before(doc.TokenExpiresAt)) {
		err = errors.New("its token is revoked or expired")
	}
	if err != nil {
		log.Warn("mark1d: parked spool kept on disk, not uploaded", "dir", dir, "err", err)
		return false
	}
	spillPub, err := os.ReadFile(filepath.Join(stateDir, "spill", "spill.pub"))
	if err != nil {
		log.Error("mark1d: parked spool not drained", "dir", dir, "err", err)
		return false
	}
	// ponytail: no Checkpoint — parked events land unreceipted; a sealer over the parked identity if that tail ever matters.
	up, err := uplink.New(uplink.Config{
		Store: sp, Drops: []uplink.DropSource{sp}, Tokens: uplink.StaticToken(doc.DeviceToken),
		Endpoint: doc.Endpoints.Ingest, EdgeVersion: version,
		QuarantineDir: filepath.Join(stateDir, "quarantine"),
		Seal:          func(p []byte) ([]byte, error) { return spill.Seal(spillPub, p, time.Now()) },
		Log:           log,
	})
	if err != nil {
		log.Error("mark1d: parked spool not drained", "dir", dir, "err", err)
		return false
	}
	pctx, cancel := context.WithDeadline(ctx, doc.TokenExpiresAt)
	defer cancel()
	for {
		up.Flush(pctx)
		if empty() {
			log.Info("mark1d: parked spool drained under its own identity", "tenant_id", doc.TenantID, "dir", dir)
			return true
		}
		select {
		case <-pctx.Done():
			return false
		case <-time.After(parkedRetry):
		}
	}
}
