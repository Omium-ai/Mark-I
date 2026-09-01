// Package spill is the receiving end of the hookshim's sanitized spill ring
// (04 §5.4): mark1d mints the device X25519 spill keypair — the private half
// lives only in daemon custody (04 §2.9), the public half is materialized at
// <state-dir>/spill/spill.pub for the shim to seal to — and the drain, on
// startup and periodically, unseals every ring entry, replays it through the
// SAME capture admission path (redact-admit included: spilled events were
// pre-redacted by the shim, but admission re-runs fail-closed anyway), then
// truncates the ring. Losses are never silent: entries past the ≤24 h TTL are
// dropped with Dropped{RING_EXPIRED} accounting (08 §4.4), the shim's
// overflow-shed sidecar converts to Dropped{RING_EVICTED} (04 §5.4's reason
// for ring-overflow loss), and undecryptable/undecodable entries are
// quarantine-accounted — the drain-side half of spill.rs's contract that a
// redaction-broken frame "is quarantined at drain".
package spill

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// Ring record layout, spill.rs's format verbatim:
// [u32 le record_len][ver=1][u64 le unix_secs][eph_pub 32][nonce 12][ciphertext].
const (
	recordVersion = 1
	recHeaderLen  = 1 + 8 + 32 + 12
	// minRecord: header + the AEAD tag of an empty plaintext.
	minRecord = recHeaderLen + 16
	// maxRecord: header + one M1PL frame (the shim spills exactly one encoded
	// frame per entry) + tag. Anything larger is not a record this ring wrote.
	maxRecord = recHeaderLen + fabric.MaxFrame + 16
)

// sealLabel is spill.rs's SEAL_LABEL: chacha key = HMAC-SHA256(DH shared
// secret, label), so the raw group element never keys the AEAD directly.
var sealLabel = []byte("m1p.spill.seal.v1")

// TTL is 04 §5.4 / 08 §4.4's hard bound: entries older than this are swept
// with receipted expiry, never replayed.
const TTL = 24 * time.Hour

// Drop reasons beyond the spool's own two, mirroring m1p.v1.DropReason
// numbering (envelope.proto) exactly as capture does — the uplink translation
// stays a cast.
const (
	dropLocalQuarantine spool.DropReason = 4 // DROP_REASON_LOCAL_QUARANTINE
	dropRingEvicted     spool.DropReason = 8 // DROP_REASON_RING_EVICTED
	dropRingExpired     spool.DropReason = 9 // DROP_REASON_RING_EXPIRED
)

// Drainer owns the ring's read side. The shim is the only writer; the drain
// renames the ring before reading so a shim mid-append either landed before
// the rename (drained now) or opens a fresh ring after it (drained next tick).
type Drainer struct {
	stateDir string
	adm      *capture.Admitter
	priv     *ecdh.PrivateKey

	// Now is the TTL clock, injectable for tests; the committed-fixture test
	// pins it so a frozen ring never "expires" the conformance check.
	Now func() time.Time
	// Health counts drained ring records as `shim.spilled`; nil is legal.
	Health *obs.Health
	// Settle is the one re-read grace for a torn tail: a shim that opened the
	// ring just before the rename finishes its single write_all within its
	// 50 ms budget, so one short wait turns an in-flight append into a whole
	// record instead of a quarantined half.
	Settle time.Duration
}

// Open loads-or-mints the device spill keypair and materializes the public
// half where spill.rs reads it (<state-dir>/spill/spill.pub). Key custody is
// identity's 0600 FileCustody floor (04 §2.9) — the same 32-byte seed shape
// as the device Ed25519 key, so the ladder's Keychain/TPM rungs slot in
// unchanged when enroll lands.
func Open(stateDir string, adm *capture.Admitter) (*Drainer, error) {
	c := identity.FileCustody{Path: filepath.Join(stateDir, "spill.key")}
	seed, err := c.Load()
	if errors.Is(err, identity.ErrNoKey) {
		seed = make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := c.Store(seed); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(stateDir, "spill")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// The pub file is derived state: rewrite whenever it diverges (a stale or
	// foreign pubkey would make the shim seal to a key this daemon cannot
	// open — every spill would then drain to quarantine).
	pub := priv.PublicKey().Bytes()
	pubPath := filepath.Join(dir, "spill.pub")
	if cur, err := os.ReadFile(pubPath); err != nil || !hmac.Equal(cur, pub) {
		if err := os.WriteFile(pubPath, pub, 0o600); err != nil {
			return nil, err
		}
	}
	return &Drainer{
		stateDir: stateDir,
		adm:      adm,
		priv:     priv,
		Now:      time.Now,
		Settle:   100 * time.Millisecond,
	}, nil
}

// Run drains once immediately (the restart scan, 04 §5), then on every tick
// until ctx ends. Errors are returned to the caller's logger and do not stop
// the loop — an unreplayable ring keeps its bytes for the next tick.
func (d *Drainer) Run(ctx context.Context, every time.Duration, onErr func(error)) {
	for {
		if err := d.Drain(ctx); err != nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// Drain performs one full pass: shed accounting, any leftover from a crashed
// prior drain, then the live ring. On an admission failure the drain file is
// KEPT for retry — replays are duplicate-safe because the shim stamps
// event_id and capture preserves writer-set ids (07 §2: the server dedupe
// key), so at-least-once is the correct posture here.
func (d *Drainer) Drain(ctx context.Context) error {
	dir := filepath.Join(d.stateDir, "spill")
	d.drainShed(dir)

	draining := filepath.Join(dir, "hookshim.ring.draining")
	if err := d.drainFile(ctx, draining); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(dir, "hookshim.ring"), draining); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return d.drainFile(ctx, draining)
}

// drainShed converts the shim's overflow sidecar (one byte per event refused
// at the 64 MiB writer cap, spill.rs) into Dropped{RING_EVICTED}. Rename
// first: a shim appending between read and delete would lose its count.
// Class is honestly unknowable without the refused payload — ClassUnknown,
// the tornClass precedent (07 §6 recovery step 4), never guessed.
func (d *Drainer) drainShed(dir string) {
	shed := filepath.Join(dir, "hookshim.ring.shed")
	tmp := shed + ".draining"
	if err := os.Rename(shed, tmp); err != nil {
		if _, statErr := os.Stat(tmp); statErr != nil {
			return // no fresh sidecar and no leftover
		}
	}
	if fi, err := os.Stat(tmp); err == nil {
		d.adm.AccountDropped(dropRingEvicted, spool.ClassUnknown, uint64(fi.Size())) // #nosec G115 -- a file size is non-negative
	}
	_ = os.Remove(tmp)
}

func (d *Drainer) drainFile(ctx context.Context, path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	recs, torn := parseRing(raw)
	if torn {
		// One settle re-read: an append in flight across the rename completes
		// within the shim's 50 ms budget; only then is a torn tail real.
		time.Sleep(d.Settle)
		if again, err := os.ReadFile(path); err == nil {
			raw = again
		}
		recs, torn = parseRing(raw)
	}
	quarantined, spilled := uint64(0), uint64(0)
	if torn {
		quarantined++ // the torn tail is one lost record, counted
	}
	now := d.Now()
	for _, rec := range recs {
		if rec.bad {
			quarantined++ // unreadable record version — skip by length, count
			continue
		}
		// Future timestamps are clock skew, not age — only the past expires.
		if ts := time.Unix(rec.unixSecs, 0); now.Sub(ts) > TTL {
			// 08 §4.4 / 04 §5.4: receipted expiry — dropped, never replayed.
			d.adm.AccountDropped(dropRingExpired, spool.ClassUnknown, 1)
			continue
		}
		payload, ok := d.unseal(rec)
		if !ok {
			quarantined++
			continue
		}
		// Ring records are whole FabricFrames (the shim spills what it would
		// have written to the socket); AdmitBytes takes the inner Event. The
		// live path unwraps in session.frame before the handler ever sees it.
		inner, err := fabric.UnwrapEvent(payload)
		if err != nil {
			quarantined++
			continue
		}
		err = d.adm.AdmitBytes(ctx, inner)
		switch {
		case err == nil,
			errors.Is(err, capture.ErrShed),
			errors.Is(err, capture.ErrQuarantined):
			// Admitted, or already accounted inside capture's own ledger.
			// Either way the shim reached the ring instead of the socket,
			// which is what `shim.spilled` measures (11 §3.3: the transient
			// shim holds no counters; the daemon counts its outcomes at drain).
			spilled++
		default:
			// Spool-level failure: keep the file, retry next tick. Anything
			// already admitted this pass replays then — event_id absorbs it.
			return fmt.Errorf("spill: drain admit: %w", err)
		}
	}
	d.adm.AccountDropped(dropLocalQuarantine, spool.ClassUnknown, quarantined)
	d.Health.Spilled(spilled)
	return os.Remove(path)
}

// Seal is the producer twin of spill.rs seal(): one ring record sealed to the
// device spill public key, stamped ts. In production the ONLY writer is the
// shim (mark1-hookshim links mark1-redact and sanitizes before sealing —
// invariant 5); this exists for the drain's own tests and the daemon-level
// replay test, and the committed shim-generated fixture in testdata/ is what
// keeps it from drifting away from the Rust bytes.
func Seal(pub, plaintext []byte, ts time.Time) ([]byte, error) {
	devicePub, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(devicePub)
	if err != nil {
		return nil, err
	}
	kdf := hmac.New(sha256.New, shared)
	kdf.Write(sealLabel)
	aead, err := chacha20poly1305.New(kdf.Sum(nil))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	if recHeaderLen+len(ct) > maxRecord {
		return nil, errors.New("spill: plaintext exceeds one M1PL frame")
	}
	rec := make([]byte, 0, 4+recHeaderLen+len(ct))
	rec = binary.LittleEndian.AppendUint32(rec, uint32(recHeaderLen+len(ct))) // #nosec G115 -- bounded above
	rec = append(rec, recordVersion)
	rec = binary.LittleEndian.AppendUint64(rec, uint64(max(ts.Unix(), 0))) // #nosec G115 -- clamped
	rec = append(rec, eph.PublicKey().Bytes()...)
	rec = append(rec, nonce...)
	return append(rec, ct...), nil
}

type ringRecord struct {
	bad      bool // record version this drain cannot read — quarantined
	unixSecs int64
	eph      []byte
	nonce    []byte
	ct       []byte
}

// parseRing walks spill.rs records off raw. torn=true means the tail was not
// a whole well-formed record — spill.rs writes each record in one append, so
// a torn tail is an interrupted writer, and everything before it is intact.
func parseRing(raw []byte) (recs []ringRecord, torn bool) {
	for len(raw) > 0 {
		if len(raw) < 4 {
			return recs, true
		}
		n := binary.LittleEndian.Uint32(raw[:4])
		if n < minRecord || n > maxRecord || len(raw) < 4+int(n) {
			return recs, true
		}
		rec := raw[4 : 4+n]
		raw = raw[4+n:]
		if rec[0] != recordVersion {
			// A future version is unreadable, not torn: skip by length so the
			// rest of the ring still drains; the entry itself quarantines.
			recs = append(recs, ringRecord{bad: true})
			continue
		}
		ts := binary.LittleEndian.Uint64(rec[1:9])
		recs = append(recs, ringRecord{
			unixSecs: int64(min(ts, 1<<62)), // #nosec G115 -- clamped
			eph:      rec[9:41],
			nonce:    rec[41:53],
			ct:       rec[53:],
		})
	}
	return recs, false
}

// unseal inverts spill.rs's seal(): X25519(device priv, ephemeral pub) →
// HMAC-SHA256(shared, "m1p.spill.seal.v1") → ChaCha20-Poly1305 open, then the
// plaintext must be exactly one M1PL frame whose payload feeds admission.
func (d *Drainer) unseal(rec ringRecord) ([]byte, bool) {
	eph, err := ecdh.X25519().NewPublicKey(rec.eph)
	if err != nil {
		return nil, false
	}
	shared, err := d.priv.ECDH(eph)
	if err != nil {
		return nil, false
	}
	kdf := hmac.New(sha256.New, shared)
	kdf.Write(sealLabel)
	aead, err := chacha20poly1305.New(kdf.Sum(nil))
	if err != nil {
		return nil, false
	}
	plain, err := aead.Open(nil, rec.nonce, rec.ct, nil)
	if err != nil {
		return nil, false
	}
	// Redaction may lawfully break the frame's length prefix (spill.rs:
	// redaction outranks replay fidelity) — such an entry quarantines here.
	var dec fabric.Decoder
	dec.Push(plain)
	payload, consumed, err := dec.Next()
	if err != nil || payload == nil || consumed != len(plain) {
		return nil, false
	}
	return payload, true
}
