// Package bundle is the edge's PolicyBundle intake path (FR-POLICY-004/-005,
// 04 §9.4). It is the wiring between the two halves that already existed:
// policy.VerifyAndDecode (which decides whether bytes are a bundle) and
// verdict.FromBundle (which renders an accepted bundle as the verdict plane's
// matrices). Everything here is transport, custody and the state machine
// between them; not one verification rule is re-implemented.
//
// 04 §9.4, as code:
//
//	RUNNING_LKG   boot on the persisted last-known-good (built-ins if none)
//	FETCHED       ETag poll 200, or SSE hint → GET; bytes in hand
//	RUNNING_NEW   verify + decode OK → swap matrices, persist LKG, ACK applied
//	RUNNING_LKG   M1E-3001/3002/3003/3005 → KEEP LKG, ACK rejected(code)
//	BUILTINS      LKG past max_age → conservative built-ins, verdicts stale_cert
//
// The single rule the rest serves: a rejected bundle NEVER downgrades the edge
// below its last-known-good, and an unreachable control plane changes nothing
// at all. Fail-static is not fail-open — the only thing that lowers the edge's
// posture is the CLOCK passing max_age, which is FR-POLICY-005's specified
// behaviour and is flagged (M1E-3006 stale_cert), never silent.
//
// TRUST MATERIAL SPLIT, and why it is not symmetric. The section-signing keys
// are read from LOCAL pinned custody (<state>/policy/keys.json) and never from
// the control plane: a server that hands out both the signature and the key it
// verifies against has not been checked. The transparency-log head is the
// opposite case — it MUST advance as the log grows (the frozen vectors prove
// it: seq 1's proof targets tree_size 1, seq 2's targets tree_size 3), so a
// head frozen into local custody would verify exactly one bundle and then
// refuse the rest forever. It is therefore fetched from /.well-known/mark1-keys
// (08 §3.5) — a DIFFERENT endpoint from the bundle, which is what keeps D-S's
// property: the inclusion proof is never verified against a root the bundle
// itself carried.
//
// ponytail: the fetched head is trusted on the strength of TLS to the control
// plane, not on its own signature. 08 §3.5 shows the head carrying a `sig` but
// freezes no signing input for it, and 05 §4.4 puts head witnessing in the
// hourly witness bucket, outside this daemon.
//
// Ceiling, stated at its true size (D-BB): the uncovered adversary is not a
// MITM — TLS closes that — it is OMIUM, the publisher the log exists to
// constrain. A control plane that is compromised or coerced can serve this
// device a forked view: a targeted bundle plus a head whose root commits to it,
// consistent under every check this file makes. 08 §3.5 says so in as many
// words ("a forked view is detectable by comparison, not prevented by auth")
// and names the compensating control: hourly external witness comparison. That
// witness is specified and NOT YET BUILT, so today the inclusion-proof check
// constrains an outsider and not the publisher. Verifying head.sig would not
// close this either — the signer would be the same party.
//
// Upgrade path, in the order that actually helps: (1) the external witness of
// 05 §4.4, which is what makes a fork detectable at all; (2) verify head.sig
// against a pinned ring once ADR-0004's key ceremony freezes the signed bytes
// and picks the signer — the ring already has a home in keys.json.
//
// KEY ROTATION (ADR-0004) is the one way the pinned ring grows without an
// operator touching keys.json: a bundle signed by a key we do not pin triggers
// ONE read of the manifest, and a new section key is admitted iff its
// cross_sig is by a key ALREADY pinned for that same section. A self-signed
// key, a key endorsed from outside its section, or a manifest whose update
// key is also a bundle key (R5) admits nothing; the bundle is then refused as
// before and last-known-good stays in force.
package bundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

const (
	// defaultPoll is 08 §3.2's "jittered 5-min interval" — the CORRECTNESS
	// path. SSE only ever makes an apply earlier than this, never later.
	defaultPoll = 5 * time.Minute
	// backoffCap matches uplink's: past half an hour of failures, retrying
	// harder is noise, and fail-static means nothing is waiting on it.
	backoffCap = 30 * time.Minute
	// freshEvery paces the max_age re-evaluation. It is not a doc number: it
	// only bounds how long the edge keeps serving a bundle that aged out
	// between polls, and the poll re-evaluates too.
	freshEvery = 30 * time.Second
	// sseLineMax bounds one SSE line. Hints are two integers; anything larger
	// is a broken or hostile stream, not a bigger hint.
	sseLineMax = 1 << 16
)

// Config wires one Client. Every field is optional except StateDir: a Client
// with no BaseURL is a legal, fully-functional edge that runs its persisted
// last-known-good forever (FR-POLICY-005's blackhole case as a configuration).
type Config struct {
	// StateDir is the daemon state root; bundle custody is <StateDir>/policy.
	StateDir string
	// BaseURL is the control-plane ORIGIN (08 §3.2/§3.5 paths hang off it).
	// Empty = never fetch.
	BaseURL string
	// Channel per 08 §3.2; empty defaults to "stable".
	Channel string
	// Token is the bearer device token. DEV SEAM, same as the uplink's:
	// enrollment (08 §3.1) issues the real ≤24 h one.
	Token       string
	EdgeVersion string
	Log         *slog.Logger
	// Health receives the applied-posture gauges (seq/age_s/stale); nil is legal.
	Health *obs.Health

	// Test seams; nil/zero ⇒ production defaults.
	HTTPClient *http.Client
	Now        func() time.Time
	After      func(d time.Duration) <-chan time.Time
	Rand       func() float64 // U(0,1) full-jitter source
	Poll       time.Duration
	FreshEvery time.Duration
}

// applied is one bundle in force: the bytes (so a re-serve is recognised
// without re-verifying), the decode, the ETag that names it upstream, and the
// log head it was verified AGAINST — retained because that head is the only
// one its inclusion proof will ever reproduce, so a boot re-verification must
// use it and not whatever the log has grown to since.
type applied struct {
	raw  []byte
	b    *policy.Bundle
	etag string
	head *policy.TlogHead
}

// Client is single-goroutine-owned: New runs on the caller's goroutine before
// Run starts, and every field below is touched only by Run afterwards.
type Client struct {
	dir         string
	baseURL     string
	channel     string
	token       string
	edgeVersion string
	keys        *policy.SectionKeys
	trust       trustFile // the pinned entries keys was built from; rotation appends here
	log         *slog.Logger
	health      *obs.Health
	http        *http.Client
	now         func() time.Time
	after       func(time.Duration) <-chan time.Time
	rand        func() float64
	poll        time.Duration
	freshEvery  time.Duration

	// Apply publishes accepted matrices into the verdict plane
	// (verdict.Engine.SetBundle). MUST be set before Run and never after: Run
	// owns it from then on. nil is legal — the client then only maintains
	// custody, which is what a test of the persistence half wants.
	Apply func(verdict.BundleMatrices)
	// ApplyRanker publishes the applied bundle's cortex learned_ranker (nil
	// when absent or stale) under the same rules as Apply; cortex.Plane.SetRanker.
	ApplyRanker func(*policy.LearnedRanker)

	lkg  *applied
	boot verdict.BundleMatrices
	// pending is the one ACK we still owe the ledger. Canary widening reads
	// ACK coverage (05 §4.3), so an ACK lost to a blip is re-offered on the
	// next tick rather than dropped; only the LATEST is kept, because an ACK
	// for a superseded seq tells the controller nothing it cannot infer.
	pending   *ackBody
	published struct {
		seq   uint64
		stale bool
	}
	hint chan struct{}
}

// New loads custody and computes the boot posture. It performs NO network I/O
// and never blocks on the control plane: a daemon whose control plane is down
// at boot must come up on last-known-good (or built-ins) immediately.
func New(cfg Config) (*Client, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("bundle: StateDir required")
	}
	c := &Client{
		dir:         filepath.Join(cfg.StateDir, "policy"),
		baseURL:     cfg.BaseURL,
		channel:     cfg.Channel,
		token:       cfg.Token,
		edgeVersion: cfg.EdgeVersion,
		log:         cfg.Log,
		health:      cfg.Health,
		http:        cfg.HTTPClient,
		now:         cfg.Now,
		after:       cfg.After,
		rand:        cfg.Rand,
		poll:        cfg.Poll,
		freshEvery:  cfg.FreshEvery,
		hint:        make(chan struct{}, 1),
	}
	if c.channel == "" {
		c.channel = "stable"
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if c.http == nil {
		// No redirect following, for the reason uplink gives: a redirect is a
		// middlebox answering, and bundle bytes from a middlebox are bytes we
		// would rather never hand a verifier.
		c.http = &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.after == nil {
		c.after = time.After
	}
	if c.rand == nil {
		c.rand = rand.Float64
	}
	if c.poll <= 0 {
		c.poll = defaultPoll
	}
	if c.freshEvery <= 0 {
		c.freshEvery = freshEvery
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, err
	}

	c.keys, c.trust = c.loadKeys()
	if c.keys == nil {
		// No pinned keys ⇒ nothing can ever verify ⇒ built-ins forever. That
		// is the honest posture, not an error: the daemon's job is capture,
		// and policy is an enhancement it can run without.
		c.log.Warn("mark1d: no pinned bundle signing keys; policy stays on built-in defaults (FR-POLICY-005)", "path", filepath.Join(c.dir, keysFile))
	} else {
		c.lkg = c.loadLKG()
	}
	c.boot, c.published.seq, c.published.stale = c.posture()
	c.report()
	return c, nil
}

// Matrices is the boot value for verdict.NewEngine. Call it before Run.
func (c *Client) Matrices() verdict.BundleMatrices { return c.boot }

// Cortex is the applied bundle's cortex section under the same freshness
// posture as Matrices: no bundle, or one past max_age, is the zero section,
// which cortex.BudgetFrom maps to the compiled default. Read once at boot
// before Run, so it needs no lock -- the daemon does not respawn cortexd on
// a bundle change (NFR-FOOTPRINT-003 residual: budget applies at next boot).
func (c *Client) Cortex() policy.CortexSection {
	if b := c.fresh(); b != nil {
		return b.Cortex
	}
	return policy.CortexSection{}
}

func (c *Client) Memory() policy.MemorySection {
	if b := c.fresh(); b != nil {
		return b.Memory
	}
	return policy.MemorySection{}
}

// Gates is the applied bundle's gates section under the same freshness
// posture as Matrices and Cortex: no bundle, or one past max_age, is the zero
// section -- stop_gate_enabled false, which is FR-POLICY-005's "gates open".
// Boot-only like Cortex: fabric.Gate.ApplyGates clamps it into the gate
// before Serve (FR-POLICY-006), so a later bundle's gates apply at next boot.
func (c *Client) Gates() policy.GatesSection {
	if b := c.fresh(); b != nil {
		return b.Gates
	}
	return policy.GatesSection{}
}

// fresh is the last-known-good bundle while it is inside max_age, else nil --
// the one freshness rule every boot-time section accessor reads through.
func (c *Client) fresh() *policy.Bundle {
	if c.lkg == nil || !c.lkg.b.IsFresh(c.epoch()) {
		return nil
	}
	return c.lkg.b
}

// Run drives the state machine until ctx is done. It returns only on
// cancellation; every failure inside is logged and retried, never fatal.
func (c *Client) Run(ctx context.Context) {
	if c.canFetch() {
		go c.stream(ctx)
	}
	fresh := c.after(c.freshEvery)
	poll := c.after(c.nextPoll())

	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-fresh:
			// The BUILTINS edge of 04 §9.4, and the way back from it. No
			// fetch: this transition is driven by the clock alone.
			c.publish()
			fresh = c.after(c.freshEvery)
			continue
		case <-c.hint:
		case <-poll:
		}
		if c.tick(ctx) {
			attempt = 0
			poll = c.after(c.nextPoll())
		} else {
			attempt++
			poll = c.after(c.backoff(attempt))
		}
	}
}

func (c *Client) canFetch() bool { return c.baseURL != "" && c.keys != nil }

// tick is one fetch→verify→apply/reject→ACK pass. It returns false only for a
// RETRYABLE transport failure (the caller then backs off); a bundle that was
// fetched and refused is a successful tick — refusing it again sooner does not
// help, and the ACK has already told the ledger.
func (c *Client) tick(ctx context.Context) bool {
	if !c.canFetch() {
		return true
	}
	if c.pending != nil {
		c.flushAck(ctx)
	}
	res, err := c.getBundle(ctx)
	if err != nil {
		c.log.Warn("mark1d: policy fetch failed; last-known-good stays in force (FR-POLICY-005)", "err", err)
		return false
	}
	if res.notModified {
		return true
	}
	if c.lkg != nil && bytes.Equal(res.body, c.lkg.raw) {
		// The same bytes we already run, re-served because our ETag was lost
		// (a fresh custody dir, a 304-less proxy). Verifying them would hit
		// the anti-rollback rule and emit a spurious `rejected` ACK, which is
		// exactly what the canary controller's halt rule counts (05 §4.3).
		c.lkg.etag = res.etag
		return true
	}
	// A head we cannot fetch is not evidence that the bundle is bad — it is a
	// missing input. Treating it as retryable keeps M1E-3003 meaning "the
	// proof did not check out" instead of "our network hiccuped".
	head, err := c.getHead(ctx)
	if err != nil {
		c.log.Warn("mark1d: tlog head unavailable; deferring bundle apply", "err", err)
		return false
	}

	var lastSeq *uint64
	if c.lkg != nil {
		lastSeq = &c.lkg.b.Seq
	}
	b, rej := policy.VerifyAndDecode(res.body, c.keys, lastSeq, head)
	if rej != nil && rej.Kind() == "unknown_key" && c.admitRotation(ctx) {
		b, rej = policy.VerifyAndDecode(res.body, c.keys, lastSeq, head)
	}
	if rej != nil {
		c.reject(ctx, res, rej.Code(), rej.Error())
		return true
	}
	if code, why := c.callerChecks(b); code != "" {
		c.reject(ctx, res, code, why)
		return true
	}

	c.lkg = &applied{raw: res.body, b: b, etag: res.etag, head: head}
	c.persist(c.lkg)
	c.publish()
	c.queueAck(&ackBody{
		Channel:    c.channel,
		Seq:        fmt.Sprintf("%d", b.Seq),
		BundleHash: hashLabel(b.BodySHA256[:]),
		Result:     "applied",
	})
	c.flushAck(ctx)
	c.log.Info("mark1d: policy bundle applied", "seq", b.Seq, "channel", b.Channel, "max_age_s", b.MaxAgeS)
	return true
}

// callerChecks are the two rules VerifyAndDecode structurally cannot make,
// both documented as the caller's: 04 §7.3 ("the last-accepted body hash lives
// in the caller's LKG state") and 08 §3.2's per-(tenant, channel) sequencing.
// Both land in the M1E-3001 family per 05 §4.6's table.
func (c *Client) callerChecks(b *policy.Bundle) (code, why string) {
	if b.Channel != c.channel {
		// seq is monotonic per (tenant, CHANNEL). Applying another channel's
		// bundle would advance our anti-rollback floor against a sequence that
		// is not ours, permanently locking out our own channel's next bundle.
		return "M1E-3001", fmt.Sprintf("bundle channel %q served on channel %q", b.Channel, c.channel)
	}
	// Linkage is only checkable when the bundle is the DIRECT successor of
	// what we run. 05 §4.6(2) makes gaps normal — an edge that never saw seq N
	// applies N+1 — and across a gap we hold none of the intervening bodies,
	// so the inclusion proof is the evidence and prev_hash is unverifiable.
	if c.lkg != nil && b.Seq == c.lkg.b.Seq+1 && b.PrevHash != c.lkg.b.BodySHA256 {
		return "M1E-3001", "prev_hash does not chain from the applied bundle (fork indicator)"
	}
	return "", ""
}

func (c *Client) reject(ctx context.Context, res *fetchResult, code, why string) {
	// The seq label comes from the transport header echo, which 08 §3.2 says
	// participates in no verification step. That is precisely why it is safe
	// here and nowhere else: this ACK is a statement about bytes we REFUSED,
	// so the only honest identifier is the one the server filed them under.
	// bundle_hash is over the raw bytes rather than the canonical body — a
	// bundle that failed the canonical-form check has no body to hash.
	sum := sha256.Sum256(res.body)
	c.log.Error("mark1d: policy bundle rejected; last-known-good retained (FR-POLICY-004)",
		"code", code, "why", why, "served_seq", res.seq, "applied_seq", c.appliedSeq())
	c.queueAck(&ackBody{
		Channel:    c.channel,
		Seq:        res.seq,
		BundleHash: hashLabel(sum[:]),
		Result:     "rejected",
		RejectCode: code,
	})
	c.flushAck(ctx)
}

func (c *Client) appliedSeq() int64 {
	if c.lkg == nil {
		return -1
	}
	return int64(c.lkg.b.Seq) // #nosec G115 -- diagnostic log field only
}

// posture renders the CURRENT matrices, the seq they came from, and whether
// the edge is running degraded. This is FR-POLICY-005's two halves in one
// place: no bundle ⇒ built-ins; a bundle past max_age ⇒ built-ins, gates open,
// verdicts flagged stale_cert (M1E-3006). The bundle is NOT discarded when it
// goes stale — a clock correction or a fresh publication restores it.
func (c *Client) posture() (verdict.BundleMatrices, uint64, bool) {
	if c.lkg == nil {
		return verdict.Builtins(), 0, true
	}
	if !c.lkg.b.IsFresh(c.epoch()) {
		return verdict.Builtins(), c.lkg.b.Seq, true
	}
	m, err := verdict.FromBundle(c.lkg.b)
	if err != nil {
		return verdict.Builtins(), c.lkg.b.Seq, true
	}
	return *m, c.lkg.b.Seq, m.Stale
}

// publish swaps the verdict plane onto the current posture, and only when the
// posture actually moved — the freshness ticker calls this every 30 s.
func (c *Client) publish() {
	m, seq, stale := c.posture()
	if seq == c.published.seq && stale == c.published.stale {
		return
	}
	wasStale := c.published.stale
	c.published.seq, c.published.stale = seq, stale
	c.report()
	if c.Apply != nil {
		c.Apply(m)
	}
	if c.ApplyRanker != nil {
		c.ApplyRanker(c.Cortex().LearnedRanker)
	}
	switch {
	case stale && !wasStale:
		c.log.Warn("mark1d: policy past max_age — conservative built-ins, gates open, verdicts flagged stale_cert (M1E-3006)", "seq", seq)
	case !stale && wasStale:
		c.log.Info("mark1d: policy fresh again", "seq", seq)
	}
}

// report mirrors the published posture into the health table. Called from New
// as well as publish: a daemon that never reaches its control plane is running
// built-ins on purpose, and that is a posture worth reporting, not an absence.
// issued_at comes off the bundle rather than the clock, so age_s is publication
// age — no bundle means 0, which ageS reads as "never", with stale=1 alongside.
func (c *Client) report() {
	var issued uint64
	if c.lkg != nil {
		issued = c.lkg.b.IssuedAtEpochS
	}
	c.health.Bundle(c.published.seq, issued, c.published.stale)
}

func (c *Client) epoch() uint64 {
	s := c.now().Unix()
	if s < 0 {
		return 0
	}
	return uint64(s)
}

// backoff is full jitter over a capped exponential whose BASE is the poll
// interval: the first failure retries no sooner than a normal poll would, so a
// down control plane can never be hammered harder than a healthy one.
func (c *Client) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	exp := float64(c.poll) * math.Pow(2, float64(attempt-1))
	return time.Duration(math.Min(exp, float64(backoffCap)) * c.rand())
}

// nextPoll is 08 §3.2's jittered 5-minute cadence: ±25%, so a fleet that
// restarted together does not stay in lockstep.
func (c *Client) nextPoll() time.Duration {
	return time.Duration(float64(c.poll) * (0.75 + 0.5*c.rand()))
}

// hashLabel renders a 32-byte digest the way 08 §3.2's ACK example does. The
// digest IS SHA-256 (07 and 05 §4.4, over the bundle's canonical bytes); this
// used to emit `blake3:` because 08 §3.2 divergence row 3 said so, and that row
// has since moved to `sha256:` — resolved while no server counterpart exists to
// coordinate with. The prefix is out-of-band metadata the proto does not carry.
func hashLabel(sum []byte) string { return "sha256:" + hex.EncodeToString(sum) }

// ── custody ─────────────────────────────────────────────────────────────

const (
	keysFile = "keys.json"
	lkgFile  = "lkg.cbor"
	metaFile = "lkg.json"
)

// trustFile is the local pinned signing material, shaped after 08 §3.5's
// `bundle_section_keys` so enrollment can eventually write the manifest's
// subset straight through. `key_id` is deliberately absent: SectionKeys
// DERIVES it, so a ring can never hold a key under a name that will not
// verify it. cross_sig is kept on an admitted key as its provenance.
type trustFile struct {
	BundleSectionKeys []pinnedKey `json:"bundle_section_keys"`
}

type pinnedKey struct {
	Section   string    `json:"section"`
	PubkeyHex string    `json:"pubkey_hex"`
	NotBefore string    `json:"not_before"`
	NotAfter  string    `json:"not_after"`
	CrossSig  *crossSig `json:"cross_sig,omitempty"`
}

type crossSig struct {
	ByKeyID      string `json:"by_key_id"`
	SignatureHex string `json:"signature_hex"`
}

// loadKeys returns nil when there is no usable pinned material — the caller
// then never fetches, which is the correct posture: unverifiable bundles are
// worse than no bundles.
func (c *Client) loadKeys() (*policy.SectionKeys, trustFile) {
	raw, err := os.ReadFile(filepath.Join(c.dir, keysFile))
	if err != nil {
		return nil, trustFile{}
	}
	var tf trustFile
	if err := json.Unmarshal(raw, &tf); err != nil {
		c.log.Error("mark1d: pinned bundle keys unparseable", "err", err)
		return nil, trustFile{}
	}
	sk, err := ringOf(tf)
	if err != nil {
		c.log.Error("mark1d: pinned bundle keys unusable", "err", err)
		return nil, trustFile{}
	}
	return sk, tf
}

func sectionOf(name string) (policy.Section, bool) {
	for _, s := range policy.AllSections() {
		if s.Name() == name {
			return s, true
		}
	}
	return 0, false
}

// ringOf builds the section-split ring from pinned entries; nil with no
// error means the file pins nothing.
func ringOf(tf trustFile) (*policy.SectionKeys, error) {
	sk := policy.NewSectionKeys()
	for _, e := range tf.BundleSectionKeys {
		s, ok := sectionOf(e.Section)
		if !ok {
			return nil, fmt.Errorf("pinned key names an unknown section class %q", e.Section)
		}
		pub, err := hex.DecodeString(e.PubkeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pinned %s key is not a 32-byte hex ed25519 public key", e.Section)
		}
		sk.Insert(s, policy.KeyEntry{Public: pub, NotBefore: e.NotBefore, NotAfter: e.NotAfter})
	}
	if len(tf.BundleSectionKeys) == 0 {
		return nil, nil
	}
	return sk, nil
}

// crossSignDomain and crossSignInput mirror controld's receipts.CrossSignInput
// and rust/mark1-policy's cross_sign_input: domain || role || 0x00 || pub.
const crossSignDomain = "mark1-key-rotation-v1\x00"

func crossSignInput(role string, pub []byte) []byte {
	out := append([]byte(crossSignDomain), role...)
	out = append(out, 0)
	return append(out, pub...)
}

// admitRotation reads the key manifest once and admits every section key it
// does not yet pin whose cross_sig is by a key ALREADY pinned for that
// section (rust/mark1-policy apply_rotation, mirrored). All or nothing: one
// refusal admits no key, so a manifest cannot smuggle a root in beside a
// genuine rotation. Returns true iff the ring grew.
func (c *Client) admitRotation(ctx context.Context) bool {
	req, err := c.request(ctx, http.MethodGet, pathKeys, nil)
	if err != nil {
		return false
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.log.Warn("mark1d: key manifest unavailable; rotation not applied", "err", err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, ackBodyLimit))
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	var km struct {
		BundleSectionKeys []pinnedKey `json:"bundle_section_keys"`
		UpdateKeys        []pinnedKey `json:"update_keys"`
	}
	if err := json.Unmarshal(raw, &km); err != nil {
		c.log.Error("mark1d: key manifest unparseable; rotation not applied", "err", err)
		return false
	}
	refuse := func(kind, why string) bool {
		c.log.Error("mark1d: key manifest refused; pinned ring unchanged, last-known-good retained (ADR-0004)", "kind", kind, "why", why)
		return false
	}
	for _, u := range km.UpdateKeys {
		for _, b := range km.BundleSectionKeys {
			if u.PubkeyHex == b.PubkeyHex {
				return refuse("update_equals_bundle", "update key "+u.PubkeyHex[:16]+" is also the "+b.Section+" section key (R5)")
			}
		}
	}
	pinned := map[string]map[string]ed25519.PublicKey{}
	for _, e := range c.trust.BundleSectionKeys {
		pub, _ := hex.DecodeString(e.PubkeyHex)
		if pinned[e.Section] == nil {
			pinned[e.Section] = map[string]ed25519.PublicKey{}
		}
		pinned[e.Section][identity.DeriveKeyID(pub)] = pub
	}
	staged := trustFile{BundleSectionKeys: append([]pinnedKey(nil), c.trust.BundleSectionKeys...)}
	admitted := 0
	for _, e := range km.BundleSectionKeys {
		if _, ok := sectionOf(e.Section); !ok {
			return refuse("unknown_section", e.Section)
		}
		pub, err := hex.DecodeString(e.PubkeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return refuse("key_id_mismatch", e.Section+" key is not a 32-byte hex public key")
		}
		id := identity.DeriveKeyID(pub)
		if _, have := pinned[e.Section][id]; have {
			continue
		}
		switch {
		case e.CrossSig == nil:
			return refuse("unsigned", id+" for "+e.Section+" carries no cross_sig")
		case e.CrossSig.ByKeyID == id:
			return refuse("self_signed", id+" cross-signs itself")
		}
		by, ok := pinned[e.Section][e.CrossSig.ByKeyID]
		if !ok {
			return refuse("unknown_signer", id+" is cross-signed by "+e.CrossSig.ByKeyID+", not pinned for "+e.Section)
		}
		sig, err := hex.DecodeString(e.CrossSig.SignatureHex)
		if err != nil || !ed25519.Verify(by, crossSignInput("bundle:"+e.Section, pub), sig) {
			return refuse("bad_cross_signature", id+" by "+e.CrossSig.ByKeyID)
		}
		staged.BundleSectionKeys = append(staged.BundleSectionKeys, e)
		admitted++
	}
	if admitted == 0 {
		return false
	}
	keys, err := ringOf(staged)
	if err != nil {
		return refuse("key_id_mismatch", err.Error())
	}
	c.keys, c.trust = keys, staged
	if raw, err := json.Marshal(staged); err == nil {
		if err := writeAtomic(filepath.Join(c.dir, keysFile), raw); err != nil {
			c.log.Error("mark1d: persisting rotated pinned keys", "err", err)
		}
	}
	c.log.Info("mark1d: bundle section key rotation admitted through pinned cross-signature (ADR-0004)", "admitted", admitted)
	return true
}

type lkgMeta struct {
	Seq           uint64 `json:"seq"`
	ETag          string `json:"etag"`
	AppliedAt     string `json:"applied_at"`
	BodySHA256Hex string `json:"body_sha256_hex"`
	HeadTreeSize  uint64 `json:"tlog_head_tree_size"`
	HeadRootHex   string `json:"tlog_head_root_hex"`
}

// loadLKG re-runs the FULL verification over the persisted bytes. The custody
// dir is 0700 in the user's own home, which is a boundary and not a proof:
// anything that could rewrite lkg.cbor could otherwise install policy no key
// ever signed. lastAppliedSeq is nil because this bundle IS the last applied —
// passing its own seq would make it its own replay.
func (c *Client) loadLKG() *applied {
	raw, err := os.ReadFile(filepath.Join(c.dir, lkgFile))
	if err != nil {
		return nil
	}
	metaRaw, err := os.ReadFile(filepath.Join(c.dir, metaFile))
	if err != nil {
		c.log.Error("mark1d: last-known-good bundle has no metadata; ignoring it", "err", err)
		return nil
	}
	var meta lkgMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		c.log.Error("mark1d: last-known-good metadata unparseable; ignoring it", "err", err)
		return nil
	}
	head, err := decodeHead(meta.HeadTreeSize, meta.HeadRootHex)
	if err != nil {
		c.log.Error("mark1d: last-known-good pinned head unreadable; ignoring it", "err", err)
		return nil
	}
	b, rej := policy.VerifyAndDecode(raw, c.keys, nil, head)
	if rej != nil {
		// Tampered, or signed by a key that has since been rotated out of the
		// pinned ring. Either way it is not evidence any more: built-ins.
		c.log.Error("mark1d: last-known-good bundle no longer verifies; falling to built-in defaults",
			"code", rej.Code(), "kind", rej.Kind(), "err", rej)
		return nil
	}
	if b.Seq != meta.Seq {
		c.log.Error("mark1d: last-known-good metadata disagrees with the bundle it describes; ignoring it",
			"meta_seq", meta.Seq, "bundle_seq", b.Seq)
		return nil
	}
	c.log.Info("mark1d: last-known-good policy bundle loaded", "seq", b.Seq, "channel", b.Channel)
	return &applied{raw: raw, b: b, etag: meta.ETag, head: head}
}

// persist writes custody atomically at 0600. A failure here is logged and does
// NOT block the apply: an edge that verified a bundle should run it, and the
// cost of a lost write is re-fetching after a restart, not wrong behaviour.
func (c *Client) persist(a *applied) {
	meta := lkgMeta{
		Seq:           a.b.Seq,
		ETag:          a.etag,
		AppliedAt:     c.now().UTC().Format(time.RFC3339),
		BodySHA256Hex: hex.EncodeToString(a.b.BodySHA256[:]),
	}
	if a.head != nil {
		meta.HeadTreeSize = a.head.TreeSize
		meta.HeadRootHex = hex.EncodeToString(a.head.Root[:])
	}
	metaRaw, err := json.Marshal(meta)
	if err != nil {
		c.log.Error("mark1d: encoding last-known-good metadata", "err", err)
		return
	}
	// Bytes first: a meta without its bundle is ignored on load, a bundle
	// without its meta is too — neither half alone can be mistaken for state.
	if err := writeAtomic(filepath.Join(c.dir, lkgFile), a.raw); err != nil {
		c.log.Error("mark1d: persisting last-known-good bundle", "err", err)
		return
	}
	if err := writeAtomic(filepath.Join(c.dir, metaFile), metaRaw); err != nil {
		c.log.Error("mark1d: persisting last-known-good metadata", "err", err)
	}
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func decodeHead(treeSize uint64, rootHex string) (*policy.TlogHead, error) {
	if rootHex == "" && treeSize == 0 {
		return nil, nil // seq-0 custody: D-P's pre-log waiver, structurally
	}
	root, err := hex.DecodeString(rootHex)
	if err != nil || len(root) != 32 {
		return nil, fmt.Errorf("tlog head root is not 32 hex bytes")
	}
	return &policy.TlogHead{TreeSize: treeSize, Root: [32]byte(root)}, nil
}
