// The 08 §3.2 wire leg: the ETag-conditional bundle GET (the correctness
// path), the SSE hint stream (the latency path), the ACK POST, and the
// /.well-known/mark1-keys head read. Nothing here decides anything — every
// response is either bytes for policy.VerifyAndDecode or a retryable failure.
package bundle

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
)

// Paths hang off the configured origin. 08 §3.2 puts the three policy routes
// under /api/v1/policy; 08 §3.5 puts the key manifest at the well-known root,
// unauthenticated by design.
const (
	pathBundle = "/api/v1/policy/bundle"
	pathStream = "/api/v1/policy/stream"
	pathAck    = "/api/v1/policy/ack"
	pathKeys   = "/.well-known/mark1-keys"
)

// ackBodyLimit bounds the ACK/keys responses: both are a JSON sentence, never
// data.
const ackBodyLimit = 1 << 20

type fetchResult struct {
	body        []byte
	etag        string
	seq         string // X-Mark1-Bundle-Seq — an unauthenticated transport echo
	notModified bool
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("X-Mark1-Edge-Version", c.edgeVersion)
	return req, nil
}

// getBundle is the conditional poll. A 304 is the common case and costs
// nothing; anything that is not 200 or 304 is a transport failure the caller
// backs off on — including 404 (M1E-3004, unknown channel), which is a SERVER
// condition and per policy.proto can never become an edge ACK.
func (c *Client) getBundle(ctx context.Context) (*fetchResult, error) {
	req, err := c.request(ctx, http.MethodGet, pathBundle+"?channel="+url.QueryEscape(c.channel), nil)
	if err != nil {
		return nil, err
	}
	if c.lkg != nil && c.lkg.etag != "" {
		req.Header.Set("If-None-Match", c.lkg.etag)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return &fetchResult{notModified: true}, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("policy bundle GET: HTTP %d", resp.StatusCode)
	}
	// One byte past the decoder's ceiling, so an oversized body still reaches
	// VerifyAndDecode and is rejected as too_large rather than silently
	// truncated into a canonical-form error.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, policy.MaxBundleLen+1))
	if err != nil {
		return nil, err
	}
	return &fetchResult{
		body: raw,
		etag: resp.Header.Get("ETag"),
		seq:  resp.Header.Get("X-Mark1-Bundle-Seq"),
	}, nil
}

// keyManifest is the subset of 08 §3.5 this client reads. The section keys in
// the same document are deliberately NOT read: they live in local pinned
// custody (see the package comment).
type keyManifest struct {
	Tlog struct {
		Head *struct {
			Size uint64 `json:"size"`
			Root string `json:"root"`
		} `json:"head"`
	} `json:"tlog"`
}

// getHead reads the pinned log head. A missing `tlog.head` is not an error —
// a deployment with no transparency log serves only bundle zero, whose
// inclusion is structurally waived (D-P).
func (c *Client) getHead(ctx context.Context) (*policy.TlogHead, error) {
	req, err := c.request(ctx, http.MethodGet, pathKeys, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("key manifest GET: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, ackBodyLimit))
	if err != nil {
		return nil, err
	}
	var km keyManifest
	if err := json.Unmarshal(raw, &km); err != nil {
		return nil, err
	}
	if km.Tlog.Head == nil {
		return nil, nil
	}
	// The manifest renders the root as an algorithm-prefixed string in 08's
	// examples; accept both that and bare hex rather than fail closed on a
	// cosmetic prefix.
	root := km.Tlog.Head.Root
	if i := strings.IndexByte(root, ':'); i >= 0 {
		root = root[i+1:]
	}
	rb, err := hex.DecodeString(root)
	if err != nil || len(rb) != 32 {
		return nil, fmt.Errorf("key manifest tlog head root is not 32 hex bytes")
	}
	return &policy.TlogHead{TreeSize: km.Tlog.Head.Size, Root: [32]byte(rb)}, nil
}

// ackBody is m1p.v1.BundleAck in proto3 canonical JSON (08 §3.2). `seq` is a
// string because proto3 renders uint64 that way; `sections_skipped` is absent
// because this edge never skips — see queueAck.
type ackBody struct {
	Channel    string `json:"channel"`
	Seq        string `json:"seq"`
	BundleHash string `json:"bundle_hash"`
	Result     string `json:"result"`
	RejectCode string `json:"reject_code,omitempty"`
}

// queueAck records the ACK we owe. Only the latest is held: the ledger reads
// adoption per (device, channel, seq) and an ACK for a seq we have already
// moved past tells the canary controller nothing it cannot infer from the
// newer one.
//
// `sections_skipped` / result "partial" (08 §10.3 rule 2) is DEFERRED, not
// forgotten: skip-and-retain needs per-section `section_version` negotiation,
// and neither policy decoder surfaces a section version today, so an edge that
// reported "partial" would be reporting a state it cannot enter.
func (c *Client) queueAck(a *ackBody) { c.pending = a }

// flushAck is one best-effort attempt. A failure leaves the ACK pending for
// the next tick — 05 §4.3 widens on ACK COVERAGE, so a silently dropped ACK
// reads as a device that never adopted.
func (c *Client) flushAck(ctx context.Context) {
	a := c.pending
	if a == nil {
		return
	}
	raw, err := json.Marshal(a)
	if err != nil {
		c.log.Error("mark1d: encoding bundle ACK", "err", err)
		c.pending = nil
		return
	}
	req, err := c.request(ctx, http.MethodPost, pathAck, bytes.NewReader(raw))
	if err != nil {
		c.log.Warn("mark1d: bundle ACK deferred", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		c.log.Warn("mark1d: bundle ACK deferred", "err", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, ackBodyLimit))
	if resp.StatusCode != http.StatusOK {
		c.log.Warn("mark1d: bundle ACK refused; will retry", "status", resp.StatusCode, "seq", a.Seq)
		return
	}
	c.pending = nil
}

// stream is the advisory SSE leg (08 §3.2). It never carries a bundle and
// never applies anything — it only wakes the poll loop early. A dead stream
// degrades latency from seconds to one poll interval, never correctness, so
// every failure here is a reconnect with backoff and nothing else.
func (c *Client) stream(ctx context.Context) {
	for attempt := 1; ctx.Err() == nil; {
		if c.streamOnce(ctx) {
			attempt = 1
		} else {
			attempt++
		}
		t := time.NewTimer(c.backoff(attempt))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// streamOnce holds one connection open. It returns true if the stream
// delivered anything at all, which is what resets the reconnect backoff — a
// server that accepts and immediately closes must not be reconnected to in a
// tight loop.
func (c *Client) streamOnce(ctx context.Context) bool {
	req, err := c.request(ctx, http.MethodGet, pathStream+"?channel="+url.QueryEscape(c.channel), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4096), sseLineMax)
	event, got := "", false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[len("event:"):])
		case line == "":
			// End of one SSE block. `revocation` is deliberately ignored here:
			// re-checking the fail-closed classes is enrollment's (08 §3.4),
			// and a policy client that acted on it would be acting outside its
			// own contract.
			if event == "bundle" {
				got = true
				c.nudge()
			}
			event = ""
		}
	}
	return got
}

func (c *Client) nudge() {
	select {
	case c.hint <- struct{}{}:
	default: // a fetch is already queued: one in flight is the bound
	}
}
