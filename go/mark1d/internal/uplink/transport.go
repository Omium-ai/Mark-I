// The M1P/1 wire leg: plain HTTPS POST, never gRPC to the edge (08 §2).
// Headers are 08 §2.1 verbatim; the response grammar is 08 §2.4's table plus
// the JSON ack/error bodies controld emits ({"quarantined":[…]} /
// {"error":{"code","detail":{"event_ids":[…]}}}).
package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// TokenSource is the bearer-token seam (04 §2.9 owns the real one: device
// tokens ≤24 h from enrollment). Refresh is the 401 row of 08 §2.4 — the one
// retryable 4xx, and only after a successful re-auth.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	Refresh(ctx context.Context) error
}

// ErrNoRefresh is a TokenSource with no refresh path: per 08 §2.4's 401 row
// the batch then parks rather than quarantines.
var ErrNoRefresh = errors.New("uplink: token source has no refresh path")

// StaticToken is the dev/test TokenSource: a fixed bearer with no refresh.
// Enrollment (§3.1) wires the real one when it lands.
type StaticToken string

func (s StaticToken) Token(context.Context) (string, error) { return string(s), nil }
func (s StaticToken) Refresh(context.Context) error         { return ErrNoRefresh }

// ingestResp is one parsed server verdict. err-path fields and ack-path
// fields never coexist on the wire; both live here so the automaton switches
// on status alone.
type ingestResp struct {
	status      int
	retryAfter  time.Duration
	errCode     string
	quarantined []string // 202: server-quarantined event_ids (08 §2.4)
	badEventIDs []string // 422: invariant-violating event_ids (M1E-2006 detail)
}

// respBodyLimit bounds the ack/error read: bodies are a JSON sentence, never
// data — an oversized one is a broken or hostile server, not a bigger ack.
const respBodyLimit = 1 << 20

// post sends one composed batch. A non-nil error is a network-class failure
// (retryable per 08 §2.5); a non-2xx status is NOT an error here — the
// automaton owns the status table.
func (u *Uplink) post(ctx context.Context, b *outBatch) (*ingestResp, error) {
	tok, err := u.tokens.Token(ctx)
	if err != nil {
		// No token ⇒ no egress, capture untouched (04 §1.4: tokens gate
		// egress only) — surfaces as a retryable failure, parking eventually.
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.endpoint, bytes.NewReader(b.body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-m1p-protobuf")
	req.Header.Set("Content-Encoding", "zstd")
	req.Header.Set("M1P-Schema", "m1p.v1")
	req.Header.Set("M1P-Batch-Id", b.id.String())
	req.Header.Set("X-Mark1-Edge-Version", u.edgeVersion)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// A redirect is a middlebox or captive portal answering, never controld
	// (the client is built to not follow one): network-class, retryable —
	// neither an ack nor a content verdict the 4xx rule may quarantine on.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("uplink: ingest answered a redirect (%d) — refusing to follow (08 §2.2: only controld's landing ack licenses deletion)", resp.StatusCode)
	}
	out := &ingestResp{status: resp.StatusCode}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		// Seconds form only; 08 §2.5 makes it a floor, and controld emits
		// ceil-seconds. An unparseable value degrades to plain backoff.
		if secs, perr := strconv.Atoi(ra); perr == nil && secs > 0 {
			out.retryAfter = time.Duration(secs) * time.Second
		}
	}
	var body struct {
		BatchID     string   `json:"batch_id"`
		Quarantined []string `json:"quarantined"`
		Error       struct {
			Code   string `json:"code"`
			Detail struct {
				EventIDs []string `json:"event_ids"`
			} `json:"detail"`
		} `json:"error"`
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	jerr := json.Unmarshal(raw, &body)
	if jerr == nil {
		out.quarantined = body.Quarantined
		out.errCode = body.Error.Code
		out.badEventIDs = body.Error.Detail.EventIDs
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
		// 08 §2.2 gives the ack license to controld's durable landing, not to
		// any 2xx byte off the TLS connection: interception proxies and
		// portals (the middlebox environment 08 §2 names) answer 2xx HTML,
		// and an ack taken on the status line alone would delete spool
		// segments the real server never landed. Provenance check before the
		// cursor may move: JSON content type and the body's batch_id echoing
		// OURS (08 §2.6 returns it for exactly this comparison). Anything
		// short of that is network-class — a re-POST is safe (08 §2.3),
		// a deletion is not.
		switch {
		case readErr != nil:
			return nil, fmt.Errorf("uplink: 2xx with unreadable ack body: %w", readErr)
		case !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json"):
			return nil, fmt.Errorf("uplink: 2xx with Content-Type %q is not controld's ack (08 §2.6)", resp.Header.Get("Content-Type"))
		case jerr != nil || body.BatchID != b.id.String():
			return nil, fmt.Errorf("uplink: 2xx ack does not echo batch_id %s — not accepting deletion authority (08 §2.2)", b.id)
		}
	} else if readErr != nil && resp.StatusCode >= 500 {
		// The status line arrived but the 5xx body tore mid-read: the whole
		// exchange is network-class, retryable either way.
		return nil, readErr
	}
	return out, nil
}
