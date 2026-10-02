// Package tailers turns Claude Code transcript streams into Usage events —
// the edge layer of 07 §7's three-layer dedupe. This layer kills the only
// duplicates it alone can see: streaming rewrites of one assistant message
// (the verified ~2.5× overcount) and sidechain re-logs in the parent
// transcript. One Usage per (message.id, requestId), last line wins pre-emit;
// a post-emission rewrite with identical numbers is suppressed, one with
// UPDATED numbers re-emits as a correction under the same idem_key (07 §7:
// the Usage rollup keeps max(event_id) per idem_key); sidechain lines never
// emit — all PROTOCOL INVARIANTS (08 §5.1), not parser etiquette.
package tailers

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BackfillWindow is the founder ruling of 2026-09-19: a first tail imports at most this much transcript history.
const BackfillWindow = 30 * 24 * time.Hour

// Role of a transcript stream. The sidechain rule is role-dependent: a Usage
// event is attributed to the transcript in which the API call ORIGINATED
// (08 §5.1) — subagent streams are the origin of their own sidechain-marked
// lines and do emit; the parent's isSidechain replays never do.
type Role int

const (
	RoleParent Role = iota
	RoleSubagent
)

// pendingKey implements the dedupe rule as a protocol invariant (04 §2.1).
type pendingKey struct{ MessageID, RequestID string }

type pendingEntry struct {
	key pendingKey
	ev  *m1pv1.Event
}

// quiesce is 04 §2.1's debounce: a pending entry with no newer line for this
// long is emitted without waiting for the Stop hook.
const quiesce = 2 * time.Second

// stream is the per-transcript dedupe state machine, pure over lines so the
// replay suite drives it without files or clocks.
type stream struct {
	role    Role
	session uuid.UUID // the PARENT session for subagent streams too (04 §2.1)
	idemKey []byte    // tenant usage-idem key (HKDF from the tenant HMAC root)

	// pending is ordered by first-seen key so emissions match transcript
	// order; in practice it holds ≤1 entry because a new key flushes the old.
	pending    []pendingEntry
	lastLineAt time.Time

	// emitted remembers the last Usage this stream released per key, for the
	// stream's lifetime. It closes the two post-emission rewrite holes the
	// pending buffer alone cannot see: a rewrite arriving AFTER the quiesce
	// flush, and interleaved rewrites (key A, key B flushes A, key A again).
	// Identical numbers are suppressed — C8's "zero duplicate Usage" at the
	// edge; UPDATED numbers re-emit under the same idem_key, which 07 §7
	// supports explicitly: the Usage rollup collapses idem_key keeping
	// max(event_id), so a later re-emit carrying the cumulative final counts
	// is correct at-least-once behavior, not a duplicate.
	// ponytail: grows one Usage per key for the stream's lifetime; an
	// eviction sweep if transcripts ever hold enough messages to matter.
	emitted map[pendingKey]*m1pv1.Usage

	// parse is the vendor line parser (Format.NewParser); nil is claudecode's.
	parse func(line []byte) (Line, bool)

	// importAt is the first-tail instant when a backfill window applies: a line stamped before it is history, before importCutoff it is dropped. Zero = resumed from a cursor or no window, nothing is history.
	importAt, importCutoff time.Time
	importOldest           time.Time // stamp of the oldest line admitted as history; zero until one is
	importMarked           bool      // the history_import marker precedes the first backfilled emission, once
}

// Line is one vendor usage line reduced to the fields every adapter's dedupe
// and Usage event need — the seam a Format's parser fills.
type Line struct {
	Sidechain            bool
	MessageID, RequestID string
	Model, Timestamp     string
	ServiceTier          string
	InputTokens          uint64
	OutputTokens         uint64
	CacheCreationTokens  uint64
	CacheReadTokens      uint64
}

// txLine is claudecode's minimal vendor shape (08 §5.1).
type txLine struct {
	IsSidechain bool   `json:"isSidechain"`
	RequestID   string `json:"requestId"`
	Timestamp   string `json:"timestamp"`
	Message     *struct {
		ID    string `json:"id"`
		Model string `json:"model"`
		Usage *struct {
			InputTokens              uint64 `json:"input_tokens"`
			OutputTokens             uint64 `json:"output_tokens"`
			CacheCreationInputTokens uint64 `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     uint64 `json:"cache_read_input_tokens"`
			ServiceTier              string `json:"service_tier"`
		} `json:"usage"`
	} `json:"message"`
}

// consume feeds one transcript line and returns the Usage events this line
// released: a key newer than a pending one emits the pending entry (04 §2.1
// trigger 1). Non-usage lines, unparseable noise, and parent-stream sidechain
// replays release nothing and are never themselves emitted.
func (s *stream) consume(line []byte, now time.Time) []*m1pv1.Event {
	s.lastLineAt = now
	if s.parse == nil {
		s.parse = parseClaudeCode
	}
	l, ok := s.parse(line)
	if !ok || l.MessageID == "" || l.RequestID == "" {
		return nil // transcript noise; usage lines are the only contract here
	}
	// PROTOCOL INVARIANT (07 §7 layer 1): sidechain lines in the parent
	// transcript never emit — the subagent's own stream owns this key.
	if s.role == RoleParent && l.Sidechain {
		return nil
	}
	if !s.importAt.IsZero() {
		// Unstamped lines carry no age evidence and pass as live.
		if ts, err := time.Parse(time.RFC3339Nano, l.Timestamp); err == nil && ts.Before(s.importAt) {
			if ts.Before(s.importCutoff) {
				return nil
			}
			if s.importOldest.IsZero() {
				s.importOldest = ts
			}
		}
	}
	key := pendingKey{l.MessageID, l.RequestID}
	ev := s.buildUsage(&l)
	for i := range s.pending {
		if s.pending[i].key == key {
			// Last line wins pre-emit: a streaming rewrite replaces the
			// pending entry rather than appending (the ~2.5× defense).
			s.pending[i].ev = ev
			return nil
		}
	}
	// Post-emission rewrite (07 §7 layer 1, C8 "zero duplicate Usage"): a key
	// this stream already released re-enters only when its NUMBERS moved — a
	// byte-identical rewrite (e.g. the post-compaction re-log) is the exact
	// duplicate this layer exists to kill and emits nothing; changed numbers
	// re-pend as a correction under the SAME idem_key, which the ledger
	// resolves by keeping max(event_id) per idem_key (07 §7).
	if prev, ok := s.emitted[key]; ok && proto.Equal(prev, ev.GetUsage()) {
		return nil
	}
	out := s.flush()
	s.pending = append(s.pending, pendingEntry{key, ev})
	return out
}

// flush emits everything pending, first-seen order — the Stop-hook and
// shutdown trigger (04 §2.1); quiet() drives the same path on the debounce.
func (s *stream) flush() []*m1pv1.Event {
	if len(s.pending) == 0 {
		return nil
	}
	out := make([]*m1pv1.Event, 0, len(s.pending)+1)
	if !s.importOldest.IsZero() && !s.importMarked {
		s.importMarked = true
		out = append(out, s.historyImport())
	}
	if s.emitted == nil {
		s.emitted = map[pendingKey]*m1pv1.Usage{}
	}
	for _, p := range s.pending {
		out = append(out, p.ev)
		s.emitted[p.key] = p.ev.GetUsage()
	}
	s.pending = nil
	return out
}

// historyImport is the backfill marker: a closed BYPASS window from the oldest imported line to the first-tail instant, on this session, so the app can label every Usage of the session stamped before occurred_at as imported history rather than live capture. DeviceWide because the tailer holds no tenant path key; the session_id is the join.
func (s *stream) historyImport() *m1pv1.Event {
	return &m1pv1.Event{
		SessionId:  s.session[:],
		OccurredAt: timestamppb.New(s.importAt),
		Body: &m1pv1.Event_CoverageTransition{CoverageTransition: &m1pv1.CoverageTransition{
			Kind:        m1pv1.CoverageKind_COVERAGE_KIND_BYPASS,
			WorkspaceId: coverage.DeviceWide(),
			DurationMs:  uint64(s.importAt.Sub(s.importOldest).Milliseconds()), //nolint:gosec // G115: importOldest < importAt by construction
			ReasonCode:  coverage.ReasonHistoryImport,
		}},
	}
}

// idle is lineSource's cursor gate: nothing pending.
func (s *stream) idle() bool { return len(s.pending) == 0 }

// quiet flushes iff the stream has been line-silent past the 2 s debounce.
func (s *stream) quiet(now time.Time) []*m1pv1.Event {
	if len(s.pending) == 0 || now.Sub(s.lastLineAt) < quiesce {
		return nil
	}
	return s.flush()
}

// parseClaudeCode reads 08 §5.1's assistant line: the tailer reads ONLY lines
// whose message carries usage, and must tolerate every unknown sibling field.
func parseClaudeCode(line []byte) (Line, bool) {
	var l txLine
	if json.Unmarshal(line, &l) != nil || l.Message == nil || l.Message.Usage == nil {
		return Line{}, false
	}
	u := l.Message.Usage
	return Line{
		Sidechain: l.IsSidechain, MessageID: l.Message.ID, RequestID: l.RequestID,
		Model: l.Message.Model, Timestamp: l.Timestamp, ServiceTier: u.ServiceTier,
		InputTokens: u.InputTokens, OutputTokens: u.OutputTokens,
		CacheCreationTokens: u.CacheCreationInputTokens, CacheReadTokens: u.CacheReadInputTokens,
	}, true
}

func (s *stream) buildUsage(l *Line) *m1pv1.Event {
	ev := &m1pv1.Event{
		SessionId: s.session[:],
		Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
			IdemKey:                  IdemKey(s.idemKey, s.session, l.MessageID, l.RequestID),
			MessageId:                l.MessageID,
			RequestId:                l.RequestID,
			Model:                    l.Model,
			InputTokens:              l.InputTokens,
			OutputTokens:             l.OutputTokens,
			CacheCreationInputTokens: l.CacheCreationTokens,
			CacheReadInputTokens:     l.CacheReadTokens,
			ServiceTier:              l.ServiceTier,
			Source:                   m1pv1.UsageSource_USAGE_SOURCE_TRANSCRIPT,
		}},
	}
	// occurred_at is display/skew only (07 §2) — set when the vendor stamped
	// one, never fabricated.
	if t, err := time.Parse(time.RFC3339Nano, l.Timestamp); err == nil {
		ev.OccurredAt = timestamppb.New(t)
	}
	return ev
}

// IdemKey computes the events.proto recipe verbatim: HMAC-SHA256 keyed by the
// tenant's usage-idem key over
//
//	session_id(16 raw bytes) || 0x00 || message_id(utf8) || 0x00 || request_id(utf8).
//
// Computed at the edge as a protocol invariant — the server upserts on it
// unconditionally, so even a tailer bug cannot double-bill (07 §7).
func IdemKey(usageIdemKey []byte, session uuid.UUID, messageID, requestID string) []byte {
	mac := hmac.New(sha256.New, usageIdemKey)
	mac.Write(session[:])
	mac.Write([]byte{0})
	mac.Write([]byte(messageID))
	mac.Write([]byte{0})
	mac.Write([]byte(requestID))
	return mac.Sum(nil)
}

// DeriveUsageIdemKey derives the tenant's usage-idem key from the tenant HMAC
// root under the events.proto label "m1p.usage.idem". The root itself arrives
// with enrollment and lives in identity custody (04 §2.9); this is the one
// derivation between it and the wire.
func DeriveUsageIdemKey(tenantRoot []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, tenantRoot, nil, "m1p.usage.idem", 32)
}
