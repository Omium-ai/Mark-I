package memory

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
)

const (
	packHeader    = "[mark1 memory] Verified experience from prior tasks in this repository:\n"
	pitfallHeader = "[mark1 memory] A verified remedy matched this failure: "
)

// Tokens is D-AF's estimate (cortexd::map::estimate_tokens): ceil(len/4).
func Tokens(text string) uint32 {
	return uint32((len(text) + 3) / 4) // #nosec G115 -- text is vendor-capped at 10k chars
}

func (c *Cache) event(session, task [16]byte) *m1pv1.Event {
	return &m1pv1.Event{SessionId: session[:], TaskId: task[:], OccurredAt: timestamppb.Now()}
}

func idBytes(a Artifact) ([]byte, bool) {
	u, err := uuid.Parse(a.ID)
	if err != nil {
		return nil, false
	}
	return u[:], true
}

// record admits the MemoryInjection first; text is delivered only once the ledger holds the delivery.
func (c *Cache) record(ctx context.Context, st *taskState, task [16]byte, ch m1pv1.InjectionChannel, chosen []Artifact, text string) string {
	ids := make([][]byte, 0, len(chosen))
	for _, a := range chosen {
		id, ok := idBytes(a)
		if !ok {
			return ""
		}
		ids = append(ids, id)
	}
	ev := c.event(st.session, task)
	ev.Body = &m1pv1.Event_MemoryInjection{MemoryInjection: &m1pv1.MemoryInjection{ArtifactIds: ids, Channel: ch, TokensUsed: Tokens(text)}}
	if err := c.cfg.Admit(ctx, ev); err != nil {
		c.cfg.Log.Warn("mark1d: MemoryInjection not admitted; nothing injected", "err", err)
		return ""
	}
	c.mu.Lock()
	st.ids = append(st.ids, ids...)
	for _, a := range chosen {
		st.seen[a.ID] = true
	}
	c.mu.Unlock()
	return text
}

// budget snapshots the task's remaining MInject room and injected set under the lock.
func (c *Cache) budget(st *taskState) (int, map[string]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := make(map[string]bool, len(st.seen))
	for k := range st.seen {
		seen[k] = true
	}
	return MInject - len(st.ids), seen
}

// pack is 06 §9.5's memory pack at TaskOpen: once per task, LCB order (d̂ = 0 until repo features exist), within pack_tokens_max and MInject.
func (c *Cache) pack(ctx context.Context, session, task [16]byte) string {
	st := c.state(session, task)
	c.mu.Lock()
	packed := st.packed
	st.packed = true
	c.mu.Unlock()
	if packed {
		return ""
	}
	room, seen := c.budget(st)
	var chosen []Artifact
	text := packHeader
	for _, a := range c.artifacts() {
		if len(chosen) >= room {
			break
		}
		if a.Kind == "pitfall" || !injectable[a.Kind] || seen[a.ID] {
			continue
		}
		line := "- " + a.Kind + ": " + strings.TrimSpace(a.Trigger) + " -> " + strings.TrimSpace(a.Guidance) + "\n"
		if uint64(Tokens(text+line)) > c.cfg.PackTokensMax {
			continue
		}
		text += line
		chosen = append(chosen, a)
	}
	if len(chosen) == 0 {
		return ""
	}
	return c.record(ctx, st, task, m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, chosen, strings.TrimRight(text, "\n"))
}

// pitfall is the reactive tier: exact digest against the cache, else the server's HNSW fuzz (D29), one remedy per failure.
func (c *Cache) pitfall(ctx context.Context, session, task [16]byte, q fabric.ContextQuery) string {
	norm := NormalizeSignature(q.Error)
	if norm == "" {
		return ""
	}
	st := c.state(session, task)
	room, seen := c.budget(st)
	if room <= 0 {
		return ""
	}
	digest := SignatureDigest(norm)
	var hit *Artifact
	for _, a := range c.artifacts() {
		if a.Kind == "pitfall" && a.SigDigest == digest && !seen[a.ID] {
			hit = &a
			break
		}
	}
	if hit == nil {
		hit = c.fuzz(ctx, seen, q)
	}
	if hit == nil {
		return ""
	}
	text := pitfallHeader + strings.TrimSpace(hit.Guidance)
	return c.record(ctx, st, task, m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, []Artifact{*hit}, text)
}

func (c *Cache) fuzz(ctx context.Context, seen map[string]bool, q fabric.ContextQuery) *Artifact {
	if c.cfg.BaseURL == "" || len(c.artifacts()) == 0 {
		return nil
	}
	budget := matchBudget
	if q.DeadlineMs != 0 {
		budget = min(budget, time.Duration(q.DeadlineMs)*time.Millisecond-matchMargin)
	}
	if budget <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	body, err := json.Marshal(struct {
		Error string `json:"error"`
		Limit int    `json:"limit"`
	}{q.Error, MInject})
	if err != nil {
		return nil
	}
	var res struct {
		Artifacts []Artifact `json:"artifacts"`
	}
	if err := c.get(ctx, http.MethodPost, pathMatch, body, &res); err != nil {
		c.cfg.Log.Debug("mark1d: memory fuzz tier unavailable", "err", err)
		return nil
	}
	for _, a := range res.Artifacts {
		if a.Kind == "pitfall" && !seen[a.ID] {
			return &a
		}
	}
	return nil
}
