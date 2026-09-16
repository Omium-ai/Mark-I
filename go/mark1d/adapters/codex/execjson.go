package codex

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// ExecStream is reader (b): a `codex exec --json` stdout stream
// (codex-rs/exec/src/exec_events.rs ThreadEvent JSONL). Usage is
// `turn.completed.usage`; the stream carries no turn_id/response_id, so the
// key is the 1-based turn ordinal — weaker than the rollout key, and never
// run beside the rollout tail of the same thread (DetectUsage picks one).
type ExecStream struct {
	R    io.Reader
	Cwd  string // the workspace the wrapped codex ran in
	Set  tailers.WorkspaceSet
	Cfg  TailConfig
	Now  func() *timestamppb.Timestamp
	seen map[string]bool
}

const execMaxLine = 16 << 20

// Run consumes the stream until EOF or ctx ends. A cwd outside the enabled
// set emits nothing (04 §0.3 invariant 3) but still drains the reader.
func (e *ExecStream) Run(ctx context.Context) error {
	allowed := e.Set != nil && e.Set.Allowed(e.Cwd)
	sc := bufio.NewScanner(e.R)
	sc.Buffer(make([]byte, 0, 64<<10), execMaxLine)
	var thread uuid.UUID
	turn := 0
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var ev struct {
			Type     string `json:"type"`
			ThreadID string `json:"thread_id"`
			Usage    *struct {
				InputTokens           uint64 `json:"input_tokens"`
				CachedInputTokens     uint64 `json:"cached_input_tokens"`
				CacheWriteInputTokens uint64 `json:"cache_write_input_tokens"`
				OutputTokens          uint64 `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		switch ev.Type {
		case "thread.started":
			thread, _ = uuid.Parse(ev.ThreadID)
			turn = 0
		case "turn.started":
			turn++
		case "turn.completed":
			if ev.Usage == nil || thread == uuid.Nil || !allowed {
				continue
			}
			msg, req := fmt.Sprintf("turn:%d", turn), "exec:"+thread.String()
			if e.seen == nil {
				e.seen = map[string]bool{}
			}
			if e.seen[msg] {
				continue
			}
			e.seen[msg] = true
			out := &m1pv1.Event{
				SessionId: thread[:],
				Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
					IdemKey:                  tailers.IdemKey(e.Cfg.UsageIdemKey, thread, msg, req),
					MessageId:                msg,
					RequestId:                req,
					InputTokens:              ev.Usage.InputTokens,
					OutputTokens:             ev.Usage.OutputTokens,
					CacheCreationInputTokens: ev.Usage.CacheWriteInputTokens,
					CacheReadInputTokens:     ev.Usage.CachedInputTokens,
					Source:                   m1pv1.UsageSource_USAGE_SOURCE_TRANSCRIPT,
				}},
			}
			if e.Now != nil {
				out.OccurredAt = e.Now()
			}
			if err := e.Cfg.Emit(ctx, out); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
