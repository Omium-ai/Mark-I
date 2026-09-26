package querychoke

import (
	"net/http"
	"sort"
	"time"
)

// Open days — today, and yesterday until its rollup window closes (rollup.py D20: UTC day end + 2 h) — have no tvo_tenant_day row yet, so the desktop's 1d tile and every first-day tenant's report read 0 by construction. The report computes those days live from the reads the rollup itself performs (tvo_task_window + coverage_band), folds them beside the closed rows and refuses guarantee grade while any live day contributes: labelled, never laundered (ADR-0010 §2.7).
const rollupGrace = 2 * time.Hour

type dayTotals struct {
	tokens, verified, retryLoop uint64
	observed, bypass, disabled  uint64
	segVersion                  string
}

func (d dayTotals) empty() bool {
	return d.tokens == 0 && d.verified == 0 && d.observed+d.bypass+d.disabled == 0
}

func rollupClosed(day, now time.Time) bool {
	return !now.Before(day.AddDate(0, 0, 1).Add(rollupGrace))
}

// posteriorMode mirrors reader.py _posterior_mode: the argmax of the p_* columns, "" when all zero.
func posteriorMode(row map[string]any) string {
	best, bestP := "", 0.0
	for _, k := range []string{"satisfied", "violated", "refused", "error"} {
		if p := asF64(row["p_"+k]); p > bestP {
			best, bestP = k, p
		}
	}
	return best
}

// resolvedWord mirrors rollup.py resolved(): a certified-stage satisfied|violated word stands; otherwise the terminal posterior's mode.
func resolvedWord(word, stage, mode string) string {
	if (word == "satisfied" || word == "violated") && (stage == "certified" || stage == "revised") {
		return word
	}
	if mode == "satisfied" || mode == "violated" {
		return mode
	}
	return ""
}

type liveAttempt struct {
	n, tokens         uint64
	word, stage, mode string
}

// foldAttempts is compute_rollup_rows + waste.retry_loop_tokens over one day's tvo_task_window rows.
func foldAttempts(rows []map[string]any) dayTotals {
	var out dayTotals
	byTask := map[string][]liveAttempt{}
	for _, row := range rows {
		byTask[asStr(row["task_id"])] = append(byTask[asStr(row["task_id"])], liveAttempt{
			n:      asU64(row["attempt_n"]),
			tokens: asU64(row["gen_tokens"]) + asU64(row["verifier_tokens"]),
			word:   asStr(row["fused_verdict"]),
			stage:  asStr(row["verdict_stage"]),
			mode:   posteriorMode(row),
		})
		if s := asStr(row["task_seg_version"]); s > out.segVersion {
			out.segVersion = s
		}
	}
	for _, atts := range byTask {
		sort.Slice(atts, func(i, j int) bool { return atts[i].n < atts[j].n })
		byN := map[uint64]liveAttempt{}
		for _, a := range atts {
			byN[a.n] = a
		}
		for _, a := range atts {
			out.tokens += a.tokens
			if prev, ok := byN[a.n-1]; a.n >= 2 && ok && prev.word == "violated" {
				out.retryLoop += a.tokens
			}
		}
		last := atts[len(atts)-1]
		if resolvedWord(last.word, last.stage, last.mode) == "satisfied" {
			out.verified++
		}
	}
	return out
}

// liveSpan reads the days [from, to] the way the rollup would (one open day, or a team member's whole window); a failed read has already been written to w.
func (m *Module) liveSpan(w http.ResponseWriter, r *http.Request, tid TenantID, from, to time.Time) (dayTotals, bool) {
	next := to.AddDate(0, 0, 1)
	winTpl, err := m.reg.Lookup("tvo_task_window")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "registry miswired")
		return dayTotals{}, false
	}
	winQ, err := Build(tid, winTpl, Params{"from": from, "to": next})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return dayTotals{}, false
	}
	winRows, ok := m.run(w, r, winQ)
	if !ok {
		return dayTotals{}, false
	}
	out := foldAttempts(winRows.Rows)
	covTpl, err := m.reg.Lookup("coverage_band")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "registry miswired")
		return dayTotals{}, false
	}
	covQ, err := Build(tid, covTpl, Params{"from": from, "to": next})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return dayTotals{}, false
	}
	covRows, ok := m.run(w, r, covQ)
	if !ok {
		return dayTotals{}, false
	}
	for _, row := range covRows.Rows {
		if d := asDay(row["day"]); d < from.Format(time.DateOnly) || d > to.Format(time.DateOnly) {
			continue
		}
		out.observed += asU64(row["observed_ms"])
		out.bypass += asU64(row["bypass_ms"])
		out.disabled += asU64(row["disabled_ms"])
	}
	return out, true
}

func asF64(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	}
	return float64(asU64(v))
}
