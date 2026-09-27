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
func posteriorMode(row map[string]any) string { return posteriorModeOf(row, "") }

// posteriorModeOf reads the p_*<suffix> columns (savings.v3's "_at_close" set).
func posteriorModeOf(row map[string]any, suffix string) string {
	best, bestP := "", 0.0
	for _, k := range []string{"satisfied", "violated", "refused", "error"} {
		if p := asF64(row["p_"+k+suffix]); p > bestP {
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

// liveDays is a team member's per-day trend: tvo_task_day's rows folded one UTC day at a time with foldAttempts, the rollup's own per-day rule; a day with no tokens and no outcome is no day. A failed read has already been written to w.
func (m *Module) liveDays(w http.ResponseWriter, r *http.Request, tid TenantID, from, to time.Time) (map[string]dayTotals, bool) {
	tpl, err := m.reg.Lookup("tvo_task_day")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "registry miswired")
		return nil, false
	}
	q, err := Build(tid, tpl, Params{"from": from, "to": to.AddDate(0, 0, 1)})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return nil, false
	}
	rows, ok := m.run(w, r, q)
	if !ok {
		return nil, false
	}
	byDay := map[string][]map[string]any{}
	for _, row := range rows.Rows {
		d := asDay(row["day"])
		byDay[d] = append(byDay[d], row)
	}
	out := map[string]dayTotals{}
	for d, rs := range byDay {
		if t := foldAttempts(rs); t.tokens > 0 || t.verified > 0 {
			out[d] = t
		}
	}
	return out, true
}

// savings is savings.v3 folded (doc 16 ruling 4, ADR-0013): against plain Claude Code, a block on a task that then resolved saved the follow-up request its estimate names, the usage after a block on a task that never resolved is spent that plain Claude Code would not have spent, and an arrest only avoided a retry Mark 1's own block would have forced — reported apart, never in the net. Every task sits in the cohort of the cost basis its first decision was priced under; a closed decision day whose net moved after it closed is counted as restated.
type savings struct {
	blocks, blocksResolved, credit, debit uint64
	arrests, arrestSaved                  uint64
	certCredit, certDebit                 uint64
	byBasis                               map[string]*basisCohort
	restatedTasks                         uint64
	restated                              int64
}

type basisCohort struct{ credit, debit, blocks, arrests uint64 }

// basisUnknown is a decision from an edge that predates GuardDecision.cost_basis: labelled apart, never certified.
const basisUnknown = "unknown"

// taskNet resolves one task with the rollup's rule (resolvedWord over the terminal verdict) from the columns suffix names: "" is now, "_at_close" is the ledger as controld had received it when the decision day closed — where no block had arrived yet, the task was not in the figure at all.
func taskNet(row map[string]any, suffix string) (credit, debit uint64, resolved bool) {
	if suffix != "" && asU64(row["blocks"+suffix]) == 0 {
		return 0, 0, false
	}
	if resolvedWord(asStr(row["fused_verdict"+suffix]), asStr(row["verdict_stage"+suffix]), posteriorModeOf(row, suffix)) == "satisfied" {
		return asU64(row["block_saved"+suffix]), 0, true
	}
	return 0, asU64(row["post_block_tokens"+suffix]), false
}

// foldSavings folds savings.v3's per-task rows for a report under costBasis at now: certified narrows the net to certified tasks decided under that basis, and a task whose decision day has closed and whose net differs from the net at close is a restatement, not a silent change.
func foldSavings(rows []map[string]any, costBasis string, now time.Time) savings {
	s := savings{byBasis: map[string]*basisCohort{}}
	for _, row := range rows {
		if asU64(row["blocks"])+asU64(row["arrests"]) == 0 {
			continue
		}
		basis, _ := row["decision_basis"].(string)
		if basis == "" {
			basis = basisUnknown
		}
		c := s.byBasis[basis]
		if c == nil {
			c = &basisCohort{}
			s.byBasis[basis] = c
		}
		s.arrests += asU64(row["arrests"])
		c.arrests += asU64(row["arrests"])
		s.arrestSaved += asU64(row["arrest_saved"])
		blocks := asU64(row["blocks"])
		if blocks == 0 {
			continue
		}
		s.blocks += blocks
		c.blocks += blocks
		credit, debit, resolved := taskNet(row, "")
		if resolved {
			s.blocksResolved += blocks
		}
		s.credit += credit
		s.debit += debit
		c.credit += credit
		c.debit += debit
		if asStr(row["verdict_stage"]) == "certified" && basis == costBasis {
			s.certCredit += credit
			s.certDebit += debit
		}
		if day, err := time.Parse(time.DateOnly, asDay(row["decision_day"])); err == nil && rollupClosed(day, now) {
			c0, d0, _ := taskNet(row, "_at_close")
			if delta := netOf(credit, debit) - netOf(c0, d0); delta != 0 {
				s.restatedTasks++
				s.restated += delta
			}
		}
	}
	return s
}

// netOf is credit − debit, negative when blocks cost more than they saved.
func netOf(credit, debit uint64) int64 {
	return int64(credit) - int64(debit) //nolint:gosec // G115: token sums sit far below 2^63
}

func (s savings) body() map[string]any {
	byBasis := map[string]any{}
	for basis, c := range s.byBasis {
		byBasis[basis] = map[string]any{"total": netOf(c.credit, c.debit), "block_count": c.blocks, "arrest_count": c.arrests}
	}
	return map[string]any{
		"label": "estimated", "estimate": true, "version": "savings.v3",
		"total": netOf(s.credit, s.debit), "blocks": s.credit, "block_count": s.blocks, "blocks_resolved": s.blocksResolved, "debit": s.debit,
		"arrests": s.arrestSaved, "arrest_count": s.arrests,
		"re_exploration_avoided": uint64(0), "routing": uint64(0),
		"certified":     netOf(s.certCredit, s.certDebit),
		"by_cost_basis": byBasis,
		"restated":      map[string]any{"tasks": s.restatedTasks, "total": s.restated},
	}
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
