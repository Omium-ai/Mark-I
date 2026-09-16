// Strict typed decode of the six PolicyBundle sections — the Go twin of
// rust/mark1-policy/src/decode.rs (07 §"PolicyBundle v1", decode-time
// rejection rules 1–4):
//
//   - No command strings, structurally (rule 1): every tstr is validated
//     against its production; a failing string rejects the WHOLE bundle as
//     M1E-3005 — no partial acceptance.
//   - Strict maps everywhere (rule 3): an unknown key fails decode.
//   - Anchors are catalog-ID enables only (rule 2); no wasm_module or any
//     executable field exists to decode (rule 4).
//
// The grammars are hand-rolled byte predicates, each naming the CDDL
// production it implements.

package policy

import (
	"fmt"
	"math"
	"sort"
)

// ── the CDDL string productions ─────────────────────────────────────────

// isCatalogID: `catalog_id: tstr .regexp "[a-z0-9_.-]{1,64}"` (normative in
// 07's CDDL; 04 §7.3's former `@cat-N` form is dead by 04's own note).
func isCatalogID(s string) bool {
	return ident(s, 64, func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
	})
}

// isVerifierID: `verifier-id = tstr .regexp "[a-z0-9_.@-]{1,128}"`.
func isVerifierID(s string) bool {
	return ident(s, 128, func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '@' || c == '-'
	})
}

// isM1pField: `m1p-field = tstr .regexp "[a-z0-9_.]{1,64}"`.
func isM1pField(s string) bool {
	return ident(s, 64, func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.'
	})
}

// isFreeIdent is 07 rule 1(d)'s fallback production `[A-Za-z0-9_.:@-]{1,128}`
// for the tstr fields the CDDL writes bare (channel, group_id, task_class,
// model_id, ladder_id, facet, agent_id, agent_version, threshold keys,
// tailer-rule keys): no whitespace, no path separator, no shell
// metacharacter can pass (04 §7.3's rejection triad).
func isFreeIdent(s string) bool {
	return ident(s, 128, func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == ':' || c == '@' || c == '-'
	})
}

// isJSONPointer: `json-pointer = tstr .size (0..1024)
// .regexp "(/[^/~]*(~[01][^/~]*)*)*"` — RFC 6901: empty, or '/'-prefixed
// segments where every '~' escapes as '~0' or '~1'. The .size bound is not
// decoration (07): the regexp admits ANY byte except an unescaped '~', so
// "structurally incapable of naming a command" rests on the CONSUMER
// resolving these as RFC 6901 pointers, never as text; the length bound is
// the part decode can enforce.
func isJSONPointer(s string) bool {
	if len(s) > 1024 {
		return false
	}
	if s == "" {
		return true
	}
	if s[0] != '/' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '~' {
			if i+1 >= len(s) || s[i+1] != '0' && s[i+1] != '1' {
				return false
			}
			i++
		}
	}
	return true
}

func ident(s string, max int, ok func(byte) bool) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

// ── value extraction helpers (every mismatch is a whole-bundle reject) ──

func schemaErr(path, detail string) *Reject {
	return &Reject{kind: kindSchema, detail: path + ": " + detail}
}

func mapOf(v any, path string) (map[string]any, *Reject) {
	entries, ok := v.(vmap)
	if !ok {
		return nil, schemaErr(path, "expected map")
	}
	out := make(map[string]any, len(entries))
	for _, e := range entries {
		k, ok := e.k.(string)
		if !ok {
			return nil, schemaErr(path, "non-text map key")
		}
		// The canonical-form check already forbids duplicate keys; this is
		// the local restatement so this module is safe standalone.
		if _, dup := out[k]; dup {
			return nil, schemaErr(path, "duplicate key "+k)
		}
		out[k] = e.v
	}
	return out, nil
}

// strictKeys is the strict-map rule (07 rule 3): the key set must be exactly
// `required` plus a subset of `optional` — an unknown key fails the bundle.
func strictKeys(m map[string]any, required, optional []string, path string) *Reject {
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return schemaErr(path, "missing key "+k)
		}
	}
	for k := range m {
		if !contains(required, k) && !contains(optional, k) {
			return schemaErr(path, "unknown key "+k)
		}
	}
	return nil
}

func contains(list []string, k string) bool {
	for _, e := range list {
		if e == k {
			return true
		}
	}
	return false
}

func uintVal(v any, path string) (uint64, *Reject) {
	u, ok := v.(uint64)
	if !ok {
		return 0, schemaErr(path, "expected uint")
	}
	return u, nil
}

func boolVal(v any, path string) (bool, *Reject) {
	b, ok := v.(bool)
	if !ok {
		return false, schemaErr(path, "expected bool")
	}
	return b, nil
}

func textVal(v any, path string) (string, *Reject) {
	t, ok := v.(string)
	if !ok {
		return "", schemaErr(path, "expected tstr")
	}
	return t, nil
}

func arrayVal(v any, path string) ([]any, *Reject) {
	// A definite-length empty array decodes to a nil []any; both shapes are
	// the array type.
	if v == nil {
		return nil, schemaErr(path, "expected array")
	}
	a, ok := v.([]any)
	if !ok {
		return nil, schemaErr(path, "expected array")
	}
	return a, nil
}

func bytesN(v any, n int, path, what string) ([]byte, *Reject) {
	b, ok := v.([]byte)
	if !ok {
		return nil, schemaErr(path, "expected bstr")
	}
	if len(b) != n {
		return nil, schemaErr(path, what)
	}
	return b, nil
}

// finiteVal: a finite float — NaN/∞ never enter the eval structs (a NaN in a
// prior poisons every posterior downstream without failing a comparison).
func finiteVal(v any, path string) (float64, *Reject) {
	f, ok := v.(float64)
	if !ok {
		return 0, schemaErr(path, "expected float")
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, schemaErr(path, "non-finite float")
	}
	return f, nil
}

// probVal: a probability — finite and in [0, 1].
func probVal(v any, path string) (float64, *Reject) {
	f, rej := finiteVal(v, path)
	if rej != nil {
		return 0, rej
	}
	if f < 0.0 || f > 1.0 {
		return 0, schemaErr(path, "probability outside [0,1]")
	}
	return f, nil
}

// checked: a grammar-checked string — failure is the M1E-3005 structural
// rejection (07 rule 1): invalid is a security event, never applied piecewise.
func checked(v any, path string, production func(string) bool) (string, *Reject) {
	t, rej := textVal(v, path)
	if rej != nil {
		return "", rej
	}
	if !production(t) {
		return "", &Reject{kind: kindCommandString, detail: path}
	}
	return t, nil
}

// distSumTol is D-R's NORMATIVE distribution tolerance: 1e-9 — ~7 decimal
// digits looser than the worst f64 rounding of shortest-float decimal
// literals, yet far below any probability mass a compiler could misplace.
// A per-entry [0,1] range check is NOT sufficient — all-zero priors passes
// ranges and then detonates fusion at runtime.
const distSumTol = 1e-9

func sumsToOne(entries []float64, path string) *Reject {
	sum := 0.0
	for _, e := range entries {
		sum += e
	}
	if math.Abs(sum-1.0) > distSumTol {
		return schemaErr(path, fmt.Sprintf("distribution sums to %v, not 1.0", sum))
	}
	return nil
}

func posterior4(v any, path string) (Posterior4, *Reject) {
	var p Posterior4
	a, rej := arrayVal(v, path)
	if rej != nil {
		return p, rej
	}
	if len(a) != 4 {
		return p, schemaErr(path, "posterior4 must have exactly 4 entries")
	}
	for i := range p {
		if p[i], rej = probVal(a[i], path); rej != nil {
			return p, rej
		}
	}
	return p, sumsToOne(p[:], path)
}

// signal3: `[accept, reject, abstain]` (D-R) — a proper distribution over the
// observed-signal vocabulary, enforced like posterior4.
func signal3(v any, path string) (Signal3, *Reject) {
	var s Signal3
	a, rej := arrayVal(v, path)
	if rej != nil {
		return s, rej
	}
	if len(a) != 3 {
		return s, schemaErr(path, "signal3 must have exactly 3 entries")
	}
	for i := range s {
		if s[i], rej = probVal(a[i], path); rej != nil {
			return s, rej
		}
	}
	return s, sumsToOne(s[:], path)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ── section decoders ────────────────────────────────────────────────────

// checkChannel: `channel` rides the envelope, parsed BEFORE any signature
// check. The same identifier production applies, but a violation here is
// schema, never command_string: pre-signature bytes are UNAUTHENTICATED, and
// classifying them as the paged M1E-3005 (05 §4.3's compiler P1) hands that
// pager to any attacker who can reach the endpoint. 3005 is reserved for
// string-production violations in SIGNED content.
func checkChannel(v any, path string) (string, *Reject) {
	t, rej := textVal(v, path)
	if rej != nil {
		return "", rej
	}
	if !isFreeIdent(t) {
		return "", schemaErr(path, "channel fails the identifier production")
	}
	return t, nil
}

func decodeVerify(v any) (VerifySection, *Reject) {
	var out VerifySection
	p := "sections.verify"
	m, rej := mapOf(v, p)
	if rej != nil {
		return out, rej
	}
	if rej = strictKeys(m, []string{"anchors", "verifiers", "priors", "correlation_groups", "quarantine"}, nil, p); rej != nil {
		return out, rej
	}

	rawAnchors, rej := arrayVal(m["anchors"], p)
	if rej != nil {
		return out, rej
	}
	for i, av := range rawAnchors {
		ap := fmt.Sprintf("%s.anchors[%d]", p, i)
		am, rej := mapOf(av, ap)
		if rej != nil {
			return out, rej
		}
		if rej = strictKeys(am, []string{"catalog_id", "enabled"}, []string{"thresholds", "debounce_ms"}, ap); rej != nil {
			return out, rej
		}
		var anchor AnchorEnable
		if tv, ok := am["thresholds"]; ok {
			tm, rej := mapOf(tv, ap)
			if rej != nil {
				return out, rej
			}
			for _, k := range sortedKeys(tm) {
				if !isFreeIdent(k) {
					return out, &Reject{kind: kindCommandString, detail: ap + ".thresholds." + k}
				}
				f, rej := finiteVal(tm[k], ap)
				if rej != nil {
					return out, rej
				}
				anchor.Thresholds = append(anchor.Thresholds, Threshold{k, f})
			}
		}
		if anchor.CatalogID, rej = checked(am["catalog_id"], ap+".catalog_id", isCatalogID); rej != nil {
			return out, rej
		}
		if anchor.Enabled, rej = boolVal(am["enabled"], ap); rej != nil {
			return out, rej
		}
		if dv, ok := am["debounce_ms"]; ok {
			d, rej := uintVal(dv, ap)
			if rej != nil {
				return out, rej
			}
			anchor.DebounceMs = &d
		}
		out.Anchors = append(out.Anchors, anchor)
	}

	indexOf := map[string]uint32{}
	rawVerifiers, rej := arrayVal(m["verifiers"], p)
	if rej != nil {
		return out, rej
	}
	for i, vv := range rawVerifiers {
		vp := fmt.Sprintf("%s.verifiers[%d]", p, i)
		vm, rej := mapOf(vv, vp)
		if rej != nil {
			return out, rej
		}
		if rej = strictKeys(vm, []string{"verifier_id", "confusion"}, nil, vp); rej != nil {
			return out, rej
		}
		verifierID, rej := checked(vm["verifier_id"], vp+".verifier_id", isVerifierID)
		if rej != nil {
			return out, rej
		}
		if _, dup := indexOf[verifierID]; dup {
			return out, schemaErr(vp, "duplicate verifier_id")
		}
		indexOf[verifierID] = uint32(i) //nolint:gosec // G115: i indexes a slice decoded from the bundle, so exceeding uint32 needs a >4 GiB bundle
		// D-R: `confusion4x3` — 4 true-verdict rows, each a signal3 over
		// (accept, reject, abstain).
		rows, rej := arrayVal(vm["confusion"], vp)
		if rej != nil {
			return out, rej
		}
		if len(rows) != 4 {
			return out, schemaErr(vp, "confusion must be 4x3")
		}
		var confusion [4]Signal3
		for r := range confusion {
			if confusion[r], rej = signal3(rows[r], vp); rej != nil {
				return out, rej
			}
		}
		out.Verifiers = append(out.Verifiers, VerifierModel{verifierID, confusion})
	}

	// Ids resolve to indices HERE so fusion never compares a string (04 §7.3
	// "no map lookups or string compares on the gate/route path").
	resolve := func(val any, path string) (uint32, *Reject) {
		id, rej := checked(val, path, isVerifierID)
		if rej != nil {
			return 0, rej
		}
		idx, ok := indexOf[id]
		if !ok {
			return 0, schemaErr(path, "unknown verifier_id "+id)
		}
		return idx, nil
	}

	rawGroups, rej := arrayVal(m["correlation_groups"], p)
	if rej != nil {
		return out, rej
	}
	for i, gv := range rawGroups {
		gp := fmt.Sprintf("%s.correlation_groups[%d]", p, i)
		gm, rej := mapOf(gv, gp)
		if rej != nil {
			return out, rej
		}
		if rej = strictKeys(gm, []string{"group_id", "members"}, nil, gp); rej != nil {
			return out, rej
		}
		rawMembers, rej := arrayVal(gm["members"], gp)
		if rej != nil {
			return out, rej
		}
		if len(rawMembers) == 0 {
			return out, schemaErr(gp, "members must be non-empty") // CDDL [+ verifier-id]
		}
		var group CorrelationGroup
		for _, mv := range rawMembers {
			idx, rej := resolve(mv, gp)
			if rej != nil {
				return out, rej
			}
			for _, existing := range group.Members {
				if existing == idx {
					// One observation, listed twice.
					return out, schemaErr(gp, "duplicate group member")
				}
			}
			group.Members = append(group.Members, idx)
		}
		if group.GroupID, rej = checked(gm["group_id"], gp+".group_id", isFreeIdent); rej != nil {
			return out, rej
		}
		out.CorrelationGroups = append(out.CorrelationGroups, group)
	}

	out.Quarantined = make([]bool, len(out.Verifiers))
	rawQuarantine, rej := arrayVal(m["quarantine"], p)
	if rej != nil {
		return out, rej
	}
	for _, qv := range rawQuarantine {
		idx, rej := resolve(qv, p+".quarantine")
		if rej != nil {
			return out, rej
		}
		out.Quarantined[idx] = true
	}

	if out.Priors, rej = posterior4(m["priors"], p+".priors"); rej != nil {
		return out, rej
	}
	return out, nil
}

func decodeRoute(v any) (RouteSection, *Reject) {
	var out RouteSection
	p := "sections.route"
	m, rej := mapOf(v, p)
	if rej != nil {
		return out, rej
	}
	if rej = strictKeys(m, []string{"cpvs", "ladders", "knee"}, []string{"exploration", "exploration_opt_in"}, p); rej != nil {
		return out, rej
	}

	rawCpvs, rej := arrayVal(m["cpvs"], p)
	if rej != nil {
		return out, rej
	}
	for i, rv := range rawCpvs {
		rp := fmt.Sprintf("%s.cpvs[%d]", p, i)
		rm, rej := mapOf(rv, rp)
		if rej != nil {
			return out, rej
		}
		if rej = strictKeys(rm, []string{"task_class", "model_id", "p_pass", "tokens_est"}, nil, rp); rej != nil {
			return out, rej
		}
		var row CpvsRow
		if row.TaskClass, rej = checked(rm["task_class"], rp+".task_class", isFreeIdent); rej != nil {
			return out, rej
		}
		if row.ModelID, rej = checked(rm["model_id"], rp+".model_id", isFreeIdent); rej != nil {
			return out, rej
		}
		if row.PPass, rej = probVal(rm["p_pass"], rp); rej != nil {
			return out, rej
		}
		if row.TokensEst, rej = uintVal(rm["tokens_est"], rp); rej != nil {
			return out, rej
		}
		out.Cpvs = append(out.Cpvs, row)
	}

	rawLadders, rej := arrayVal(m["ladders"], p)
	if rej != nil {
		return out, rej
	}
	for i, lv := range rawLadders {
		lp := fmt.Sprintf("%s.ladders[%d]", p, i)
		lm, rej := mapOf(lv, lp)
		if rej != nil {
			return out, rej
		}
		if rej = strictKeys(lm, []string{"ladder_id", "rungs"}, nil, lp); rej != nil {
			return out, rej
		}
		rawRungs, rej := arrayVal(lm["rungs"], lp)
		if rej != nil {
			return out, rej
		}
		if len(rawRungs) == 0 {
			return out, schemaErr(lp, "rungs must be non-empty") // CDDL [+ rung]
		}
		var ladder Ladder
		for _, rv := range rawRungs {
			rm, rej := mapOf(rv, lp)
			if rej != nil {
				return out, rej
			}
			if rej = strictKeys(rm, []string{"model_id", "keep_prefix"}, nil, lp); rej != nil {
				return out, rej
			}
			var rung Rung
			if rung.ModelID, rej = checked(rm["model_id"], lp+".model_id", isFreeIdent); rej != nil {
				return out, rej
			}
			if rung.KeepPrefix, rej = boolVal(rm["keep_prefix"], lp); rej != nil {
				return out, rej
			}
			ladder.Rungs = append(ladder.Rungs, rung)
		}
		if ladder.LadderID, rej = checked(lm["ladder_id"], lp+".ladder_id", isFreeIdent); rej != nil {
			return out, rej
		}
		out.Ladders = append(out.Ladders, ladder)
	}

	kp := p + ".knee"
	km, rej := mapOf(m["knee"], kp)
	if rej != nil {
		return out, rej
	}
	if rej = strictKeys(km, []string{"cost_basis", "rows", "v_default"}, nil, kp); rej != nil {
		return out, rej
	}
	basis, rej := textVal(km["cost_basis"], kp)
	if rej != nil {
		return out, rej
	}
	switch basis {
	case "usd":
		out.Knee.CostBasis = CostBasisUsd
	case "quota":
		out.Knee.CostBasis = CostBasisQuota
	default:
		// Closed enum (07 rule 1c) — but a typo'd basis is a SCHEMA defect
		// (M1E-3001), not command_string: 05 §4.3 pages a human on any
		// M1E-3005 ACK, and a two-value enum miss is a compiler typo, not
		// smuggled shell. 3005 stays reserved for the string PRODUCTIONS.
		return out, schemaErr(kp+".cost_basis", "not a cost basis: "+basis)
	}
	rawRows, rej := arrayVal(km["rows"], kp)
	if rej != nil {
		return out, rej
	}
	if len(rawRows) == 0 {
		return out, schemaErr(kp, "rows must be non-empty") // CDDL [+ row]
	}
	for _, rv := range rawRows {
		rm, rej := mapOf(rv, kp)
		if rej != nil {
			return out, rej
		}
		if rej = strictKeys(rm, []string{"n", "c_n"}, []string{"p_lcb"}, kp); rej != nil {
			return out, rej
		}
		cn, rej := finiteVal(rm["c_n"], kp)
		if rej != nil {
			return out, rej
		}
		if cn < 0.0 {
			return out, schemaErr(kp, "c_n must be >= 0") // a negative cost never arrests a retry
		}
		n, rej := uintVal(rm["n"], kp)
		if rej != nil {
			return out, rej
		}
		var plcb *float64
		if pv, ok := rm["p_lcb"]; ok {
			p, rej := probVal(pv, kp)
			if rej != nil {
				return out, rej
			}
			plcb = &p
		}
		out.Knee.Rows = append(out.Knee.Rows, KneeRow{N: n, CN: cn, PLCB: plcb})
	}
	if out.Knee.VDefault, rej = finiteVal(km["v_default"], kp); rej != nil {
		return out, rej
	}
	if out.Knee.VDefault < 0.0 {
		return out, schemaErr(kp, "v_default must be >= 0")
	}

	out.ExplorationEpsilon = 0.0 // .default 0.0 — propensity 1.0 logged honestly
	if ev, ok := m["exploration"]; ok {
		ep := p + ".exploration"
		em, rej := mapOf(ev, ep)
		if rej != nil {
			return out, rej
		}
		if rej = strictKeys(em, nil, []string{"epsilon"}, ep); rej != nil {
			return out, rej
		}
		if e, ok := em["epsilon"]; ok {
			if out.ExplorationEpsilon, rej = probVal(e, ep); rej != nil {
				return out, rej
			}
		}
	}
	// D-EF: ε>0 needs the publisher-signed opt-in; ponytail: absent ⇒ pre-ruling grammar until the re-freeze fixes `full` (ε 0.05, no opt-in).
	if o, ok := m["exploration_opt_in"]; ok {
		op := p + ".exploration_opt_in"
		optIn, rej := boolVal(o, op)
		if rej != nil {
			return out, rej
		}
		if !optIn && out.ExplorationEpsilon > 0 {
			return out, schemaErr(op, "exploration.epsilon > 0 without opt-in")
		}
	}
	return out, nil
}

func decodeMemory(v any) (MemorySection, *Reject) {
	var out MemorySection
	p := "sections.memory"
	m, rej := mapOf(v, p)
	if rej != nil {
		return out, rej
	}
	if rej = strictKeys(m, []string{"injection_rules", "budgets"}, nil, p); rej != nil {
		return out, rej
	}
	rawRules, rej := arrayVal(m["injection_rules"], p)
	if rej != nil {
		return out, rej
	}
	for i, rv := range rawRules {
		rp := fmt.Sprintf("%s.injection_rules[%d]", p, i)
		rm, rej := mapOf(rv, rp)
		if rej != nil {
			return out, rej
		}
		if rej = strictKeys(rm, []string{"facet"}, []string{"max_items"}, rp); rej != nil {
			return out, rej
		}
		var rule InjectionRule
		if rule.Facet, rej = checked(rm["facet"], rp+".facet", isFreeIdent); rej != nil {
			return out, rej
		}
		if mv, ok := rm["max_items"]; ok {
			mi, rej := uintVal(mv, rp)
			if rej != nil {
				return out, rej
			}
			rule.MaxItems = &mi
		}
		out.InjectionRules = append(out.InjectionRules, rule)
	}
	bp := p + ".budgets"
	bm, rej := mapOf(m["budgets"], bp)
	if rej != nil {
		return out, rej
	}
	if rej = strictKeys(bm, []string{"pack_tokens_max"}, nil, bp); rej != nil {
		return out, rej
	}
	if out.PackTokensMax, rej = uintVal(bm["pack_tokens_max"], bp); rej != nil {
		return out, rej
	}
	return out, nil
}

func decodeCortex(v any) (CortexSection, *Reject) {
	var out CortexSection
	p := "sections.cortex"
	m, rej := mapOf(v, p)
	if rej != nil {
		return out, rej
	}
	if rej = strictKeys(m, []string{"map_budget_tokens", "channels"}, []string{"learned_ranker"}, p); rej != nil {
		return out, rej
	}
	bp := p + ".map_budget_tokens"
	bm, rej := mapOf(m["map_budget_tokens"], bp)
	if rej != nil {
		return out, rej
	}
	if rej = strictKeys(bm, []string{"min", "max"}, nil, bp); rej != nil {
		return out, rej
	}
	if out.MapBudgetTokensMin, rej = uintVal(bm["min"], bp); rej != nil {
		return out, rej
	}
	if out.MapBudgetTokensMax, rej = uintVal(bm["max"], bp); rej != nil {
		return out, rej
	}
	if out.MapBudgetTokensMin > out.MapBudgetTokensMax {
		return out, schemaErr(bp, "min > max") // binary-search bounds must be an interval
	}
	rawChannels, rej := arrayVal(m["channels"], p)
	if rej != nil {
		return out, rej
	}
	for _, cv := range rawChannels {
		t, rej := textVal(cv, p)
		if rej != nil {
			return out, rej
		}
		switch t {
		case "session_start":
			out.Channels = append(out.Channels, CortexSessionStart)
		case "prompt_submit":
			out.Channels = append(out.Channels, CortexPromptSubmit)
		case "before_model":
			out.Channels = append(out.Channels, CortexBeforeModel)
		default:
			// Closed enum (07 rule 1c) → schema, same reasoning as
			// cost_basis: enum misses are M1E-3001, not the paged 3005.
			return out, schemaErr(p+".channels", "not a cortex channel: "+t)
		}
	}
	if rv, ok := m["learned_ranker"]; ok {
		if out.LearnedRanker, rej = decodeRanker(rv, p+".learned_ranker"); rej != nil {
			return out, rej
		}
	}
	return out, nil
}

func decodeRanker(v any, p string) (*LearnedRanker, *Reject) {
	m, rej := mapOf(v, p)
	if rej != nil {
		return nil, rej
	}
	if rej = strictKeys(m, []string{"stage", "weight", "bias", "coefficients"}, nil, p); rej != nil {
		return nil, rej
	}
	out := &LearnedRanker{}
	stage, rej := textVal(m["stage"], p+".stage")
	if rej != nil {
		return nil, rej
	}
	switch RankerStage(stage) {
	case RankerProbation, RankerShadow, RankerActive:
		out.Stage = RankerStage(stage)
	default:
		return nil, schemaErr(p+".stage", "not a ranker stage: "+stage)
	}
	if out.Weight, rej = probVal(m["weight"], p+".weight"); rej != nil {
		return nil, rej
	}
	if out.Bias, rej = finiteVal(m["bias"], p+".bias"); rej != nil {
		return nil, rej
	}
	cp := p + ".coefficients"
	c, rej := arrayVal(m["coefficients"], cp)
	if rej != nil {
		return nil, rej
	}
	if len(c) != 4 {
		return nil, schemaErr(cp, "coefficients must have exactly 4 entries")
	}
	for i, cv := range c {
		if out.Coefficients[i], rej = finiteVal(cv, cp); rej != nil {
			return nil, rej
		}
	}
	return out, nil
}

func decodeGates(v any) (GatesSection, *Reject) {
	var out GatesSection
	p := "sections.gates"
	m, rej := mapOf(v, p)
	if rej != nil {
		return out, rej
	}
	if rej = strictKeys(m, []string{"stop_gate_enabled", "max_consecutive_blocks", "hourly_block_ceiling"}, nil, p); rej != nil {
		return out, rej
	}
	mcb, rej := uintVal(m["max_consecutive_blocks"], p)
	if rej != nil {
		return out, rej
	}
	if mcb > 3 {
		// CDDL `.le 3`: a bundle may LOWER the local hard cap, never raise it.
		return out, schemaErr(p, "max_consecutive_blocks > 3")
	}
	out.MaxConsecutiveBlocks = uint8(mcb)
	if out.StopGateEnabled, rej = boolVal(m["stop_gate_enabled"], p); rej != nil {
		return out, rej
	}
	if out.HourlyBlockCeiling, rej = uintVal(m["hourly_block_ceiling"], p); rej != nil {
		return out, rej
	}
	if out.HourlyBlockCeiling > maxHourlyBlockCeiling {
		// Same direction as mcb (FR-VERIFY-010): lower only; 0 = edge default.
		return out, schemaErr(p, "hourly_block_ceiling > 30")
	}
	return out, nil
}

// ponytail: 30 mirrors fabric/gate.go:27 DefaultHourlyCeiling (and controld
// policydist/bundle.go maxHourlyBlockCeiling) — 07's CDDL types
// hourly_block_ceiling as a bare uint and no doc names a number, so the edge
// built-in is the only ceiling a bundle can lower. Hand-copied const (policy
// must not import fabric): bump all three or none.
const maxHourlyBlockCeiling = 30

func decodeAgentMaps(v any) (AgentMaps, *Reject) {
	var out AgentMaps
	p := "sections.agent_maps"
	m, rej := mapOf(v, p)
	if rej != nil {
		return out, rej
	}
	if rej = strictKeys(m, []string{"agents"}, nil, p); rej != nil {
		return out, rej
	}
	rawAgents, rej := arrayVal(m["agents"], p)
	if rej != nil {
		return out, rej
	}
	for i, av := range rawAgents {
		ap := fmt.Sprintf("%s.agents[%d]", p, i)
		am, rej := mapOf(av, ap)
		if rej != nil {
			return out, rej
		}
		if rej = strictKeys(am, []string{"agent_id", "agent_version", "hook_fields", "tailer_rules"}, nil, ap); rej != nil {
			return out, rej
		}
		var agent AgentMap
		fieldMaps := func(v any, mapName string, keyOK func(string) bool) ([]FieldMap, *Reject) {
			fm, rej := mapOf(v, ap)
			if rej != nil {
				return nil, rej
			}
			var fields []FieldMap
			for _, k := range sortedKeys(fm) {
				kPath := ap + "." + mapName + "." + k
				if !keyOK(k) {
					return nil, &Reject{kind: kindCommandString, detail: kPath}
				}
				ptr, rej := checked(fm[k], kPath, isJSONPointer)
				if rej != nil {
					return nil, rej
				}
				fields = append(fields, FieldMap{k, ptr})
			}
			return fields, nil
		}
		if agent.HookFields, rej = fieldMaps(am["hook_fields"], "hook_fields", isM1pField); rej != nil {
			return out, rej
		}
		if agent.TailerRules, rej = fieldMaps(am["tailer_rules"], "tailer_rules", isFreeIdent); rej != nil {
			return out, rej
		}
		if agent.AgentID, rej = checked(am["agent_id"], ap+".agent_id", isFreeIdent); rej != nil {
			return out, rej
		}
		if agent.AgentVersion, rej = checked(am["agent_version"], ap+".agent_version", isFreeIdent); rej != nil {
			return out, rej
		}
		out.Agents = append(out.Agents, agent)
	}
	return out, nil
}
