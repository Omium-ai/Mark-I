// Package redact is mark1d's admit-to-upload secret scanner — the Go twin of
// rust/mark1-redact's admit axis (04 §2.0), fail-closed with NO off switch:
// no config field, parameter, or build tag bypasses it (CON-008, invariant 5).
// Bit-identical behavior with the Rust crate is pinned by the frozen
// conformance/vectors/redact/ family (12 §3.4); divergence there is a red CI.
//
// Only the admit axis lives here: mark1d never mutates a stream in transit
// (the detect axis is the proxy's, 04 §7.1), so the streaming carry is not
// ported. Every ceiling — pattern bounds, entropy floors, table priority —
// is the Rust table's, never loosened (see rules.go).
package redact

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sort"
)

// Outcome mirrors mark1-redact's AdmitOutcome (04 §7.1).
type Outcome int

const (
	Clean Outcome = iota
	Redacted
	// Quarantine is the internal-failure leg (F-35): the caller drops the
	// event locally, accounted, never admits it raw.
	Quarantine
)

type compiledRule struct {
	class      Class
	reAt       *regexp.Regexp // \A-anchored: confirm = "matches starting exactly here"
	re         *regexp.Regexp // bare form, full-buffer pass for anchor-less rules
	minEntropy float32
	hasFloor   bool
	anchors    [][]byte
}

// Scanner is the compiled ruleset plus the tenant redaction key: the hash leg
// of every token is HMAC-SHA256(key, span), so equal secrets correlate within
// one tenant and reveal nothing (04 §7.1).
type Scanner struct {
	rules   []compiledRule
	hmacKey []byte
}

// NewScanner compiles the builtin table. Construction is the only fallible
// step; a caller that cannot construct one must refuse or quarantine, never
// pass through (the admit axis has no "scannerless" mode — mark1-redact
// lib.rs, RulesetError contract).
func NewScanner(hmacKey []byte) (*Scanner, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		// \A-anchoring makes Go's FindIndex(buf[pos:]) the exact equivalent of
		// Rust's find_at + "match starts at the anchor hit" confirm.
		reAt, err := regexp.Compile(`\A(?:` + r.pattern + `)`)
		if err != nil {
			return nil, fmt.Errorf("redact: rule %s failed to compile: %w", r.id, err)
		}
		re, err := regexp.Compile(r.pattern)
		if err != nil {
			return nil, fmt.Errorf("redact: rule %s failed to compile: %w", r.id, err)
		}
		anchors := make([][]byte, len(r.anchors))
		for i, a := range r.anchors {
			anchors[i] = []byte(a)
		}
		compiled = append(compiled, compiledRule{
			class:      r.class,
			reAt:       reAt,
			re:         re,
			minEntropy: r.minEntropy,
			hasFloor:   r.hasFloor,
			anchors:    anchors,
		})
	}
	return &Scanner{rules: compiled, hmacKey: append([]byte(nil), hmacKey...)}, nil
}

type candidate struct {
	start, end, ruleIdx int
}

type finding struct {
	class      Class
	start, end int
}

// findAll reproduces Scanner::find_all's overlap resolution verbatim: sort by
// (start asc, longest first, table priority), keep greedily non-overlapping —
// the dedupe invariant the vectors pin.
func (s *Scanner) findAll(buf []byte) []finding {
	var cand []candidate
	for idx, r := range s.rules {
		if len(r.anchors) == 0 {
			// Unanchored entropy rules: full-buffer, non-overlapping leftmost
			// iteration — regexp's FindAllIndex == Rust's find_iter.
			for _, m := range r.re.FindAllIndex(buf, -1) {
				if s.entropyOK(r, buf[m[0]:m[1]]) {
					cand = append(cand, candidate{m[0], m[1], idx})
				}
			}
			continue
		}
		for _, a := range r.anchors {
			// Overlapping anchor occurrences, like the aho-corasick prefilter.
			for pos := 0; pos <= len(buf)-len(a); {
				i := bytes.Index(buf[pos:], a)
				if i < 0 {
					break
				}
				at := pos + i
				if m := r.reAt.FindIndex(buf[at:]); m != nil && s.entropyOK(r, buf[at:at+m[1]]) {
					cand = append(cand, candidate{at, at + m[1], idx})
				}
				pos = at + 1
			}
		}
	}
	sort.Slice(cand, func(i, j int) bool {
		if cand[i].start != cand[j].start {
			return cand[i].start < cand[j].start
		}
		if cand[i].end != cand[j].end {
			return cand[i].end > cand[j].end
		}
		return cand[i].ruleIdx < cand[j].ruleIdx
	})
	var kept []finding
	covered := 0
	for _, c := range cand {
		if c.start < covered {
			continue
		}
		covered = c.end
		kept = append(kept, finding{class: s.rules[c.ruleIdx].class, start: c.start, end: c.end})
	}
	return kept
}

func (s *Scanner) entropyOK(r compiledRule, span []byte) bool {
	if !r.hasFloor {
		return true
	}
	return shannonBitsPerByte(span) >= r.minEntropy
}

// Admit is the admit-to-upload axis: flagged spans are replaced in place with
// `⟨redacted:class:hash⟩` before any caller persists a byte. Any internal
// failure (panic-caught, per the Rust catch_unwind leg) returns Quarantine —
// never admit-raw (F-35). The returned buffer replaces the input; when
// Redacted, the substitution count is exact (kept spans never overlap).
func (s *Scanner) Admit(buf []byte) (out []byte, outcome Outcome, substitutions uint32) {
	defer func() {
		if recover() != nil {
			out, outcome, substitutions = nil, Quarantine, 0
		}
	}()
	findings := s.findAll(buf)
	if len(findings) == 0 {
		return buf, Clean, 0
	}
	res := make([]byte, 0, len(buf))
	cursor := 0
	for _, f := range findings {
		res = append(res, buf[cursor:f.start]...)
		res = append(res, s.token(f.class, buf[f.start:f.end])...)
		cursor = f.end
	}
	res = append(res, buf[cursor:]...)
	// The Rust twin zeroizes the pre-image here; Go's GC can have copied the
	// caller's buffer already, so wiping is best-effort hygiene only — the
	// invariant that matters (no pre-redaction byte PERSISTS) is carried by
	// the caller replacing its value with `res` before any spool append.
	for i := range buf {
		buf[i] = 0
	}
	// Kept spans never overlap and one substitution each: the count is exact
	// and cannot exceed len(buf); the clamp is unreachable and only bounds
	// the int→uint32 conversion.
	subs := len(findings)
	if subs > math.MaxInt32 {
		subs = math.MaxInt32
	}
	return res, Redacted, uint32(subs) //nolint:gosec // G115: clamped above; count ≤ len(buf) in practice
}

// token: `⟨redacted:class:hash⟩`, hash = first 8 bytes of HMAC-SHA256(tenant
// key, span) as lowercase hex — byte-identical to mark1-redact's token().
func (s *Scanner) token(class Class, span []byte) []byte {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write(span)
	return []byte("⟨redacted:" + string(class) + ":" + hex.EncodeToString(mac.Sum(nil)[:8]) + "⟩")
}

// shannonBitsPerByte mirrors the Rust f32 arithmetic. ponytail: the log2 leg
// rounds through float64 (Go has no f32 intrinsic), a ≤1-ulp difference; every
// frozen vector sits ≥0.3 bits/byte from its floor, so the compare cannot flip.
func shannonBitsPerByte(span []byte) float32 {
	if len(span) == 0 {
		return 0
	}
	var counts [256]uint32
	for _, b := range span {
		counts[b]++
	}
	n := float32(len(span))
	var bits float32
	for _, c := range counts {
		if c > 0 {
			p := float32(c) / n
			bits -= p * float32(math.Log2(float64(p)))
		}
	}
	return bits
}
