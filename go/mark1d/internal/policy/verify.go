// PolicyBundle v1 verify + decode — the Go twin of
// rust/mark1-policy/src/lib.rs (04 §7.3, 07 §"PolicyBundle v1"), validated
// against conformance/vectors/bundle/.
//
// Verification order (04 §7.3, 07 rule 5): canonical-form check →
// section-split Ed25519 signatures → monotonic `seq` → transparency-log
// inclusion proof → strict typed schema decode. Failure at ANY step rejects
// the whole bundle — the caller keeps last-known-good (fail-static, F-27) —
// and Reject carries the ACK code (M1E-3001/3002/3003/3005, 08 §9).
//
// BUNDLE ZERO (lead ruling D-P): the inclusion-proof waiver at seq == 0 is
// the literal comparison in VerifyAndDecode, never a flag — no operator can
// widen it under deadline pressure.

package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"math"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
)

// Schema is the closed `schema` value — anything else is a different contract
// (forward compatibility is a new policy_bundle.v2, 07 rule 3).
const Schema = "policy_bundle.v1"

// MaxBundleLen: no document names a bundle size ceiling, so the M1PL frame
// bound (07 §5's 4 MiB) is borrowed — checked BEFORE any parse so a hostile
// length is a cheap rejection, not an OOM lottery (mirrors lib.rs).
const MaxBundleLen = 4 << 20

// genesisPrevHash: bundle zero chains from 32 zero bytes, exactly like the
// server catalog's head default (m1_009) and the receipt chain genesis.
var genesisPrevHash [32]byte

// signingDomain is D-Q's domain prefix: the bundle plane gets its OWN domain
// string, matching the receipt plane's `mark1-label-v1\0` discipline — a
// bundle signature can never verify as a receipt signature or vice versa.
var signingDomain = []byte("mark1-bundle-v1\x00")

// rejectKind is the conformance vectors' finer defect vocabulary — a negative
// vector that fails for the wrong reason is a failed vector.
type rejectKind int

const (
	kindTooLarge rejectKind = iota
	kindNonCanonical
	kindSchema
	kindUnknownKey
	kindOutsideValidity
	kindBadSignature
	kindSeqReplay
	kindPrevHashMismatch
	kindInclusionInvalid
	kindCommandString
)

var kindNames = [...]string{
	kindTooLarge:         "too_large",
	kindNonCanonical:     "non_canonical",
	kindSchema:           "schema",
	kindUnknownKey:       "unknown_key",
	kindOutsideValidity:  "outside_validity",
	kindBadSignature:     "bad_signature",
	kindSeqReplay:        "seq_replay",
	kindPrevHashMismatch: "prev_hash_mismatch",
	kindInclusionInvalid: "inclusion_invalid",
	kindCommandString:    "command_string",
}

// Reject is why a bundle was rejected: Code() is the ACK reject_code (08
// §9's frozen table); Kind() the finer vector vocabulary.
type Reject struct {
	kind   rejectKind
	detail string
}

func (r *Reject) Code() string {
	switch r.kind {
	case kindSeqReplay:
		return "M1E-3002"
	case kindInclusionInvalid:
		return "M1E-3003"
	case kindCommandString:
		return "M1E-3005"
	default:
		return "M1E-3001"
	}
}

func (r *Reject) Kind() string { return kindNames[r.kind] }

func (r *Reject) Error() string { return r.Kind() + ": " + r.detail }

// KeyEntry is one published section-class key. Bounds are strict
// second-precision RFC 3339 UTC ("" = unbounded side), the same precision
// mark1-receipt's windows carry; an unparseable bound fails CLOSED.
type KeyEntry struct {
	Public    ed25519.PublicKey
	NotBefore string
	NotAfter  string
}

// SectionKeys is the section-split key set (05 §4.5): one ring per section
// class, so a key can only ever answer for the class it was published under —
// ring membership IS the role (lib.rs SectionKeys; the receipt discipline of
// derived key_ids and RFC 8032 verify is identity's, reused).
type SectionKeys struct {
	rings [numSections]map[string]KeyEntry
}

func NewSectionKeys() *SectionKeys {
	sk := &SectionKeys{}
	for i := range sk.rings {
		sk.rings[i] = map[string]KeyEntry{}
	}
	return sk
}

// Insert publishes entry for section; the key_id is DERIVED, never taken, so
// a ring cannot hold a key under a name that will not verify it.
func (sk *SectionKeys) Insert(section Section, entry KeyEntry) string {
	id := identity.DeriveKeyID(entry.Public)
	sk.rings[section][id] = entry
	return id
}

// parseRFC3339UTC: strict fixed-precision `YYYY-MM-DDTHH:MM:SSZ` → epoch
// seconds (lib.rs parse_rfc3339_utc, ported — Go's time.Parse tolerates
// fractional seconds the Rust twin rejects, and the two legs must fail the
// same inputs). false = unparseable, which the caller treats as OUTSIDE
// validity: trust metadata fails closed, never open.
func parseRFC3339UTC(s string) (int64, bool) {
	if len(s) != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' ||
		s[13] != ':' || s[16] != ':' || s[19] != 'Z' {
		return 0, false
	}
	num := func(a, b int) (int64, bool) {
		var n int64
		for i := a; i < b; i++ {
			if s[i] < '0' || s[i] > '9' {
				return 0, false
			}
			n = n*10 + int64(s[i]-'0')
		}
		return n, true
	}
	y, ok1 := num(0, 4)
	mo, ok2 := num(5, 7)
	d, ok3 := num(8, 10)
	h, ok4 := num(11, 13)
	mi, ok5 := num(14, 16)
	sec, ok6 := num(17, 19)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return 0, false
	}
	leap := (y%4 == 0 && y%100 != 0) || y%400 == 0
	var dim int64
	switch mo {
	case 1, 3, 5, 7, 8, 10, 12:
		dim = 31
	case 4, 6, 9, 11:
		dim = 30
	case 2:
		dim = 28
		if leap {
			dim = 29
		}
	default:
		return 0, false
	}
	if d < 1 || d > dim || h > 23 || mi > 59 || sec > 59 {
		return 0, false
	}
	// Howard Hinnant's days_from_civil — the same integer math the estate's
	// other legs reproduce without a date library.
	yy := y
	if mo <= 2 {
		yy--
	}
	era := yy
	if yy < 0 {
		era = yy - 399
	}
	era /= 400
	yoe := yy - era*400
	moAdj := mo + 9
	if mo > 2 {
		moAdj = mo - 3
	}
	doy := (153*moAdj+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	days := era*146_097 + doe - 719_468
	return days*86_400 + h*3_600 + mi*60 + sec, true
}

func sha256Parts(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return [32]byte(h.Sum(nil))
}

// verifyInclusionRFC6962 is RFC 6962-shape inclusion verification with
// SHA-256 (05 §4.4; the walk is RFC 9162 §2.1.3.2 verbatim, lib.rs
// verify_inclusion_rfc6962). leafEntry is the 32-byte body digest; leaf_hash
// = SHA-256(0x00 || entry), interior = SHA-256(0x01 || L || R) — the domain
// split that stops an interior node replaying as a leaf.
func verifyInclusionRFC6962(leafEntry [32]byte, leafIndex, treeSize uint64, path [][32]byte, root [32]byte) bool {
	if leafIndex >= treeSize {
		return false
	}
	fnode, snode := leafIndex, treeSize-1
	r := sha256Parts([]byte{0x00}, leafEntry[:])
	for _, p := range path {
		if snode == 0 {
			return false // path longer than the tree is deep
		}
		if fnode&1 == 1 || fnode == snode {
			r = sha256Parts([]byte{0x01}, p[:], r[:])
			if fnode&1 == 0 {
				for fnode&1 == 0 && fnode != 0 {
					fnode >>= 1
					snode >>= 1
				}
			}
		} else {
			r = sha256Parts([]byte{0x01}, r[:], p[:])
		}
		fnode >>= 1
		snode >>= 1
	}
	return snode == 0 && r == root
}

// sectionSigningInput is DECISION D-Q (07 §"PolicyBundle v1"):
// `b"mark1-bundle-v1\0" || canonical-CBOR(bundle-sig-input)` — a
// domain-separated canonical-CBOR structure, never a bare concatenation. The
// nine-field map covers every envelope field EXCEPT `inclusion` (a
// transparency-log leaf cannot commit to the proof of its own inclusion).
func sectionSigningInput(section Section, sectionBytes []byte, tenantID [16]byte,
	channel string, seq, issuedAtEpochS, maxAgeS uint64, prevHash [32]byte) ([]byte, error) {
	// encodeCanonical sorts the entries; listed here in D-Q's doc order.
	sigInput := vmap{
		{"schema", Schema},
		{"section_name", section.Name()},
		{"tenant_id", tenantID[:]},
		{"channel", channel},
		{"seq", seq},
		{"issued_at", vtag{1, issuedAtEpochS}},
		{"max_age", maxAgeS},
		{"prev_hash", prevHash[:]},
		{"section", sectionBytes},
	}
	enc, err := encodeCanonical(sigInput)
	if err != nil {
		return nil, err
	}
	return append(append(make([]byte, 0, len(signingDomain)+len(enc)), signingDomain...), enc...), nil
}

// bodySHA256FromEntries is SHA-256 of the bundle BODY: the canonical map
// minus its `inclusion` entry. The proof cannot cover itself, so the body is
// what the tlog leaf, the ACK bundle_hash (m1_009 body_sha256) and the next
// bundle's prev_hash all commit to.
func bodySHA256FromEntries(entries vmap) ([32]byte, *Reject) {
	body := make(vmap, 0, len(entries))
	for _, e := range entries {
		if k, ok := e.k.(string); ok && k == "inclusion" {
			continue
		}
		body = append(body, e)
	}
	enc, err := encodeCanonical(body)
	if err != nil {
		return [32]byte{}, &Reject{kind: kindNonCanonical, detail: err.Error()}
	}
	return sha256Parts(enc), nil
}

// VerifyAndDecode is the full verification order (04 §7.3) — the twin of
// lib.rs verify_and_decode.
//
// lastAppliedSeq is nil when no bundle has ever been accepted (the only state
// in which bundle zero's seq == 0 is admissible — a bare u64 cannot say
// "nothing yet" without stealing a legal seq value).
//
// DECISION D-S: tlogHead is the caller's PINNED log head, REQUIRED at
// seq > 0 — nil there is an M1E-3003 refusal, and a proof whose root differs
// from the head is an M1E-3003 rejection; verifying against a root read from
// the bundle's OWN inclusion map is self-consistency, not evidence. At
// seq == 0 the D-P waiver holds and the head is structurally irrelevant.
//
// For seq > 0 this function proves prev_hash is WELL-FORMED but cannot prove
// linkage — the last-accepted body hash lives in the caller's LKG state,
// compared against Bundle.BodySHA256 of its retained bundle. The seq-0
// genesis rule IS checked here, structurally.
func VerifyAndDecode(raw []byte, keys *SectionKeys, lastAppliedSeq *uint64, tlogHead *TlogHead) (*Bundle, *Reject) {
	// ── canonical form + envelope (parsing precedes signatures by necessity;
	//    nothing below trusts a byte the canonical check did not pin) ──
	if len(raw) > MaxBundleLen {
		return nil, &Reject{kind: kindTooLarge, detail: fmt.Sprintf("bundle exceeds MaxBundleLen (%d bytes)", len(raw))}
	}
	value, err := decodeCanonical(raw)
	if err != nil {
		return nil, &Reject{kind: kindNonCanonical, detail: err.Error()}
	}
	entries, isMap := value.(vmap)
	if !isMap {
		return nil, schemaErr("bundle", "expected map")
	}
	top, rej := mapOf(value, "bundle")
	if rej != nil {
		return nil, rej
	}
	if rej = strictKeys(top, []string{
		"schema", "tenant_id", "channel", "seq", "issued_at",
		"max_age", "prev_hash", "sections", "signatures", "inclusion",
	}, nil, "bundle"); rej != nil {
		return nil, rej
	}

	schemaVal, rej := textVal(top["schema"], "bundle.schema")
	if rej != nil {
		return nil, rej
	}
	if schemaVal != Schema {
		return nil, schemaErr("bundle.schema", "expected "+Schema)
	}
	tb, rej := bytesN(top["tenant_id"], 16, "bundle.tenant_id", "expected 16-byte uuid")
	if rej != nil {
		return nil, rej
	}
	tenantID := [16]byte(tb)
	channel, rej := checkChannel(top["channel"], "bundle.channel")
	if rej != nil {
		return nil, rej
	}
	seq, rej := uintVal(top["seq"], "bundle.seq")
	if rej != nil {
		return nil, rej
	}
	// CDDL `time` = tag 1 epoch seconds; non-integer time has no canonical
	// second-precision meaning here and is rejected.
	tag, isTag := top["issued_at"].(vtag)
	if !isTag || tag.num != 1 {
		return nil, schemaErr("bundle.issued_at", "expected tag-1 time")
	}
	issuedAtEpochS, rej := uintVal(tag.inner, "bundle.issued_at")
	if rej != nil {
		return nil, rej
	}
	maxAgeS, rej := uintVal(top["max_age"], "bundle.max_age")
	if rej != nil {
		return nil, rej
	}
	pb, rej := bytesN(top["prev_hash"], 32, "bundle.prev_hash", "expected 32-byte hash")
	if rej != nil {
		return nil, rej
	}
	prevHash := [32]byte(pb)

	sections, rej := mapOf(top["sections"], "bundle.sections")
	if rej != nil {
		return nil, rej
	}
	if rej = strictKeys(sections, sectionNames[:], nil, "bundle.sections"); rej != nil {
		return nil, rej
	}
	signatures, rej := mapOf(top["signatures"], "bundle.signatures")
	if rej != nil {
		return nil, rej
	}
	if rej = strictKeys(signatures, sectionNames[:], nil, "bundle.signatures"); rej != nil {
		return nil, rej
	}

	// ── 1. section-split signatures, each against ITS class's ring ──
	issued := int64(math.MaxInt64)
	if issuedAtEpochS <= math.MaxInt64 {
		issued = int64(issuedAtEpochS)
	}
	for _, section := range AllSections() {
		path := "bundle.signatures." + section.Name()
		sigMap, rej := mapOf(signatures[section.Name()], path)
		if rej != nil {
			return nil, rej
		}
		if rej = strictKeys(sigMap, []string{"key_id", "sig"}, nil, path); rej != nil {
			return nil, rej
		}
		keyID, rej := textVal(sigMap["key_id"], path)
		if rej != nil {
			return nil, rej
		}
		sig, rej := bytesN(sigMap["sig"], ed25519.SignatureSize, path, "sig must be 64 bytes")
		if rej != nil {
			return nil, rej
		}
		entry, published := keys.rings[section][keyID]
		if !published {
			// Never published for THIS class — a wrong-role key lands here
			// too (ring membership IS the role; see SectionKeys).
			return nil, &Reject{kind: kindUnknownKey, detail: path + ": key_id not published for this section class"}
		}
		inWindow := func(bound string, after bool) bool {
			if bound == "" {
				return true // unbounded side
			}
			t, ok := parseRFC3339UTC(bound)
			if !ok {
				return false // unparseable trust metadata fails closed
			}
			if after {
				return issued >= t
			}
			return issued <= t
		}
		if !inWindow(entry.NotBefore, true) || !inWindow(entry.NotAfter, false) {
			return nil, &Reject{kind: kindOutsideValidity, detail: path + ": key not valid at issued_at"}
		}
		sectionBytes, err := encodeCanonical(sections[section.Name()])
		if err != nil {
			return nil, &Reject{kind: kindNonCanonical, detail: err.Error()}
		}
		// D-Q: the signed message covers the whole envelope (minus
		// `inclusion`) AND the section name — so the issued_at the key window
		// above was judged against is itself under the signature.
		msg, err := sectionSigningInput(section, sectionBytes, tenantID, channel, seq, issuedAtEpochS, maxAgeS, prevHash)
		if err != nil {
			return nil, &Reject{kind: kindNonCanonical, detail: err.Error()}
		}
		if !identity.Verify(entry.Public, sig, msg) {
			return nil, &Reject{kind: kindBadSignature, detail: path + ": signature does not verify"}
		}
	}

	// ── 2. monotonic seq per (tenant, channel): a single `>` with no
	//       exception path — an exception path would BE a replay hole (05
	//       §4.6: rollback is a new higher seq, never a lower one) ──
	if lastAppliedSeq != nil && seq <= *lastAppliedSeq {
		return nil, &Reject{kind: kindSeqReplay, detail: fmt.Sprintf("seq %d <= last applied %d (anti-rollback)", seq, *lastAppliedSeq)}
	}

	// ── 3. prev_hash genesis rule + transparency-log inclusion ──
	if seq == 0 && prevHash != genesisPrevHash {
		return nil, &Reject{kind: kindPrevHashMismatch, detail: "prev_hash does not chain from genesis at seq 0"}
	}
	body, rej := bodySHA256FromEntries(entries)
	if rej != nil {
		return nil, rej
	}
	var tlog *TlogInclusion
	_, inclusionIsNull := top["inclusion"].(null)
	switch {
	// D-P's structural waiver: bundle zero is local and pre-log; the
	// carve-out is this literal 0, never configuration.
	case seq == 0 && inclusionIsNull:
		tlog = nil
	case seq == 0:
		return nil, &Reject{kind: kindInclusionInvalid, detail: "seq 0 is pre-log; inclusion must be null"}
	default:
		path := "bundle.inclusion"
		// D-S: no pinned head means no evidence to verify against — refuse
		// (the caller keeps last-known-good) rather than fall back to the
		// bundle's own root, which is what made M1E-3003 decorative at
		// seq > 0.
		if tlogHead == nil {
			return nil, &Reject{kind: kindInclusionInvalid, detail: "no pinned tlog head at seq > 0"}
		}
		if inclusionIsNull {
			return nil, &Reject{kind: kindInclusionInvalid, detail: "proof missing"}
		}
		pm, rej := mapOf(top["inclusion"], path)
		if rej != nil {
			return nil, rej
		}
		if rej = strictKeys(pm, []string{"leaf_index", "tree_size", "path", "root"}, nil, path); rej != nil {
			return nil, rej
		}
		leafIndex, rej := uintVal(pm["leaf_index"], path)
		if rej != nil {
			return nil, rej
		}
		treeSize, rej := uintVal(pm["tree_size"], path)
		if rej != nil {
			return nil, rej
		}
		rb, rej := bytesN(pm["root"], 32, path, "root must be 32 bytes")
		if rej != nil {
			return nil, rej
		}
		root := [32]byte(rb)
		rawPath, rej := arrayVal(pm["path"], path)
		if rej != nil {
			return nil, rej
		}
		audit := make([][32]byte, 0, len(rawPath))
		for _, hv := range rawPath {
			hb, rej := bytesN(hv, 32, path, "path hash must be 32 bytes")
			if rej != nil {
				return nil, rej
			}
			audit = append(audit, [32]byte(hb))
		}
		// D-S's normative comparison: the proof must target the PINNED head,
		// not a root it carried in. Tree-size equality is subsumed (two
		// SHA-256 trees of different sizes cannot share a root) but checked
		// so a mismatched checkpoint is named, not walked.
		if root != tlogHead.Root || treeSize != tlogHead.TreeSize {
			return nil, &Reject{kind: kindInclusionInvalid, detail: "proof does not target the pinned log head"}
		}
		if !verifyInclusionRFC6962(body, leafIndex, treeSize, audit, root) {
			return nil, &Reject{kind: kindInclusionInvalid, detail: "audit path does not reproduce root"}
		}
		tlog = &TlogInclusion{LeafIndex: leafIndex, TreeSize: treeSize, Root: root}
	}

	// ── 4. strict typed schema decode (the M1E-3005 structural scan) ──
	b := &Bundle{
		TenantID:       tenantID,
		Channel:        channel,
		Seq:            seq,
		IssuedAtEpochS: issuedAtEpochS,
		MaxAgeS:        maxAgeS,
		PrevHash:       prevHash,
		BodySHA256:     body,
		Tlog:           tlog,
	}
	if b.Verify, rej = decodeVerify(sections["verify"]); rej != nil {
		return nil, rej
	}
	if b.Route, rej = decodeRoute(sections["route"]); rej != nil {
		return nil, rej
	}
	if b.Memory, rej = decodeMemory(sections["memory"]); rej != nil {
		return nil, rej
	}
	if b.Cortex, rej = decodeCortex(sections["cortex"]); rej != nil {
		return nil, rej
	}
	if b.Gates, rej = decodeGates(sections["gates"]); rej != nil {
		return nil, rej
	}
	if b.AgentMaps, rej = decodeAgentMaps(sections["agent_maps"]); rej != nil {
		return nil, rej
	}
	return b, nil
}
