// Receipt chain verification and origin signing — the Go rendering of the
// estate's chain.py (vendored from core-services/recovery-orchestrator/app/
// receipts/chain.py, copied 2026-08-29) with the mark1 extensions of 07's
// receipts section / m1_002: the server COUNTERSIGNATURE over the same
// signing input, and the checkpoint Merkle fields. The defect vocabulary is
// the estate's five plus the three the extensions require, frozen by
// conformance/vectors/receipt/README.md.

package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Defect names are cross-language API (the verifier, tools/verifier, reports
// the same strings): renaming one orphans every auditor script that matches
// on it.
type Defect string

const (
	DefectBrokenLink           Defect = "broken_link"
	DefectPayloadMismatch      Defect = "payload_mismatch"
	DefectUnknownKey           Defect = "unknown_key"
	DefectBadSignature         Defect = "bad_signature"
	DefectNonCanonicalPayload  Defect = "non_canonical_payload"
	DefectBadCountersignature  Defect = "bad_countersignature"
	DefectMerkleMismatch       Defect = "merkle_mismatch"
	DefectInclusionPathInvalid Defect = "inclusion_path_invalid"
)

// DefectVocabulary in manifest order — the conformance test asserts equality
// so the two lists cannot drift apart silently.
var DefectVocabulary = []Defect{
	DefectBrokenLink, DefectPayloadMismatch, DefectUnknownKey, DefectBadSignature,
	DefectNonCanonicalPayload,
	DefectBadCountersignature, DefectMerkleMismatch, DefectInclusionPathInvalid,
}

// ChainDefect is one finding at one link. Never an error return: a verifier
// that stops at the first bad link reports one problem when there may be a
// thousand, and the SHAPE of the damage is the diagnostic (estate chain.py).
type ChainDefect struct {
	Seq    int64
	Defect Defect
	Detail string
}

// KeyRole is the key-CLASS split of 05 §4.5 as the receipt spine sees it:
// device origin keys and the server chain key are DISJOINT sets, and a lookup
// only succeeds inside the named role's set. Without the split the server key
// alone satisfies both legs of a dual-signed row — the "mint history"
// direction m1_002's dual-signing exists to close.
type KeyRole string

const (
	RoleDeviceOrigin KeyRole = "device_origin"
	RoleServerChain  KeyRole = "server_chain"
)

// PublishedKey is one published key: raw public bytes + role + optional
// tenant binding. TenantID is set for device keys (m1_001 scopes
// m1_device_keys per tenant) so a device key cannot answer another tenant's
// chain; the server chain key is global ("" — m1_002: the key signs for
// Omium, not for a tenant).
type PublishedKey struct {
	Pub      ed25519.PublicKey
	Role     KeyRole
	TenantID string
}

// KeySet is the published key set: key_id → published key. Rotated keys are
// never unpublished (estate keys.py; 05 §4.5's KeyRing keeps them verifiable
// forever), so a KeySet only ever grows.
type KeySet map[string]PublishedKey

// Add derives the id rather than taking one, so a KeySet cannot hold a key
// under a name that will not verify it.
func (ks KeySet) Add(pub ed25519.PublicKey, role KeyRole) string {
	id := DeriveKeyID(pub)
	ks[id] = PublishedKey{Pub: pub, Role: role}
	return id
}

// DeviceOriginTypes mirrors ck_m1_receipts_origin's equivalence (m1_002): the
// classes that ORIGINATE on a device carry the device signature; every other
// class is a server act — demanding a device key on those would make the
// server-only records, discontinuity included, unverifiable in this leg.
var DeviceOriginTypes = map[string]bool{
	"checkpoint":          true,
	"coverage_transition": true,
	"guard_contamination": true,
}

// Receipt is one stored chain row (m1_002 shape). PayloadText is the exact
// signed bytes as the text column holds them; hash and both signatures are
// checked against THOSE bytes, never a re-serialisation, so this verifier
// cannot pass a row an outside auditor would fail (estate chain.py).
// prev_receipt_hash and device_key_id travel INSIDE the payload — signing the
// link is what makes position part of the claim (estate canonical.py header);
// ServerKeyID rides alongside as a row column, a lookup hint and not a trust
// input, because a signature only verifies under the key that made it.
type Receipt struct {
	Seq         int64
	PayloadText string
	ReceiptHash [32]byte
	DeviceSig   []byte
	ServerKeyID string
	ServerSig   []byte
}

// ChainReport mirrors estate verify_chain's two "good" numbers, kept because
// they answer different questions: IntactPrefixSeq is the CUSTOMER's number
// (everything up to it is evidence, nothing past it is), LastGoodSeq the
// OPERATOR's (where a discontinuity record anchors).
type ChainReport struct {
	Checked         int
	Valid           bool
	Defects         []ChainDefect
	IntactPrefixSeq int64
	LastGoodSeq     int64
}

// VerifyChain walks recs (ordered by seq, starting at startSeq) and reports
// every defect. Estate verify_chain semantics kept verbatim, plus the
// countersignature leg m1_002 adds.
func VerifyChain(recs []Receipt, keys KeySet, startSeq int64) ChainReport {
	rep := ChainReport{IntactPrefixSeq: startSeq - 1}
	var expectedPrev *[32]byte
	if startSeq <= 1 {
		g := GenesisHash
		expectedPrev = &g
	}
	expectedSeq := startSeq
	prefixBroken := false

	for i := range recs {
		rec := &recs[i]
		rep.Checked++
		defects := verifyLink(rec, keys, expectedPrev, expectedSeq)
		rep.Defects = append(rep.Defects, defects...)
		if len(defects) == 0 {
			rep.LastGoodSeq = rec.Seq
			if !prefixBroken {
				rep.IntactPrefixSeq = rec.Seq
			}
		} else {
			prefixBroken = true
		}
		h := rec.ReceiptHash
		expectedPrev = &h
		expectedSeq = rec.Seq + 1
	}
	// Zero rows walked is a vacuous walk, not a verified history — an empty
	// export must never share a verdict with an intact chain (Defects stays
	// empty: there is no chain to have a defect IN).
	rep.Valid = rep.Checked > 0 && len(rep.Defects) == 0
	return rep
}

// VerifyReceipt checks one row in isolation. expectedPrev nil skips the link
// check (a mid-chain start has no predecessor to check against, estate
// start_seq > 1); expectedSeq <= 0 skips the gap check.
func VerifyReceipt(rec *Receipt, keys KeySet, expectedPrev *[32]byte, expectedSeq int64) []ChainDefect {
	return verifyLink(rec, keys, expectedPrev, expectedSeq)
}

func verifyLink(rec *Receipt, keys KeySet, expectedPrev *[32]byte, expectedSeq int64) []ChainDefect {
	var defects []ChainDefect
	add := func(d Defect, detail string) {
		defects = append(defects, ChainDefect{Seq: rec.Seq, Defect: d, Detail: detail})
	}
	signedBytes := append([]byte(DomainPrefix), rec.PayloadText...)

	// The payload parse is best-effort here: an unparseable payload still
	// gets its hash and signatures checked against the stored bytes, and the
	// canonical check below names the parse failure.
	payload, parseErr := DecodePayload([]byte(rec.PayloadText))
	fields, _ := payload.(map[string]any)

	if expectedSeq > 0 && rec.Seq != expectedSeq {
		add(DefectBrokenLink, fmt.Sprintf("expected seq %d, found %d; %d receipt(s) missing", expectedSeq, rec.Seq, rec.Seq-expectedSeq))
		// Estate rule: re-anchor on this row's own prev so a gap is reported
		// ONCE, not as wholesale tampering of every later link.
		expectedPrev = nil
	}
	if expectedPrev != nil {
		prevHex, _ := fields["prev_receipt_hash"].(string)
		if prev, err := hex.DecodeString(prevHex); err != nil || len(prev) != 32 {
			add(DefectBrokenLink, "payload carries no decodable prev_receipt_hash")
		} else if [32]byte(prev) != *expectedPrev {
			add(DefectBrokenLink, "prev_receipt_hash does not match the previous receipt's hash")
		}
	}

	if sha256.Sum256(signedBytes) != rec.ReceiptHash {
		add(DefectPayloadMismatch, "stored receipt_hash is not the hash of the stored payload")
	} else {
		// Signatures only when the hash holds (estate order): against
		// already-tampered bytes a signature failure adds noise, not
		// diagnosis. Device key comes from INSIDE the signed payload — and
		// ONLY the payload: an unsigned row column must never decide whether
		// an origin signature is owed.
		deviceKeyID, _ := fields["device_key_id"].(string)
		recordType, _ := fields["type"].(string)
		claimedTenant, _ := fields["tenant_id"].(string)
		switch {
		case deviceKeyID != "":
			entry, ok := keys[deviceKeyID]
			switch {
			case len(rec.DeviceSig) == 0:
				add(DefectBadSignature, "payload names a device_key_id but the row carries no device signature")
			case !ok:
				add(DefectUnknownKey, fmt.Sprintf("device_key_id %q is not in the published key set; a retired key dropped from publication looks exactly like this", deviceKeyID))
			case entry.Role != RoleDeviceOrigin:
				// A server key answering an origin claim is history minted
				// server-side — the direction dual-signing closes (m1_002).
				add(DefectUnknownKey, fmt.Sprintf("key_id %q is not published as a device origin key (key-class split, 05 §4.5)", deviceKeyID))
			case entry.TenantID != "" && entry.TenantID != claimedTenant:
				add(DefectUnknownKey, fmt.Sprintf("device_key_id %q is not published for the payload's tenant", deviceKeyID))
			case !Verify(entry.Pub, rec.DeviceSig, signedBytes):
				add(DefectBadSignature, "payload is intact but the origin signature does not verify under the key it names")
			}
		case DeviceOriginTypes[recordType]:
			add(DefectBadSignature, fmt.Sprintf("record_type %s originates on a device but the payload signs no device_key_id (ck_m1_receipts_origin)", recordType))
		}
		if entry, ok := keys[rec.ServerKeyID]; !ok {
			add(DefectUnknownKey, fmt.Sprintf("server_key_id %q is not in the published key set", rec.ServerKeyID))
		} else if entry.Role != RoleServerChain {
			add(DefectUnknownKey, fmt.Sprintf("key_id %q is not published as a server chain key (key-class split, 05 §4.5)", rec.ServerKeyID))
		} else if !Verify(entry.Pub, rec.ServerSig, signedBytes) {
			add(DefectBadCountersignature, "the server countersignature does not verify over the signing input")
		}
	}

	// Independent of the hash check: an auditor who re-serialises before
	// hashing and one who hashes the bytes as given must reach the SAME
	// verdict on every row, or neither can tell which of them is wrong.
	nonCanonical := parseErr != nil
	if !nonCanonical {
		recanon, err := CanonicalJSON(payload)
		nonCanonical = err != nil || recanon != rec.PayloadText
	}
	if nonCanonical {
		add(DefectNonCanonicalPayload, "the stored payload is not the canonical serialisation of itself")
	}
	return defects
}

// VerifyCheckpointRoot recomputes the Merkle root from the leaves and names
// the mismatch. nil means the claimed root is the tree's root.
func VerifyCheckpointRoot(leaves [][]byte, claimed [32]byte) *ChainDefect {
	root, err := MerkleRoot(leaves)
	if err != nil || root != claimed {
		return &ChainDefect{Defect: DefectMerkleMismatch, Detail: "payload's merkle_root is not the root recomputed from the leaves"}
	}
	return nil
}

// VerifyInclusion checks that (leaf, index, path) reproduces root in a tree
// of size leaves. A wrong-length path is the same named defect as a
// wrong-hash path — both mean the stored path proves nothing.
func VerifyInclusion(leaf []byte, index, size int, path [][32]byte, root [32]byte) *ChainDefect {
	got, err := RootFromPath(leaf, index, size, path)
	if err != nil || got != root {
		return &ChainDefect{Defect: DefectInclusionPathInvalid, Detail: "the inclusion path does not reproduce the merkle_root"}
	}
	return nil
}

// Checkpoint is the device-side batch summary (plan C13): N events → Merkle
// root over their event_ids → one chained, dual-signed receipt. Per-event
// receipts exist only for the six named classes (07); everything else rides
// under a checkpoint.
type Checkpoint struct {
	TenantID        string
	DeviceID        string
	Seq             int64
	PrevReceiptHash [32]byte
	IssuedAt        string // RFC 3339; written verbatim to the row's column too (estate rule)
	CheckpointSeq   int64
	MerkleRoot      [32]byte
	LeafCount       int
}

// Payload builds the checkpoint receipt payload in the exact field set the
// chain vectors freeze. deviceKeyID goes INSIDE: the origin claim is part of
// what gets signed.
func (c Checkpoint) Payload(deviceKeyID string) map[string]any {
	return map[string]any{
		"v":                 1,
		"type":              "checkpoint",
		"tenant_id":         c.TenantID,
		"seq":               c.Seq,
		"prev_receipt_hash": hex.EncodeToString(c.PrevReceiptHash[:]),
		"device_id":         c.DeviceID,
		"device_key_id":     deviceKeyID,
		"issued_at":         c.IssuedAt,
		"checkpoint_seq":    c.CheckpointSeq,
		"merkle_root":       hex.EncodeToString(c.MerkleRoot[:]),
		"leaf_count":        c.LeafCount,
	}
}

// OriginSigned is the device's half of a dual-signed receipt: the exact text
// the server must countersign as-is. The server adds its signature over the
// SAME signing input (m1_002's column comment) — it never re-serialises.
type OriginSigned struct {
	PayloadText string
	ReceiptHash [32]byte
	DeviceSig   []byte
}

// OriginSign canonicalises the payload once and signs the signing input —
// the mirror of what the server countersigns, and the only place device
// signatures are minted.
func OriginSign(key DeviceKey, payload map[string]any) (OriginSigned, error) {
	text, err := CanonicalJSON(payload)
	if err != nil {
		return OriginSigned{}, err
	}
	signedBytes := append([]byte(DomainPrefix), text...)
	sig, err := key.Sign(signedBytes)
	if err != nil {
		return OriginSigned{}, err
	}
	return OriginSigned{
		PayloadText: text,
		ReceiptHash: sha256.Sum256(signedBytes),
		DeviceSig:   sig,
	}, nil
}
