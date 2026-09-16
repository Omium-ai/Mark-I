# Receipt conformance vectors — the three-language lock

`manifest.json` freezes the receipt byte contract that `python/shared/mark1_receipts`,
`rust/mark1-receipt` (+ `tools/verifier`) and `go/mark1d/internal/identity` must
reproduce **bit-identically**. This README is normative where the docs delegate a
construction detail (12 §3.4: the vector commit fixes what the prose left open);
everything else restates 07's receipts section, `migrations/m1_002_receipt_chain.sql`,
and the estate's `canonical.py` — the vendor source of truth.

Regenerate with `uv run --with blake3 --with cryptography python gen_vectors.py`.
The manifest is the frozen contract: if regeneration ever changes a byte, that is a
finding against `gen_vectors.py`, never a license to update the manifest.

## Canonical bytes (the one serialisation)

```
canonical_json(payload) = JSON with sort_keys, separators (",",":"), ensure_ascii
signing_input           = b"mark1-label-v1\x00" + canonical_json(payload) as UTF-8
receipt_hash            = SHA-256(signing_input)            # 32 bytes
```

- `ensure_ascii`: every non-ASCII character serialises as `\uXXXX`; astral characters
  as **surrogate pairs** (`😀` → `😀`). Control characters use JSON's short
  escapes where they exist (`\n`, `\t`) and `\u00XX` otherwise.
- Key order is Unicode **code-point** order, which equals UTF-8 byte order — Python's
  string sort, Go's byte sort and Rust's `str` ordering all agree. The `unicode`
  vector proves it (`a < z < à < é`).
- `receipt_hash` covers the SIGNING INPUT, prefix included — a verifier that has
  recomputed the hash has by construction recomputed the exact bytes it hands to the
  signature check (estate `canonical.py`'s rule, kept verbatim).
- **Numbers: integers only.** A receipt payload MUST NOT contain a non-integer number,
  and implementations MUST refuse to canonicalise one. Cross-language float rendering
  is not deterministic (`repr` vs `strconv` vs `ryu`), so a float in a payload is a
  forgery generator. The `big_int` vector (2⁵³+1) additionally catches any
  implementation whose JSON layer detours through f64.
- Note on `04 §7.2`'s `receipt_hash(prev_hash, canonical_payload)` signature: the
  `prev_receipt_hash` travels **inside** the signed payload (hex), per the estate
  design — the two-arg form is satisfied by asserting the embedded prev equals the
  chain's expectation, then hashing the signing input alone. These vectors are the
  referee.

## Signatures (dual, one signing input)

Ed25519. Device origin signature and server countersignature are both over the SAME
`signing_input` (`m1_002`'s column comment). `device_key_id` rides inside the signed
payload; `server_key_id` rides alongside (row column) — it is a lookup hint, not a
trust input, because a signature only verifies under the key that actually made it.
`key_id = "ed25519:" + first 16 hex chars of SHA-256(public key)` — derived, never
configured. Keys are published per ROLE (05 §4.5's key-class split: device origin
keys ≠ the server chain key), and a lookup only succeeds inside the named role's set —
a server key that verifies a device-origin claim would let Omium mint history alone,
the exact direction dual-signing exists to close (m1_002 header). Role mismatch is
reported as `unknown_key`: the key is not in the published set *for that role*.

Test keys (TEST-ONLY, deliberately published): device seed `0x11 × 32`, server seed
`0x22 × 32`. Anything signed by these keys is by definition worthless outside tests.

## Merkle (checkpoints)

RFC 6962 shape with BLAKE3 (04 §7.2 names BLAKE3; 05 §4.4's tlog is already 6962 —
one tree discipline product-wide):

```
leaf_hash(leaf16)   = blake3(0x00 || leaf)          # leaves are 16-byte event_ids
node_hash(L, R)     = blake3(0x01 || L || R)
root([x])           = leaf_hash(x)
root(D[n])          = node_hash(root(D[0:k]), root(D[k:n])), k = largest power of 2 < n
inclusion_path      = bottom-up sibling subtree hashes (6962 audit path);
                      the leaf index decides left/right at each step
```

The `0x00`/`0x01` prefixes are second-preimage domain separation: an interior node can
never be replayed as a leaf. Odd counts split unbalanced (no duplication — duplication
is the CVE-2012-2459 shape). `m1_receipts.inclusion_path` stores the path as
concatenated 32-byte hashes in the same bottom-up order.

## Defect vocabulary (chain verification)

The estate's five, verbatim, plus three the dual-sig/checkpoint extensions require:

| defect | meaning |
|---|---|
| `broken_link` | payload's `prev_receipt_hash` ≠ predecessor's `receipt_hash` (or seq gap) |
| `payload_mismatch` | stored `receipt_hash` ≠ SHA-256 of the stored payload's signing input |
| `unknown_key` | a `key_id` not present in the published key set |
| `bad_signature` | device origin signature fails over the signing input |
| `non_canonical_payload` | stored payload text ≠ its own canonical re-serialisation |
| `bad_countersignature` | server countersignature fails over the signing input |
| `merkle_mismatch` | payload's `merkle_root` ≠ root recomputed from the leaves |
| `inclusion_path_invalid` | a leaf's path does not reproduce the root (wrong length included) |

`verify_chain` reports **every** defect, never just the first, plus `intact_prefix_seq`
and `last_good_seq` (estate `chain.py` semantics, kept).

## Rotation (ADR-0004) — `manifest.json["rotation"]`

The server chain key rotates: the retiring key's LAST receipt on a chain is a
`key_rotation` record (server act, `subject_id` = UUIDv5 of the successor's id) whose
signed payload carries `successor_key_id`; every later receipt is countersigned by the
successor, whose manifest entry carries `cross_sig` by the retiring key over
`"mark1-key-rotation-v1\0" || "server_chain" || 0x00 || successor pub (32 bytes)`.
A verifier that sees `server_key_id` change between two links requires BOTH — the
announcement in the chain and the endorsement in the key manifest — or names one defect:

| defect | meaning |
|---|---|
| `rotation_unchained` | the server key changed without the retiring key's receipt naming the successor, or without a verifying cross-signature on the successor |

It lives outside the frozen eight (`rotation.defect_vocabulary`): it is the key manifest
and the chain disagreeing, so the chain-walk legs that carry no manifest never emit it.
Test successor seed: `0x33 × 32`. `rotation.accept` is rows 1–4 as frozen plus the
rotation record (5) and one successor-signed row (6); `rotation.negatives` are
`rotation_without_cross_sign` (successor published bare) and `rotation_unannounced`
(row 5 re-signed without `successor_key_id`). Drivers: `tools/verifier`
`conf_vectors_verifier_follows_rotation` + the negatives loop, Go
`TestConfVectorsReceiptControldRotation`.

## Manifest layout & required tests

`manifest.json`: `keys`, `canonical[]` (payload → canonical_json → bytes → hash; incl.
integers outside int64/uint64 — Python ints and Go's `json.Number` are unbounded, so
the canonical bytes are too), `merkle` (three cases incl. odd-count and single-leaf,
with inclusion paths), `chain[]` (three dual-signed checkpoint receipts from genesis
plus one SERVER-ONLY receipt — `device_key_id`/`device_signature_hex` null, per
`ck_m1_receipts_origin`: only the three device-originated classes carry the device
signature), `negatives[]` (each a full object + `expect_defect`; incl. the server key
minting both signatures — key-ROLE binding per 05 §4.5's key-class split is what must
reject it — and a stripped device signature under an intact payload),
`defect_vocabulary`.

Every implementation MUST drive every manifest entry, positives and negatives, and
assert the named defect — a negative that fails for the wrong reason is a failure.
Test-name filters are load-bearing (`tools/ci/conformance_crosslang.sh`):
Rust `conf_vectors_*`, Go `TestConfVectors*`, Python `*conf_vectors*`.

## Changelog

- **2026-09-16 — `rotation` family added (additive).** Regenerated by the unchanged
  `gen_vectors.py` path first (byte-stable); the new code appends one top-level key and
  every pre-existing family is byte-identical. Python does not drive `rotation` (no
  Python verifier holds a key manifest).
