# Bundle conformance vectors — the cross-language decode lock

`manifest.json` + the `.cbor` files freeze the PolicyBundle v1 byte contract that
`rust/mark1-policy` (the reference decoder, 07 §"PolicyBundle v1") and the Go decoder in
`go/mark1d` must reproduce identically: same accepts, same typed results, and for every
negative the same `M1E-*` code AND the same finer `kind` — a negative that fails for the
wrong reason is a failure.

Regenerate with `cargo run -p mark1-policy --example gen_bundle_vectors` (the committed
Rust generator — house rule: vectors are generated ONCE by the Rust reference
implementation). The committed files are the frozen contract: if regeneration ever
changes a byte, that is a finding against the generator, never a license to re-freeze.
`selfcheck.py` (stdlib-only) audits manifest/disk consistency without re-deriving any
decode behavior.

This README is normative where the docs delegate a construction detail (12 §3.4: the
vector commit fixes what the prose left open). Everything else restates 07's
PolicyBundle CDDL, 05 §4.4/§4.5, and 04 §7.3.

## Canonical form

RFC 8949 §4.2.1 deterministic encoding, checked by re-encode-and-compare: definite
lengths, minimal-length heads, map keys strictly sorted by the bytewise order of their
encoded form (duplicates impossible), floats at the SHORTEST width that preserves the
value (f16/f32/f64; NaN canonicalizes to `f97e00`). A non-canonical encoding of valid
content is an `M1E-3001`-class rejection, never a tolerant parse — a second byte
representation of the same bundle would make section signatures encoder-dependent.

## Construction details this commit fixes

- `tenant_id` is an UNTAGGED 16-byte bstr (07's CDDL says `uuid` and defines nothing;
  tags would complicate the canonical check for zero benefit).
- `issued_at` is tag 1 with non-negative INTEGER seconds.
- Section signing input (D-Q, 07 §"PolicyBundle v1"): `"mark1-bundle-v1\0" ||
  canonical_cbor({schema, section_name, tenant_id: bstr16, channel, seq,
  issued_at: tag1(uint), max_age, prev_hash: bstr32, section: bstr(canonical
  section bytes)})` — a domain-separated canonical-CBOR structure, never a bare
  concatenation, covering the whole envelope except `inclusion` (a tlog leaf
  cannot commit to the proof of its own inclusion). Ed25519 (RFC 8032), one
  KMS-class key per section (05 §4.5); `key_id = "ed25519:" + first 16 hex of
  SHA-256(pub)` (receipt discipline).
- **Body bytes** = the bundle map with the `inclusion` entry REMOVED, canonically
  re-encoded. The proof cannot cover itself, so `body_sha256` (= m1_009's
  `body_sha256`) is what the tlog leaf, the ACK `bundle_hash` and the next bundle's
  `prev_hash` all commit to.
- Transparency log: RFC 6962 shape with SHA-256 (05 §4.4). Leaf entry = `body_sha256`;
  `leaf_hash = sha256(0x00 || entry)`; `node = sha256(0x01 || L || R)`. The `inclusion`
  field is `{leaf_index, tree_size, path, root}` at `seq >= 1` and **null at `seq == 0`
  only** — lead ruling D-P's bundle-zero waiver, structural (`seq == 0` in code), never
  a flag.
- `prev_hash` genesis rule: `seq == 0` must chain from 32 zero bytes (m1_009's head
  default). For `seq > 0`, linkage against the last-accepted body hash is the caller's
  LKG state; the decoder proves shape only.
- `last_applied_seq` is nullable in this manifest: null = no bundle ever accepted (the
  only state admitting seq 0); otherwise the decoder rejects `seq <= last_applied_seq`
  with `M1E-3002`, a single `>` with no exception path.

## Keys (TEST-ONLY, deliberately published)

Six section-class seeds, ASCII `'1'`×32 (`verify`) through `'6'`×32 (`agent_maps`),
plus `'7'`×32: a verify-class key published WITH a `not_after` of 2020
(`expired_key` in the manifest) so `outside_validity` is drivable. Anything signed
by these keys is by definition worthless outside tests.

## Vectors

Each entry carries `tlog_head` (D-S): the pinned log head the driving caller holds —
`null` = no head pinned. Drivers MUST pass it (or its absence) to their decoder.

| name | expect | proves |
|---|---|---|
| `bundle_zero` | accept | D-P's Phase 2 fixture: seq 0, channel `local`, genesis prev_hash, null inclusion, fusion ON with literature-default 4×3 confusion matrices (D-R)/priors + the normative syntactic∪tests correlation group |
| `full` | accept | all six sections with every optional field, seq 1 on `stable`, single-leaf tlog proof targeting the pinned head |
| `minimal` | accept | smallest CDDL-admissible sections, seq 2, prev_hash chained to `full`'s body hash, 3-leaf tlog proof (non-trivial audit path) |
| `knee_p_lcb` | accept | D-Z's OPTIONAL knee-row `p_lcb`, in all three states (absent / 0.0 / 0.75) in one table: both decoders once had it out of their optional key set, which made every bundle able to arm the knee governor an `M1E-3001` |
| `bad_section_sig` | M1E-3001 / bad_signature | one corrupted section signature rejects the whole bundle |
| `wrong_key_role` | M1E-3001 / unknown_key | verify section signed by the (published) gates key: a key only answers for its OWN section class |
| `outside_validity` | M1E-3001 / outside_validity | verify section signed by the published-but-rotated-out key (`expired_key`, not_after 2020): windows are enforced against the SIGNED issued_at |
| `non_canonical` | M1E-3001 / non_canonical | same content as bundle_zero, top-level map keys reversed |
| `non_canonical_indef_map` | M1E-3001 / non_canonical | indefinite-length map head |
| `non_canonical_indef_text` | M1E-3001 / non_canonical | indefinite-length text string |
| `non_canonical_nonminimal_int` | M1E-3001 / non_canonical | integer < 24 widened to a two-byte head |
| `non_canonical_widened_float` | M1E-3001 / non_canonical | shorter-exact float emitted at full f64 width |
| `non_canonical_unsorted_nested` | M1E-3001 / non_canonical | a NESTED map with unsorted keys |
| `non_canonical_dup_key` | M1E-3001 / non_canonical | a nested map carrying a duplicate key |
| `seq_replay` | M1E-3002 / seq_replay | the valid seq-1 bundle offered after seq 1 was applied |
| `tampered_prev_hash` | M1E-3001 / prev_hash_mismatch | a seq-0 bundle validly SIGNED over a nonzero prev_hash: only the genesis chain rule can catch it |
| `backdated_issued_at` | M1E-3001 / bad_signature | the D-Q probe: issued_at rewritten to 2017 after signing — the envelope is signed now, so key revival by backdating is dead |
| `inclusion_missing` | M1E-3003 / inclusion_invalid | null proof at seq 1 (head present): the seq-0 waiver does not stretch |
| `tlog_head_missing` | M1E-3003 / inclusion_invalid | the valid seq-1 bundle offered to a caller with NO pinned head: D-S refuses rather than trusting the in-map root |
| `forged_inclusion_root` | M1E-3003 / inclusion_invalid | a self-consistent proof whose root is not the pinned head's: the pre-D-S self-authentication hole, closed |
| `tampered_body_self_proof` | M1E-3001 / bad_signature | the full review probe (max_age→u64::MAX, prev_hash rewritten, proof recomputed over the tampered body): dies on D-Q's envelope signature |
| `schema_stray_key` | M1E-3001 / schema | a SIGNED bundle with a stray `wasm_module` key in a section: strict maps (07 rule 3) are structural, and a stray key is schema, never a paged M1E-3005 |
| `too_large` | M1E-3001 / too_large | a buffer past MAX_BUNDLE_LEN dies on length before any parse |
| `command_string` | M1E-3005 / command_string | a properly SIGNED bundle whose catalog_id is a shell command; the structural grammar (07 rule 1) rejects the whole bundle |

Every implementation MUST drive every manifest entry, positives and negatives, and for
accepts assert `body_sha256_hex` plus the `summary` fields against its own decode.
Test-name filters are load-bearing (`tools/ci/conformance_crosslang.sh`): Rust
`conf_vectors_*` (`conf_vectors_bundle_*` here), Go `TestConfVectors*`.
