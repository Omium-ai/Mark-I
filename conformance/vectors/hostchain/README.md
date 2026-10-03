# Hostchain conformance vectors — the v2 checkpoint payload (ADR-0017)

`manifest.json` is the referee for **host-bound receipts**: the checkpoint payload a
device seals when an external host (ADR-0012/0013) ran the sessions in the batch. It is
the receipt family's contract (`../receipt/README.md` — canonical bytes, dual signatures,
one signing input, the defect vocabulary) applied to one new payload shape; nothing here
redefines any of that, and `gen_vectors.py` imports the receipt generator's primitives
and test seeds rather than restating them.

## What is frozen

- **Payload v2.** The eleven v1 keys, unchanged, plus `hosts`, `arrests_acted`,
  `arrests_recommended`, and `v` = 2. `hosts[]` is sorted by `session_id`; each entry has
  every key present — `session_id`, `transport` (`fabric` | `jsonl` | `native`), `host_id`,
  `host_version`, `profile_hash`, `host_correlation_id`, `tasks[]` — and each task has
  `task_id` and, iff the host declared `supplies_identity`, `identity_hash`.
- **`profile_hash`** = sha256 over the ADR-0013 canonical profile (compact JSON, keys
  sorted); `profiles` carries the canonical text and the hash for a declared host that
  supplies identity (`cem888`), a file-tail host that does not (`tailhost`), and
  `hostprofile.Default` (the native session's profile).
- **`identity_hash`** = sha256(`identity_domain` ‖ host_id ‖ `\0` ‖ host_correlation_id ‖
  `\0` ‖ task_id hex); `identity_domain_hex` is the domain tag.
- **`chain[]`**: seq 1 is a v1 checkpoint, seq 2 a v2 checkpoint over a `fabric` cem888
  session (two tasks with identity hashes) and a `native` session, seq 3 a v2 checkpoint
  over a `jsonl` host with no tasks; `leaves_hex` are the Merkle leaves per seq so a
  verifier can recompute every root.
- **`negatives[]`**: `host_block_rewritten` (object-level tamper → `payload_mismatch`),
  `signed_a_different_host_block` (the device signed other hosts → `bad_signature`),
  `recommended_counted_as_acted` (text and object agree, the hash does not →
  `payload_mismatch`).

## Required tests

Every builder reproduces every chain row — bytes, hash, both signatures — from its own
API (mark1d `identity.Checkpoint.Payload`, controld `receipts.Checkpoint.Payload`, Rust
`CheckpointPayload::to_value_bound`, Python `build_checkpoint_payload(hosts=…)`), the
chain verifies from genesis, and every negative yields its named defect. Test-name filters
are load-bearing (`tools/ci/conformance_crosslang.sh`): Rust `conf_vectors_hostchain_*`,
Go `TestConfVectorsHostchain*`, Python `*conf_vectors_hostchain*`. The family is armed in
`conformance/vectors/EXPECTED` and the gate's `PY_REQUIRED`.

Regenerate from this directory with `uv run --frozen --all-packages python gen_vectors.py`;
the output is byte-stable.
