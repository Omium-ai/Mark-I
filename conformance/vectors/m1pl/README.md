# `m1pl` conformance vectors — M1PL/1 frame codec

The golden byte vectors that the Rust decoder (`rust/m1p-wire`) and the Go decoder
(`go/mark1d/internal/fabric`) must agree on **bit-identically**. Divergence on any vector fails
CI (`tools/ci/conformance_crosslang.sh`, NFR-CORRECTNESS-005). This family pins the **framing
layer only** — payload bytes are opaque here; Python joins the gate at C6 via the `receipt/`
family (12 §3.4), and payload (`m1p.v1.Event`) decode conformance rides those later vectors.

**Frozen.** Per 12 §3.4 these vectors never regenerate; changing any byte or expectation
requires a schema-version bump (a `ver` byte other than `0x01`, i.e. an M1PL/2 conversation).
They are hand-assembled from 07 §5, whose byte layout leaves zero encoding freedom; the Rust
implementation is reference from C2 onward and must reproduce them, not re-emit them.

## Why raw `.bin` files and a JSON manifest, not a language-native fixture

13 §11 row C2: this directory **is** the seed corpus for the fuzz targets
(`m1p-wire/fuzz/frame_decode` and `FuzzM1plFrameRead` in `mark1d/internal/fabric`, 12 §4).
Fuzzers eat raw bytes, so the vectors are raw bytes — no loader, no per-language encoding, and
both requirements of 12 §3.4 fall out for free: a vector is runnable from either language
without a language-specific loader, and accept/reject vectors are distinguishable without
executing them (the filename prefix carries the expected first outcome).

Non-`.bin` files in this directory (`README.md`, `manifest.json`, `selfcheck.py`) are inert as
fuzz seeds — the fuzzer treats them as garbage inputs, which is itself a free robustness case.

## Frame format (normative owner: 07 §5; bound owner: 08 §4.2)

```
offset  size  field
0       4     magic   'M1PL'  (0x4D 0x31 0x50 0x4C)
4       1     ver     0x01 for M1PL/1
5       4     len     u32 little-endian payload length
                      BOUND: 0 < len <= M1PL_MAX_FRAME = 4_194_304 (4 MiB)
9       len   payload opaque at this layer (one encoded m1p.v1.Event on the wire)
```

All checks run from the 9-byte header, before any payload allocation (08 §4.2 — the bound
caps what a hostile length prefix can demand at 4 MiB, which is what makes the fuzz target
memory-safety evidence rather than an OOM lottery).

## Decoder model the manifest assumes (normative for this family)

The decoder is a pure function `decode(buf) -> accept(payload_len, consumed) | incomplete |
reject(code)` over the unconsumed buffer, applied repeatedly for multi-frame vectors:

1. `len(buf) < 9` ⇒ **incomplete**, without inspecting content. This pins the one behavior
   07 §5 leaves open (whether to reject a <9-byte buffer whose bytes already cannot extend to
   a valid magic): both implementations must buffer the full header, so eager prefix rejection
   is a conformance failure, not an allowed optimization.
2. At ≥ 9 bytes, header checks run: magic, ver, len bound. Every reject vector here violates
   exactly one field (12 §3.4: "a vector that is wrong in two ways proves only that
   *something* was caught"), so check *order* is unobservable and deliberately unpinned.
3. **accept** consumes exactly `9 + payload_len` bytes; **incomplete** consumes 0;
   **reject** means close the connection — `consumed` is undefined and the decoder must never
   scan forward looking for the next valid magic (12 §3.4 row 1: resynchronizing on
   attacker-chosen bytes is how a framing bug becomes a parsing primitive).
4. EOF while **incomplete** is a connection error, never a flush (12 §3.4 row 5). The
   manifest states decoder outcomes; the connection-level error at EOF is the test harness's
   half of the contract.

## Reject codes (08 §7 error table; 12 §3.4 rejection rows)

| Violation | Code | Owner |
|---|---|---|
| bad magic | `M1E-4002` | 12 §3.4 row 1 |
| `ver` outside the shipped set (`{0x01}`) | `M1E-4003` | 08 §7 ("first frame not Hello / version mismatch"), 08 §9 |
| `len == 0` | `M1E-4002` | 08 §4.2 ("len == 0 or len > M1PL_MAX_FRAME … M1E-4002"), 08 §7 |
| `len > M1PL_MAX_FRAME` | `M1E-4002` | 08 §4.2, 08 §7 |

The code is the **refusal identity** of 12 §3.4 — the error the decoder must reach — not a
message string, so Rust and Go agree on a refusal without agreeing on formatting.

## `manifest.json` schema

Top-level object mapping `<filename>` → expectation. Iterate the keys; every key is a vector.

- Single-outcome vector: `{"outcome": "accept"|"incomplete"|"reject", "payload_len"?,
  "consumed"?, "reject_code"?, "note"?}`. `payload_len`/`consumed` appear only on accept;
  `reject_code` only on reject.
- Multi-frame vector: `{"sequence": [<outcome object>, ...], "note"?}` — apply the decoder
  repeatedly, matching each outcome in order against the remaining buffer.
- `note` is documentation, never asserted.

## Vector inventory

| File | Expectation | Pins |
|---|---|---|
| `accept_min.bin` | accept, payload_len 1 | smallest legal frame |
| `accept_two_frames.bin` | accept, accept | consumed-offset arithmetic across frames |
| `accept_max_len.bin` | accept, payload_len 4194304 | bound is inclusive (`<=`, not `<`) |
| `accept_then_reject.bin` | accept, reject 4002 | tail garbage errors loudly, no resync |
| `accept_then_incomplete_tail.bin` | accept, incomplete | 12 §3.4 row 6 (3-byte tail) + EOF rule |
| `incomplete_header_len{1..8}.bin` | incomplete | every proper header prefix waits |
| `incomplete_payload.bin` | incomplete | header valid, payload short — no partial Event |
| `reject_bad_magic.bin` | reject 4002 | last magic byte wrong — full 4-byte compare |
| `reject_ver_00.bin` / `reject_ver_02.bin` | reject 4003 | shipped version set is exact |
| `reject_len_zero.bin` | reject 4002 | the lower half of the bound |
| `reject_len_over.bin` | reject 4002 | header-only: reject before any payload/allocation |

## Split iteration (required, test-side — one vector, not N files)

Frame-boundary handling under arbitrary chunking is proven by iteration, not by committing a
file per split point:

- `accept_min.bin` (10 bytes): for every k in 1..=9, feeding bytes `[0, k)` yields
  **incomplete**; feeding the remainder then yields the same accept the manifest states.
- `accept_two_frames.bin` (22 bytes): for every k in 1..=21, feeding `[0, k)` then `[k, 22)`
  yields the cumulative sequence `[accept(1), accept(3)]` with identical `consumed` values —
  no split point may produce a reject or a third outcome.

Both language tests MUST implement this loop; it is the codec's protection against the
"header split across two socket reads" bug class that single-shot vectors cannot see.

## Test naming (load-bearing — 12 §3.4)

The CI gate selects tests by filter, and a filter that matches nothing is a **failed** run:
Rust tests must match `conf_vectors_` (e.g. `conf_vectors_m1pl_rust`), Go test functions must
match `ConfVectors` (e.g. `TestConfVectorsM1pl` in `mark1d/internal/fabric`). Renaming a test
out of the filter is a red build by design.

## `selfcheck.py`

A stdlib-only audit that re-derives every vector's expected outcome from its bytes per the
rules above and diffs against `manifest.json`. It is **not** a fourth implementation under
test — it exists so a corrupted or mis-frozen vector is caught before it poisons two
languages. Run: `python3 conformance/vectors/m1pl/selfcheck.py` (exit 0 = consistent).
