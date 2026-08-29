# `redact` conformance vectors — admit-to-upload axis

The golden document vectors that the Rust scanner (`rust/mark1-redact`) and the Go admit
twin (`go/mark1d/internal/redact`, wired into capture per 04 §2.0) must agree on
**bit-identically**: input document → substituted output (`⟨redacted:class:hash⟩`) +
admit-axis decision (12 §3.4). Divergence on any vector fails CI
(`tools/ci/conformance_crosslang.sh`, NFR-CORRECTNESS-005). This family pins the
**observable behavior of the starter ruleset** — which spans are flagged, what class they
carry, and the exact token bytes that replace them (CON-008).

> Known doc contradiction (for the reconciliation pass): 12 §3.4's owner column names the
> "Go `controld` ingest scanner" for this family, but 05 §2.1 and 12 §9 row 3 require that
> ingest scanner to be an INDEPENDENT ruleset that flags-and-quarantines, never substitutes
> — it cannot be the bit-identical twin. 04 §2.0 places the twin in `mark1d`'s capture
> pipeline, which is what exists; `conformance_crosslang.sh` runs `-run ConfVectors` over
> both Go modules, so the gate arms either way.

**Frozen.** Generated once by the Rust reference implementation (`mark1-redact`, C8) per
12 §3.4, then frozen: changing any byte or expectation is a ruleset-behavior change and lands
only with a new vector (adding rows is additive; editing rows is a redaction-contract break
that the Go twin would inherit silently — exactly what freezing prevents).

## Layout

One vector = a `<name>.in` / `<name>.out` byte pair plus its manifest entry:

- `<name>.in` — the input document, raw bytes.
- `<name>.out` — the exact bytes `admit` must leave in the buffer. For `clean` vectors it is
  byte-identical to the `.in` (Clean must not mutate).
- `manifest.json` — expectations. Raw file pairs, not a language-native fixture, for the same
  reason as `../m1pl/`: runnable from any language without a loader, and usable as-is as a
  seed corpus for `mark1-redact/fuzz`'s `admit` target (12 §4).

## The key (normative for this family)

`hash` in `⟨redacted:class:hash⟩` is the first 8 bytes of HMAC-SHA256(tenant key, span),
lowercase hex. Vectors are generated under the fixed test key in `manifest.json`
(`hmac_key_utf8`, ASCII bytes). The key is what makes the hash leg testable at all: it is a
*conformance* key, never a production value — production keys are per-tenant (04 §7.1).

## `manifest.json` schema

Top-level object: `hmac_key_utf8` (string, the scanner key as ASCII) and `vectors`, mapping
`<input filename>` → expectation:

- `outcome`: `"clean"` | `"redacted"` — the `AdmitOutcome` discriminant (04 §7.1). There is no
  `quarantine` vector **by design**: Quarantine is the internal-failure outcome (F-35) and is
  unreachable from input bytes in a correct scanner; its coverage is the fuzz target's
  totality assert and the unit suite, not a byte vector.
- `substitutions` (redacted only): the exact count `AdmitOutcome::Redacted` must report.
- `classes` (redacted only): token class labels in span order.
- `planted` (redacted only): the literal secret spans; asserted absent from the output and
  from every derived artifact — this list is also what `selfcheck.py` audits.
- `note`: documentation, never asserted.

## Vector inventory

| Vector | Expectation | Pins |
|---|---|---|
| `clean_prose` | clean | over-matching on code/prose/version literals |
| `aws_access_key_id` | redacted ×1 api_key | the AKIA/ASIA shape |
| `github_token` | redacted ×1 api_key | span-not-line replacement inside a URL |
| `anthropic_api_key` | redacted ×1 api_key | rule priority: `sk-ant-` beats the broader `sk-` (hash covers the full span) |
| `openai_api_key` | redacted ×1 api_key | the broad `sk-` shape |
| `pem_private_key` | redacted ×1 private_key | multi-line BEGIN…END is one span; tail survives |
| `jwt` | redacted ×1 oauth_token | three JOSE segments are one span |
| `high_entropy_hex` | redacted ×1 high_entropy | the entropy leg accepts random hex |
| `high_entropy_base64` | redacted ×1 high_entropy | base64 run incl. `=` padding is one span |
| `low_entropy_hex` | clean | the entropy leg REJECTS a shape-only match — the half a scanner without the randomness test gets wrong |
| `multi_secret` | redacted ×2 | exact count + offset arithmetic across a length-changing substitution |
| `repeated_secret` | redacted ×2 | equal secrets ⇒ byte-identical tokens under one key (in-tenant correlation, 04 §7.1) |
| `already_redacted` | clean | idempotency: the token grammar never matches a rule |

Every redacted vector is wrong in exactly one way relative to `clean_prose` (12 §3.4: "a
vector that is wrong in two ways proves only that *something* was caught"); `multi_secret`
and `repeated_secret` are the deliberate exceptions because count and correlation are
themselves the property under test.

## Test naming (load-bearing — 12 §3.4)

Rust: `conf_vectors_redact_rust` (in `rust/mark1-redact/tests/`), matched by the CI filter
`conf_vectors_`. Go: `TestConfVectorsRedact` in `go/mark1d/internal/redact`, matched by
`ConfVectors`. A filter that matches nothing is a **failed** run.

## `selfcheck.py`

A stdlib-only audit that checks the frozen pairs are internally consistent — every `.in` has
an `.out` and a manifest entry (and vice versa), clean pairs are byte-identical, every
`planted` secret is present in its `.in` and absent from its `.out`, and the output's
`⟨redacted:class:…⟩` token count and classes match `substitutions`/`classes`. It is **not** a
third scanner implementation — it re-derives nothing from the ruleset; it exists so a
corrupted or mis-frozen vector is caught before it poisons two languages.
Run: `python3 conformance/vectors/redact/selfcheck.py` (exit 0 = consistent).
