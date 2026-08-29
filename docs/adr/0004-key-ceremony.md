# ADR-0004 — Key ceremony: every key in the system, and the Ed25519/KMS split

- **Status:** Proposed — awaiting founder sign-off (one of the four ADRs the plan requires signed before Phase 1)
- **Date:** 2026-08-28
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** expensive — every signature ever produced must verify forever, so an algorithm or custody change is additive-only: the offline verifier and `KeyRing` carry every historical algorithm permanently, and reversing means a rotation ceremony plus a verifier release, never a deletion
- **Blocks:** Phase 1 receipt work (vendored chain primitives, checkpoint model, device origin-signing, external witness, standalone verifier — critical files 5–7), the first bundle publication, and the ceremony itself

## Context

Mark 1's trust story is cryptographic, not contractual: dual-signed receipt checkpoints, section-signed policy bundles, a signed update channel, per-tenant HMAC salts, per-tenant KMS data keys, and an external witness. Every one of those rests on a key, and the plan (`spec/execution-plan-v2.md`, "Decisions to make before code" item 4) requires the full key inventory — generation, custody, rotation, revocation, cross-signing, blast radius — decided and the ceremony signed before Phase 1.

The threat model already wrote most of this down: **§9 of `10-security-threat-model.md` is this ADR's content, written to be signed from.** This ADR formalizes §9.1 (the key table) and §9.2 (the runbook) rather than re-deriving them, and resolves the one contradiction the reconciliation pass found inside them.

**The hard problem — R-01 (`RECONCILIATION.md`).** The plan requires two things that cannot both hold:

1. Receipts use **Ed25519 chain primitives**, vendored from `recovery-orchestrator/app/receipts/keys.py`, whose `key_id` scheme is `"ed25519:" + sha256(pub)[:16]` — production-proven code, one signing discipline product-wide.
2. Server-side signing keys (server chain key, six bundle section keys, the update/transparency-log key) are **KMS-resident, sign-only, non-exportable** — custody by IAM policy, every signature CloudTrail-logged, export structurally impossible.

AWS KMS supports RSA and ECDSA (P-256/P-384/P-521). It does **not** support Ed25519. One of the two requirements must bend.

The deciding lens: the offline verifier (`tools/verifier/`) is a **customer-facing open-source artifact**, and "verify Omium" is the sales claim. Verifier complexity is therefore a product cost, not merely an engineering one.

## Decision

**Adopt option (a) — the split.** Recommended for founder sign-off; status stays Proposed until signed.

- **P-256 (ECDSA, `ECC_NIST_P256`, `ECDSA_SHA_256`) in AWS KMS** for the server chain key, the six bundle section keys, and the update/transparency-log key. Sign-only, non-exportable, key policies granting `kms:Sign` to exactly one consuming role each.
- **Ed25519 retained on devices** — device origin-signing key, X25519 spill keypair's signing sibling — where the private key is locally held anyway and the vendored `keys.py` primitives are reused unchanged.
- **The algorithm-prefixed `key_id` absorbs the difference**: `"ed25519:" + sha256(pub)[:16]` for device keys, `"p256:" + sha256(spki)[:16]` for KMS keys. The vendored scheme already carries the prefix; no format change.
- **The offline verifier and `mark1-receipt::KeyRing` implement both algorithms.** One `KeyRing` is the single implementation of "was this signature made by a then-valid key" for `mark1d`, the proxy, and the verifier alike (threat model §9.1, manifest mechanics).
- All non-KMS key classes (device keys, guard HMAC key, per-tenant HMAC salts, per-tenant S3 CMKs, device/loopback tokens) are adopted exactly as specified in threat model §9.1 — that table is normative and incorporated here by reference, including: rotation-is-re-enrollment for device keys, salt destruction as crypto-erasure at offboarding, per-tenant CMK + bucket-policy deny binding prefix to key, and **update key ≠ bundle key enforced by boot refusal R5**.

### The key inventory (normative summary; full table in threat model §9.1)

| Key | Algo / residence | Blast radius on compromise |
|---|---|---|
| Device key (per device) | Ed25519, keychain/TPM/0600 floor | Forge as that one device until revoked (≤60 s cutoff); cannot touch other devices, the server chain, or witnessed history |
| Device X25519 spill keypair | X25519, `mark1d.identity` only | Read that machine's post-redaction spill rings (≤24 h TTL) |
| Guard HMAC key (per device) | HMAC-SHA256, device-local | Forge credential fingerprints locally; shape tripwire and marker kill path still stand |
| Per-tenant HMAC salt | Symmetric, server + device custody ladder | Dictionary inversion of that one tenant's low-entropy digests; zero cross-tenant effect |
| Server chain key | **P-256, KMS** | Forge countersigns on new receipts only; device origin signatures + hourly witnessed heads bound rewrite detection to ≤1 h |
| Bundle section keys (×6) | **P-256, KMS** | One section, fleet-wide, until rotation; bounded by section semantics (gates open-only, no command strings, no code) |
| Update / tlog key | **P-256, KMS**, distinct from every bundle key (boot refusal R5) | The worst key: forged update = fleet RCE. Survivable mitigations: per-OS code signing as an independent second signature, no default self-update on managed fleets, SLSA verification at the edge, witness-detectable tlog forks |
| Per-tenant S3 CMKs | AWS KMS symmetric | One tenant's objects at rest; cross-tenant radius zero by key separation |

### The ceremony (executable runbook — signed as this ADR's appendix)

Threat model §9.2 verbatim, with the algorithm corrected to P-256 for the eight KMS keys:

- **Participants (all required, no delegation):** founder (key owner), security lead/lead engineer (operator), one witness who is neither (counsel or external advisor). Remote attendance permitted with recorded video; the attestation names who attended how.
- **Preconditions:** AWS account per `09` with CloudTrail on; time-boxed ceremony IAM roles; transparency log deployed and writable; the attestation draft open and filled in live.
- **Steps:** (1) inventory read-back and confirmation of the eight keys to create; (2) `aws kms create-key` one at a time, `ECC_NIST_P256` sign/verify, key policy granting `kms:Sign` only to the named consuming role, `kms:Verify` public, no export, no `kms:PutKeyPolicy` for runtime principals, aliased `alias/mark1-sign-<name>-v1`; (3) **distinctness check** — operator demonstrates the update/log key id differs from every bundle section key id (the same predicate R5 enforces forever), witness initials it; (4) **manifest publication** — public keys exported via `kms:GetPublicKey`, `key_id`s derived, manifest with validity windows published to `/.well-known/mark1-keys` and appended to the transparency log; operator fetches the inclusion proof and verifies it with `tools/verifier` in the session; (5) **witness selection** — the external witness target(s) for hourly chain heads are decided here and recorded; the first head is published and verified from outside Omium infrastructure; (6) **negative proof** — one forbidden operation attempted per key class (export, sign from an unauthorized role), denials recorded: the ceremony attests what the keys *cannot* do; (7) **attestation** — the document is signed by all three, hashed, and the hash appended to the transparency log.
- **Rotation ceremony:** successor created → predecessor cross-signs the successor's manifest entry → overlapping validity windows → tlog leaf → consumers migrate at the boundary → predecessor stays verify-valid for its historical window forever. **Compromise rotation** sets `not_after` to the compromise time, publishes a revocation leaf, and re-signs or invalidates everything signed after that instant; the witness record bounds what "after" can hide.
- **Cadence:** yearly for server-side keys; device keys never rotate in place; salts on tenant request or incident. Any deviation from the runbook is itself a receipted event.

## Alternatives considered

### (b) Ed25519 everywhere, server keys in CloudHSM or a self-managed KMS

The strongest case: **one algorithm, one verifier path, one signing discipline.** The open-source verifier — the artifact customers audit — contains a single, boring, misuse-resistant signature scheme. Ed25519 has no nonce-reuse failure mode, no curve-parameter footguns; every historical receipt and every future one verifies through identical code. The vendored `keys.py` runs unmodified server-side. Security reviewers never ask "why two algorithms?" because there aren't two.

Why it loses: it trades a one-time verifier cost for a **permanent operational tax on a two-person company**. CloudHSM means a paid HSM cluster (multi-node for availability), its own user management outside IAM, its own backup and quorum ceremonies, and a custody model where key policy is HSM-user administration rather than an IAM JSON document reviewed in Terraform. A self-managed signing service (e.g., Vault Transit) is worse: the key custody control now depends on infrastructure Omium must itself secure, patch, and attest — exactly the "trust Omium" posture the receipt product exists to eliminate. KMS gives non-exportability, per-signature CloudTrail, and IAM-native custody for the price of an API call. The verifier carrying two well-known algorithms is a smaller product cost than the sales claim resting on custody machinery a hostile auditor will probe and a small team will misconfigure.

### (c) P-256 everywhere, including devices

The strongest case — and it is genuinely strong: **hardware alignment.** Apple's Secure Enclave and TPM 2.0's standard profiles support P-256 natively and do not support Ed25519. P-256 everywhere would let device keys be hardware-backed on macOS and Windows instead of falling to keychain-software or the 0600 file floor, and would still give the single-algorithm verifier of option (b) without CloudHSM. Under the split, the threat model's "TPM-CNG (Windows)" rung for an Ed25519 device key is aspirational — on hardware that only speaks P-256, the Ed25519 device key is software-held.

Why it loses: it deletes the one piece of production-proven signing code Mark 1 has. The vendored `keys.py`/`canonical.py`/`chain.py` lineage — including `verify_chain`'s five defect kinds and the append-only schema — is the plan's explicit reuse target ("one signing discipline product-wide"). Rewriting the device signing path as ECDSA means new crypto code on the most trust-critical surface, plus ECDSA's nonce-sensitivity on the *client* side, where the implementation is ours rather than KMS's (deterministic RFC 6979 mitigates, but now that mitigation is our code to get wrong, on three OSes). The hardware-backing gain is real but partial (Linux dev machines vary widely), and it remains available later: device keys "rotate" by re-enrollment, so individual devices can migrate to P-256 hardware keys under the algorithm-prefixed `key_id` scheme without a ceremony — the split leaves that door open rather than forcing it now.

### Deferring the decision (build Phase 1 with local Ed25519 server keys, move to KMS later)

The strongest case: unblocks receipt code immediately; KMS custody arrives before the first paying tenant. Why it loses: the first witnessed chain head and the first customer-verifiable receipt are the Phase 1 gate — shipping them under file-held server keys means the sales claim's launch collateral was signed under custody we then admit was temporary, and the "verify Omium" story starts with an asterisk. The decision is cheap to make now and expensive to retrofit into published, witnessed history.

## Consequences

### What this makes easy
- Server-key custody is IAM + CloudTrail + Terraform review — auditable with tools every enterprise security team already trusts; the ceremony's negative proofs (step 6) are one-line API denials.
- The vendored Ed25519 chain code ships unmodified on devices; Phase 1 receipt work starts immediately.
- Future algorithm additions (including Ed25519-in-KMS if AWS ever ships it, or hardware-backed P-256 device keys) are manifest entries and `KeyRing` cases, not redesigns — the prefix scheme already generalizes.

### What this makes hard
- The offline verifier permanently implements two signature schemes, and its documentation must explain why — every customer security review will ask.
- `KeyRing` conformance vectors must cover both algorithms across Rust and Go and the verifier, forever.
- The Windows/macOS device-key story is honestly "software-held Ed25519 with a hardware ladder above the file floor where the platform allows," not "hardware-backed" — enterprise questionnaires get the honest answer.

### What we accept
- Two algorithms in the trust chain, permanently (verify-forever means even a later consolidation only ever adds; it never removes).
- ECDSA on the server path — acceptable because KMS owns nonce generation and the private key never exists outside the HSM fleet AWS operates.
- The ceremony's ~half-day of three people's synchronous time, per initial ceremony and per rotation, as the price of an attestation worth showing an auditor.

## How we would know we were wrong

**Leading indicators, measurable:**
1. **Verifier friction:** two or more customer security reviews (or verifier-repo issues) in a rolling year flag the dual-algorithm surface as a finding rather than a question — the product cost we judged small is not small.
2. **AWS ships Ed25519 in KMS** (announcement is the signal): the split's entire rationale evaporates.
3. **A KMS-path ECDSA fault** (RUSTSEC/AWS advisory touching our verify path) forces an emergency posture we would not face under EdDSA.

**Migration path and cost:** all three indicators lead to the same move — a routine rotation ceremony creating Ed25519 (or new-curve) successors, cross-signed by the P-256 predecessors, manifest windows overlapped. Cost: one ceremony (~half a day), one `KeyRing`/verifier release, zero wire-format change, zero re-signing of history. The P-256 verify path remains in the verifier forever for the historical window — that residue is the irreversible part, and it is bounded to code, not to trust.

## References
- `docs/spec/execution-plan-v2.md` — "Decisions to make before code" item 4; C13 receipts; data stores (external witness); reuse section (`keys.py` key_id scheme)
- `docs/RECONCILIATION.md` — R-01 (the finding this ADR resolves), resolution rule
- `docs/10-security-threat-model.md` — §9.1 key table (normative, incorporated by reference), §9.2 ceremony runbook, §8.3 update key ≠ bundle key / boot refusal R5, §4.3 custody rule
- `Omium-platform/core-services/recovery-orchestrator/app/receipts/keys.py` — vendored Ed25519 Signer protocol, `key_id = "ed25519:" + sha256(pub)[:16]`
- AWS KMS asymmetric key specs (RSA, ECC_NIST_P256/P384/P521; no Ed25519) — the constraint that forced the decision
