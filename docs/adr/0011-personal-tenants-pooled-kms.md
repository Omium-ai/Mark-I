# ADR-0011 — Personal tenants: one pooled KMS key for `kind='personal'`, per-tenant keys stay for organizations

- **Status:** Accepted — signed by Anurag Upadhyay (founder) 2026-09-16, as recommended by the lead ("organization keys per tenant, personal tenants share one pooled key"); recorded in docs/history/RECONCILIATION.md (D-EI)
- **Date:** 2026-09-16
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap before the first personal upload, expensive after — objects written under the pooled key cannot be re-keyed without a copy pass, and the bucket-policy deny statement is the control that makes the choice physical
- **Blocks:** the first upload from any personal tenant (the desktop app's solo-developer sign-in, `B3` in `mark1-execution-plan.md`); `s3land`'s key selection; the bucket policy in 09 §6

## Context

Mark 1's S3 posture (09 §"S3", 10 §S3, 10's key inventory row "Per-tenant KMS data keys") is one KMS CMK per tenant, `alias/mark1-tenant-<uuid>`, created at enrollment by `controld.enroll`, with a bucket-policy statement that denies any PUT whose key does not match the tenant prefix. Every ingest upload names that alias (`s3land.go:119`, `SSEKMSKeyId = alias/mark1-tenant-<uuid>`). The design assumed tenants are organizations: tens to low hundreds of them.

The desktop app (spec §3.2 step 1) mints **one tenant per person** on first sign-in (B2 memo §3.4: `m1_tenants.kind = 'personal'`, id = the platform `tenants.id`). Thousands of personal tenants break the per-tenant-key model twice: KMS bills ~US$1 per key per month (≈ US$12k/year at 1,000 developers, before a single request), and the bucket policy's per-tenant deny statement grows with tenants under a 20 KB policy-size cap, which stops working at a few hundred. Neither is a tuning problem; the model does not scale to individuals.

## Decision

1. **Organizations keep per-tenant keys** exactly as designed. Nothing changes for `kind='org'`.
2. **Personal tenants share one pooled key**, `alias/mark1-personal`, created once by IaC (not at enrollment). `s3land` selects the alias by tenant kind — one branch, read from the enrollment's tenant row, never from the request.
3. **Isolation for personal tenants moves from key separation to prefix + predicate**, which they already have: objects stay under `t/<tenant>/…`, ingest stamps the tenant from the verified token, the query chokepoint appends the tenant predicate on every read, and RLS holds in Postgres. The bucket-policy deny for the pooled key is a **prefix condition** (`s3:prefix` / resource ARN `t/*` under the pooled alias) rather than a per-tenant statement, so a mis-stamped PUT to an org prefix under the pooled key is still refused.
4. **Crypto-erasure is per-organization only.** A personal tenant's deletion is a receipted object delete under the 30-day quarantine/retention rules, not a key retirement. This is the one guarantee personal tenants lose, and the privacy language says so ("your data is deleted", not "cryptographically erased").
5. A personal tenant that becomes an organization (joins a team) gets an org tenant with its own key; the personal tenant's history stays under the pooled key. No re-keying.

## Consequences

- 09 §"S3" and §6 IAM, 10 §S3 and the key-inventory row gain a `personal` column; 05 §2.2's alias sentence becomes "by tenant kind".
- `s3land`: one branch + a boot refusal (R6 extension) proving the pooled alias exists and the pooled deny statement is present before the pod serves; a negative test that a `kind='org'` upload can never name the pooled key.
- Cost becomes flat for individuals; per-organization crypto-erasure is preserved where it is sold.
- Rejected: per-person keys (cost + policy cap); a single key for everyone (loses the org guarantee already promised in 10); envelope encryption with per-tenant data keys wrapped by one CMK (a second key-management system to build and audit for a property personal tenants do not buy — revisit if a personal tier ever needs crypto-erasure).
