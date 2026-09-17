# Public key material (safe to commit)

`mark1-user-token-jwks.prod.json` — the public JWKS of the Mark 1 user-token signer that
auth-service serves at `/auth/mark1/jwks`. The private half lives only in AWS Secrets Manager
`omium/prod/mark1-token-signing-key` (ExternalSecret `mark1-token-signing-key`, auth-service
pod only). controld pins this document verbatim through `OMIUM_USER_JWKS_PINNED` with
`OMIUM_USER_ISSUER=https://api.omium.ai` (05 §10.1: pinned, never fetched). The `kid` is the
RFC 7638 thumbprint auth-service computes from the same key; rotation = new key in SM, new
file here, both pins updated in the same release.
