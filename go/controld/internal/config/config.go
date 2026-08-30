// Package config is controld's env-driven configuration (05 §1.3): one typed
// struct, defaults inline, DSNs as DERIVED values so sslmode=require cannot be
// forgotten per-deployment. Nothing here is read after boot; there is no
// hot-reload — a config change is a rollout, which is what makes the boot
// refusals R1–R7 (05 §1.2) sufficient.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"
)

// Swappable only so tests can observe the refusal; production always dies.
var fatalf = log.Fatalf

// Config carries every knob controld reads. Only C4-scope keys exist yet;
// enroll/policydist/dprelease keys arrive with their modules (WS-6/WS-7).
type Config struct {
	Port        string // CONTROLD_PORT default "8080"
	MetricsPort string // METRICS_PORT  default "9092"

	// Postgres — components, never a pasted DSN (05 §1.3: the DSN is derived,
	// sslmode pinned; asyncpg's default `prefer` silently fell back to
	// plaintext on the estate and pgx's default permits the same).
	PGHost        string // POSTGRES_HOST          required
	PGPort        string // POSTGRES_PORT          default "5432"
	PGDB          string // POSTGRES_DB            required
	PGAppUser     string // POSTGRES_APP_USER      required
	PGAppPassword string // POSTGRES_APP_PASSWORD  required

	// ClickHouse. The users are NOT configurable: 07 fixes exactly two
	// runtime users — m1p_ingest (INSERT-only) and m1p_query (SELECT-only) —
	// and making either name an env var would be an invitation to point a
	// path at a wider principal.
	CHAddr           string // CLICKHOUSE_ADDR             required, host:port
	CHIngestPassword string // CLICKHOUSE_INGEST_PASSWORD  required
	CHQueryPassword  string // CLICKHOUSE_QUERY_PASSWORD   required (querychoke's read principal, 05 §6)
	CHDatabase       string // CLICKHOUSE_DATABASE         default "mark1"
	// CLICKHOUSE_OFFBOARD_PASSWORD — OPTIONAL: the m1p_offboard deletion
	// principal (07 §"deletion path": erasure mutations are issued by the
	// offboarding ROLE, not the INSERT-only ingest user, which answers
	// ACCESS_DENIED to a DELETE). No route drives the delete template in
	// this wave; unset means the offboard handle stays nil and querychoke
	// refuses the template loudly at run time rather than mis-routing it.
	CHOffboardPassword string

	// QUERYCHOKE_ROLLUP_WRITE=1 arms the internal tvo_rollup_tenant_day
	// write route. PRODUCTION-WRITE GUARD: ADR-0001/ADR-0010 are UNSIGNED,
	// so this defaults OFF and is for test/dev lanes only; enabling it
	// requires INTEL_SERVICE_TOKEN (a write surface that verifies nothing
	// must be absent, never open).
	RollupWriteEnabled bool
	IntelServiceToken  string // INTEL_SERVICE_TOKEN — the ADR-0010 §2.2 service credential seam

	IngestBucket string // S3_INGEST_BUCKET required
	// S3_ENDPOINT is set only for the dev/compose MinIO stack (13 §11 C4:
	// "just dev-up"); empty means the real AWS endpoint resolution chain.
	S3Endpoint string // S3_ENDPOINT optional
	// KMS_TENANT_ALIAS_PREFIX default "alias/mark1-tenant-" (05 §2.2: SSE-KMS
	// under the tenant's dedicated key; the bucket policy makes a stamping bug
	// a write FAILURE, not a cross-tenant write).
	KMSTenantKeyAliasPrefix string
	// S3_DISABLE_SSEKMS=1 drops the SSE-KMS headers from landing PUTs — for
	// the dev/compose MinIO stack ONLY, which has no KMS and refuses the
	// headers, turning every landing into a 503 (s3land.Options.DisableSSEKMS).
	// Honored exclusively under AUTH_DEV_MODE=1; set anywhere else it is a
	// boot refusal (R1): a production object landing unencrypted is a legality
	// failure (05 §2.2), so the knob fails CLOSED.
	S3DisableSSEKMS bool

	// AUTH_DEV_MODE=1 keeps the dev HMAC verifier reachable (loud boot log in
	// cmd). 05 §1.3 wanted the dev seam DELETED when enroll landed; it stays
	// behind this explicit flag instead so compose/test stacks keep working —
	// recorded as a deliberate deviation in the enroll build report.
	AuthDevMode bool
	// AUTH_DEV_TOKEN_HMAC_KEY — the dev token seam's HMAC key. Required only
	// under AUTH_DEV_MODE=1 (a defaulted key is no verifier at all).
	DevTokenHMACKey string
	// AUTH_TOKEN_ED25519_SEED — the 32-byte seed (hex or base64) behind the
	// production device-token signing key (05 §3.3: Ed25519-signed by the
	// server). Required outside dev mode: a control plane that cannot sign
	// device tokens cannot enroll device #1.
	TokenSigningSeed []byte

	// SERVER_CHAIN_ED25519_SEED — the 32-byte seed (hex or base64) behind the
	// server CHAIN key that countersigns every receipt (m1_002; key-class
	// split 05 §4.5: this is NOT the device-token signing key above, and the
	// two sharing a seed would collapse the split). Env seam per estate
	// convention; 10 §9.2's KMS-resident custody is this seam's production
	// upgrade. Required outside dev mode: a control plane that cannot
	// countersign cannot accept checkpoint #1.
	ServerChainSeed []byte
	// WITNESS_BUCKET — the object-lock bucket the hourly witness job (m1_003)
	// publishes chain heads to. Empty ⇒ the job does not run (a dev stack
	// without a witness is honest about it; prod alerting owns the gap).
	WitnessBucket string
	// WITNESS_TENANTS — comma-separated tenant UUIDs to witness. A seam, not
	// a solution: controld_app holds no sanctioned cross-tenant enumeration
	// path (m1_001 FORCE-RLS on m1_tenants; 05 §7.3's table has no witness
	// row), so the list arrives by configuration until a sanctioned lister
	// exists. Required when WITNESS_BUCKET is set.
	WitnessTenants []string
	// WITNESS_RETAIN default 8760h (1 y): the object-lock horizon witness
	// heads are locked under. 0 disables the lock header (dev MinIO).
	WitnessRetain time.Duration

	// PUBLIC_BASE_URL — the externally reachable API base the enrollment poll
	// response advertises in `endpoints` (08 §3.1).
	PublicBaseURL string
	// SERVER_MIN_EDGE — the §10.1 minimum-version handshake floor delivered
	// at enrollment and on every refresh heartbeat. Default "0.0.0" = no floor.
	ServerMinEdge string

	// REVOCATION_CACHE_MAX_AGE default 60s; clamped DOWN, never up (05 §1.3):
	// the ≤60 s revocation staleness ceiling is a fail-closed guarantee
	// (05 §3.4), so config may tighten it but can never loosen it.
	RevocationCacheMaxAge time.Duration
	DrainTimeout          time.Duration // DRAIN_TIMEOUT default 25s (< pod grace 30s, 05 §1.5)
}

// Load reads the environment. Any missing required key is an error — the
// caller (MustLoad) turns that into boot refusal R1 (05 §1.2): a control
// plane guessing its own S3 bucket is worse than none.
func Load() (Config, error) {
	c := Config{
		Port:                    envOr("CONTROLD_PORT", "8080"),
		MetricsPort:             envOr("METRICS_PORT", "9092"),
		PGPort:                  envOr("POSTGRES_PORT", "5432"),
		CHDatabase:              envOr("CLICKHOUSE_DATABASE", "mark1"),
		KMSTenantKeyAliasPrefix: envOr("KMS_TENANT_ALIAS_PREFIX", "alias/mark1-tenant-"),
		S3Endpoint:              os.Getenv("S3_ENDPOINT"),
		CHOffboardPassword:      os.Getenv("CLICKHOUSE_OFFBOARD_PASSWORD"),
		AuthDevMode:             os.Getenv("AUTH_DEV_MODE") == "1",
		PublicBaseURL:           envOr("PUBLIC_BASE_URL", "https://api.mark1.omium.ai"),
		ServerMinEdge:           envOr("SERVER_MIN_EDGE", "0.0.0"),
	}
	required := []struct {
		key string
		dst *string
	}{
		{"POSTGRES_HOST", &c.PGHost},
		{"POSTGRES_DB", &c.PGDB},
		{"POSTGRES_APP_USER", &c.PGAppUser},
		{"POSTGRES_APP_PASSWORD", &c.PGAppPassword},
		{"CLICKHOUSE_ADDR", &c.CHAddr},
		{"CLICKHOUSE_INGEST_PASSWORD", &c.CHIngestPassword},
		{"CLICKHOUSE_QUERY_PASSWORD", &c.CHQueryPassword},
		{"S3_INGEST_BUCKET", &c.IngestBucket},
	}
	for _, r := range required {
		v := os.Getenv(r.key)
		if v == "" {
			return Config{}, fmt.Errorf("config: required env %s is unset (boot refusal R1, 05 §1.2)", r.key)
		}
		*r.dst = v
	}

	// The token seams' keys: production signing seed always wanted, and R1
	// only lets it be absent under the explicit dev flag; the dev HMAC key is
	// required exactly when the dev verifier will be wired.
	c.DevTokenHMACKey = os.Getenv("AUTH_DEV_TOKEN_HMAC_KEY")
	if c.AuthDevMode && c.DevTokenHMACKey == "" {
		return Config{}, fmt.Errorf("config: AUTH_DEV_MODE=1 but AUTH_DEV_TOKEN_HMAC_KEY unset (boot refusal R1, 05 §1.2)")
	}
	if rawSeed := os.Getenv("AUTH_TOKEN_ED25519_SEED"); rawSeed != "" {
		seed, err := decodeSeed(rawSeed)
		if err != nil {
			return Config{}, fmt.Errorf("config: AUTH_TOKEN_ED25519_SEED: %w", err)
		}
		c.TokenSigningSeed = seed
	} else if !c.AuthDevMode {
		return Config{}, fmt.Errorf("config: required env AUTH_TOKEN_ED25519_SEED is unset (boot refusal R1, 05 §1.2; 05 §3.3 device-token signing key)")
	}
	if rawSeed := os.Getenv("SERVER_CHAIN_ED25519_SEED"); rawSeed != "" {
		seed, err := decodeSeed(rawSeed)
		if err != nil {
			return Config{}, fmt.Errorf("config: SERVER_CHAIN_ED25519_SEED: %w", err)
		}
		c.ServerChainSeed = seed
	} else if !c.AuthDevMode {
		return Config{}, fmt.Errorf("config: required env SERVER_CHAIN_ED25519_SEED is unset (boot refusal R1, 05 §1.2; m1_002 server chain key)")
	}
	// The SSE-KMS escape hatch: "" off, "1" on, anything else a refusal — a
	// typo'd truthy value must not silently leave encryption ON against MinIO
	// (confusing) or, worse, read as intent to turn it OFF in prod.
	switch v := os.Getenv("S3_DISABLE_SSEKMS"); v {
	case "":
	case "1":
		if !c.AuthDevMode {
			return Config{}, fmt.Errorf("config: S3_DISABLE_SSEKMS=1 without AUTH_DEV_MODE=1 — an unencrypted landing object outside a dev stack is a legality failure, not a knob (boot refusal R1, 05 §1.2; 05 §2.2)")
		}
		c.S3DisableSSEKMS = true
	default:
		return Config{}, fmt.Errorf("config: S3_DISABLE_SSEKMS=%q is not \"1\" or unset (boot refusal R1, 05 §1.2)", v)
	}

	// The rollup-write arm switch: "" off, "1" on, anything else a refusal
	// (same posture as S3_DISABLE_SSEKMS — a typo'd truthy value must not
	// read as intent to arm a write path ADR-0010 has not licensed).
	switch v := os.Getenv("QUERYCHOKE_ROLLUP_WRITE"); v {
	case "":
	case "1":
		c.IntelServiceToken = os.Getenv("INTEL_SERVICE_TOKEN")
		if c.IntelServiceToken == "" {
			return Config{}, fmt.Errorf("config: QUERYCHOKE_ROLLUP_WRITE=1 without INTEL_SERVICE_TOKEN — a write surface that verifies nothing must be absent, never open (boot refusal R1, 05 §1.2)")
		}
		c.RollupWriteEnabled = true
	default:
		return Config{}, fmt.Errorf("config: QUERYCHOKE_ROLLUP_WRITE=%q is not \"1\" or unset (boot refusal R1, 05 §1.2)", v)
	}

	c.WitnessBucket = os.Getenv("WITNESS_BUCKET")
	if raw := os.Getenv("WITNESS_TENANTS"); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				c.WitnessTenants = append(c.WitnessTenants, s)
			}
		}
	}
	if c.WitnessBucket != "" && len(c.WitnessTenants) == 0 {
		return Config{}, fmt.Errorf("config: WITNESS_BUCKET set but WITNESS_TENANTS empty — a witness job with no tenants publishes nothing and hides it (boot refusal R1)")
	}

	var err error
	if c.WitnessRetain, err = durationOr("WITNESS_RETAIN", 8760*time.Hour); err != nil {
		return Config{}, err
	}
	if c.RevocationCacheMaxAge, err = durationOr("REVOCATION_CACHE_MAX_AGE", 60*time.Second); err != nil {
		return Config{}, err
	}
	// Clamp down, never up: 60 s is the ceiling the fail-closed revocation
	// contract (05 §3.4) is stated against, not a tunable.
	if c.RevocationCacheMaxAge > 60*time.Second {
		c.RevocationCacheMaxAge = 60 * time.Second
	}
	if c.DrainTimeout, err = durationOr("DRAIN_TIMEOUT", 25*time.Second); err != nil {
		return Config{}, err
	}
	return c, nil
}

// MustLoad is boot step 1 (05 §1.1); refusal is deliberately un-caught so the
// pod crashloops and the deploy is visibly broken instead of quietly degraded.
func MustLoad() Config {
	c, err := Load()
	if err != nil {
		fatalf("%v", err)
	}
	return c
}

// AppDSN derives the request-path DSN. sslmode=require is NOT configurable —
// that is the whole point of deriving rather than pasting (05 §1.3).
func (c Config) AppDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=require",
		url.QueryEscape(c.PGAppUser), url.QueryEscape(c.PGAppPassword),
		c.PGHost, c.PGPort, c.PGDB)
}

// decodeSeed accepts hex or base64 (std/url, padded or raw) — secret stores
// disagree on encodings and a boot refusal over padding helps nobody; the
// 32-byte length check is the invariant that matters (ed25519.SeedSize).
func decodeSeed(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		if b, err := dec(s); err == nil {
			if len(b) != 32 {
				return nil, fmt.Errorf("seed decodes to %d bytes, want 32", len(b))
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("seed is neither hex nor base64")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durationOr(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return d, nil
}
