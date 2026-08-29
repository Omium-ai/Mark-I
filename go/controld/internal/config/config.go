// Package config is controld's env-driven configuration (05 §1.3): one typed
// struct, defaults inline, DSNs as DERIVED values so sslmode=require cannot be
// forgotten per-deployment. Nothing here is read after boot; there is no
// hot-reload — a config change is a rollout, which is what makes the boot
// refusals R1–R7 (05 §1.2) sufficient.
package config

import (
	"fmt"
	"log"
	"net/url"
	"os"
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

	// ClickHouse. The user is NOT configurable: 07 fixes exactly two runtime
	// users and ingest's is m1p_ingest; making the name an env var would be an
	// invitation to point the INSERT path at a wider principal.
	CHAddr           string // CLICKHOUSE_ADDR             required, host:port
	CHIngestPassword string // CLICKHOUSE_INGEST_PASSWORD  required
	CHDatabase       string // CLICKHOUSE_DATABASE         default "mark1"

	IngestBucket string // S3_INGEST_BUCKET required
	// S3_ENDPOINT is set only for the dev/compose MinIO stack (13 §11 C4:
	// "just dev-up"); empty means the real AWS endpoint resolution chain.
	S3Endpoint string // S3_ENDPOINT optional
	// KMS_TENANT_ALIAS_PREFIX default "alias/mark1-tenant-" (05 §2.2: SSE-KMS
	// under the tenant's dedicated key; the bucket policy makes a stamping bug
	// a write FAILURE, not a cross-tenant write).
	KMSTenantKeyAliasPrefix string

	// AUTH_DEV_TOKEN_HMAC_KEY — the C4 dev token seam's HMAC key (see
	// internal/auth/doc.go: Ed25519 server-key tokens arrive with enroll,
	// WS-6 / plan 1.4). Required because a token verifier with a defaulted
	// key is no verifier at all.
	DevTokenHMACKey string

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
		{"S3_INGEST_BUCKET", &c.IngestBucket},
		{"AUTH_DEV_TOKEN_HMAC_KEY", &c.DevTokenHMACKey},
	}
	for _, r := range required {
		v := os.Getenv(r.key)
		if v == "" {
			return Config{}, fmt.Errorf("config: required env %s is unset (boot refusal R1, 05 §1.2)", r.key)
		}
		*r.dst = v
	}

	var err error
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
