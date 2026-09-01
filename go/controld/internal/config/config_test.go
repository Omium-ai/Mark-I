package config

import (
	"strings"
	"testing"
	"time"
)

func setRequired(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"POSTGRES_HOST": "db", "POSTGRES_DB": "mark1",
		"POSTGRES_APP_USER": "controld_app", "POSTGRES_APP_PASSWORD": "p w%d",
		"CLICKHOUSE_ADDR": "ch:8123", "CLICKHOUSE_INGEST_PASSWORD": "chp",
		"CLICKHOUSE_QUERY_PASSWORD": "chq",
		"S3_INGEST_BUCKET":          "mark1-ingest",
		"AUTH_TOKEN_ED25519_SEED":   strings.Repeat("ab", 32), // 32 bytes of hex
		"SERVER_CHAIN_ED25519_SEED": strings.Repeat("cd", 32), // 32 bytes of hex
	} {
		t.Setenv(k, v)
	}
}

// The production signing seed is R1-required; only the explicit dev flag
// (with its own HMAC key) may stand in for it (05 §3.3 / task AUTH_DEV_MODE).
func TestTokenSeedRequiredUnlessDevMode(t *testing.T) {
	setRequired(t)
	t.Setenv("AUTH_TOKEN_ED25519_SEED", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AUTH_TOKEN_ED25519_SEED") {
		t.Fatalf("want R1 refusal naming the seed, got %v", err)
	}
	t.Setenv("AUTH_DEV_MODE", "1")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AUTH_DEV_TOKEN_HMAC_KEY") {
		t.Fatalf("dev mode without an HMAC key must refuse, got %v", err)
	}
	t.Setenv("AUTH_DEV_TOKEN_HMAC_KEY", "k")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.AuthDevMode || c.DevTokenHMACKey != "k" || c.TokenSigningSeed != nil {
		t.Fatalf("dev-mode config wrong: %+v", c)
	}
}

// The server CHAIN key seed is R1-required outside dev mode (m1_002: a
// control plane that cannot countersign cannot accept checkpoint #1), and it
// is a DIFFERENT key than the token signer — the 05 §4.5 key-class split.
func TestChainSeedRequiredUnlessDevMode(t *testing.T) {
	setRequired(t)
	t.Setenv("SERVER_CHAIN_ED25519_SEED", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SERVER_CHAIN_ED25519_SEED") {
		t.Fatalf("want R1 refusal naming the chain seed, got %v", err)
	}
	t.Setenv("AUTH_DEV_MODE", "1")
	t.Setenv("AUTH_DEV_TOKEN_HMAC_KEY", "k")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerChainSeed != nil {
		t.Fatalf("dev-mode config wrong: %+v", c)
	}
}

// A witness bucket with no tenant list would run an hourly job that
// witnesses nothing and looks healthy doing it — refused at boot.
func TestWitnessBucketRequiresTenants(t *testing.T) {
	setRequired(t)
	t.Setenv("WITNESS_BUCKET", "mark1-witness")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "WITNESS_TENANTS") {
		t.Fatalf("want R1 refusal naming WITNESS_TENANTS, got %v", err)
	}
	t.Setenv("WITNESS_TENANTS", "11111111-1111-1111-1111-111111111111, 22222222-2222-2222-2222-222222222222")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.WitnessTenants) != 2 || c.WitnessRetain != 8760*time.Hour {
		t.Fatalf("witness config wrong: %+v", c)
	}
}

// WITNESS_RETAIN=0 makes witness_s3.go omit the object-lock headers, so the
// head publishes mutable and the job still reports success — the same
// looks-healthy-doing-nothing shape as the refusal above, and the one config
// value that decides whether the chain is externally verifiable at all.
func TestWitnessRetainZeroNeedsAnExplicitOptOut(t *testing.T) {
	setRequired(t)
	t.Setenv("WITNESS_BUCKET", "mark1-witness")
	t.Setenv("WITNESS_TENANTS", "11111111-1111-1111-1111-111111111111")
	t.Setenv("WITNESS_RETAIN", "0s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "WITNESS_OBJECT_LOCK") {
		t.Fatalf("want R1 refusal naming WITNESS_OBJECT_LOCK, got %v", err)
	}
	t.Setenv("WITNESS_OBJECT_LOCK", "false")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "WITNESS_OBJECT_LOCK") {
		t.Fatalf("a near-miss opt-out value must be refused, not read as off: %v", err)
	}
	t.Setenv("WITNESS_OBJECT_LOCK", "off")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.WitnessRetain != 0 {
		t.Fatalf("deliberate opt-out did not survive: %+v", c)
	}
	// The escape must not widen to a witness that IS locked: with a retain
	// horizon set, WITNESS_OBJECT_LOCK is irrelevant and must not disarm it.
	t.Setenv("WITNESS_RETAIN", "24h")
	if c, err = Load(); err != nil || c.WitnessRetain != 24*time.Hour {
		t.Fatalf("retain=24h rejected or lost: %+v %v", c, err)
	}
}

// Without a bucket there is no witness to leave unlocked, so the guard must
// not fire — otherwise every non-witness deployment refuses to boot.
func TestWitnessRetainZeroIsFineWithNoBucket(t *testing.T) {
	setRequired(t)
	t.Setenv("WITNESS_RETAIN", "0s")
	if _, err := Load(); err != nil {
		t.Fatalf("no bucket, no witness, no refusal expected: %v", err)
	}
}

func TestTokenSeedDecodes(t *testing.T) {
	setRequired(t)
	t.Setenv("AUTH_TOKEN_ED25519_SEED", "not-a-seed")
	if _, err := Load(); err == nil {
		t.Fatal("garbage seed accepted")
	}
	t.Setenv("AUTH_TOKEN_ED25519_SEED", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") // 32 zero bytes, base64
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TokenSigningSeed) != 32 {
		t.Fatalf("seed length: %d", len(c.TokenSigningSeed))
	}
}

// R1: any missing required key refuses boot — no guessing (05 §1.2).
func TestMissingRequiredKeyRefused(t *testing.T) {
	setRequired(t)
	t.Setenv("S3_INGEST_BUCKET", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "S3_INGEST_BUCKET") {
		t.Fatalf("want R1 refusal naming the key, got %v", err)
	}
}

func TestDefaultsAndDerivedDSN(t *testing.T) {
	setRequired(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != "8080" || c.MetricsPort != "9092" || c.PGPort != "5432" {
		t.Fatalf("defaults: %+v", c)
	}
	if c.DrainTimeout != 25*time.Second {
		t.Fatalf("drain default: %v", c.DrainTimeout)
	}
	dsn := c.AppDSN()
	// sslmode=require is NOT configurable, and credentials are URL-escaped
	// (the password above contains a space and a %).
	if !strings.HasSuffix(dsn, "sslmode=require") {
		t.Fatalf("derived DSN must pin sslmode=require: %s", dsn)
	}
	if !strings.Contains(dsn, "p+w%25d") && !strings.Contains(dsn, "p%20w%25d") {
		t.Fatalf("password not escaped: %s", dsn)
	}
}

// S3_DISABLE_SSEKMS is honored ONLY under AUTH_DEV_MODE=1 — anywhere else an
// unencrypted landing object is a legality failure, so the knob fails CLOSED
// as a boot refusal (05 §2.2; R1). Typo'd truthy values refuse too: they must
// not read as intent in either direction.
func TestDisableSSEKMSOnlyInDevMode(t *testing.T) {
	setRequired(t)
	t.Setenv("S3_DISABLE_SSEKMS", "1")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "S3_DISABLE_SSEKMS") {
		t.Fatalf("SSEKMS disable outside dev mode must refuse boot, got %v", err)
	}
	t.Setenv("AUTH_DEV_MODE", "1")
	t.Setenv("AUTH_DEV_TOKEN_HMAC_KEY", "k")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.S3DisableSSEKMS {
		t.Fatal("dev-mode SSEKMS disable not honored")
	}
	t.Setenv("S3_DISABLE_SSEKMS", "true") // not "1": refuse, don't guess
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "S3_DISABLE_SSEKMS") {
		t.Fatalf("non-\"1\" truthy value must refuse, got %v", err)
	}
}

// The revocation staleness ceiling clamps DOWN, never up (05 §1.3/§3.4).
func TestRevocationMaxAgeClampsDownNeverUp(t *testing.T) {
	setRequired(t)
	t.Setenv("REVOCATION_CACHE_MAX_AGE", "5m")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.RevocationCacheMaxAge != 60*time.Second {
		t.Fatalf("config loosened a fail-closed ceiling: %v", c.RevocationCacheMaxAge)
	}
	t.Setenv("REVOCATION_CACHE_MAX_AGE", "10s")
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.RevocationCacheMaxAge != 10*time.Second {
		t.Fatalf("tightening must be allowed: %v", c.RevocationCacheMaxAge)
	}
}
