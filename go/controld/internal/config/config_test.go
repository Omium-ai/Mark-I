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
		"S3_INGEST_BUCKET": "mark1-ingest", "AUTH_DEV_TOKEN_HMAC_KEY": "k",
	} {
		t.Setenv(k, v)
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
