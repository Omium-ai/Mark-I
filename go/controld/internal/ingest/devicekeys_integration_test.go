//go:build integration

package ingest_test

// DSN-gated Postgres integration (M1_TEST_PG_DSN; M1_REQUIRE_STORES=1 fails
// instead of skipping, per house style -- 12 / 05 §7.5): PGDeviceKeys.PublicKey
// against the real m1_devices / m1_device_keys schema -- the live-key join,
// the superseded-key exclusion, and an unknown device.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

func TestIntegrationPGDeviceKeysResolvesLiveKeyOnly(t *testing.T) {
	dsn := os.Getenv("M1_TEST_PG_DSN")
	if dsn == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_TEST_PG_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_TEST_PG_DSN unset; skipping Postgres-backed test")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("cannot reach test Postgres: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	pool, err := pg.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("pg.Open (NOBYPASSRLS role required): %v", err)
	}
	t.Cleanup(pool.Close)
	db := pg.NewTenantDB(pool)

	tag := "devicekeys-it-" + uuid.NewString()[:8]
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var tenantID, deviceID uuid.UUID
	if err := pgx.BeginFunc(ctx, admin, func(tx pgx.Tx) error {
		var orgID uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO m1_organizations (name, primary_domain) VALUES ($1, $2) RETURNING id`,
			tag, tag+".example").Scan(&orgID); err != nil {
			return err
		}
		tenantID = uuid.New()
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO m1_tenants (id, org_id, name) VALUES ($1, $2, $3)`, tenantID, orgID, tag); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) VALUES ($1, 'linux', $2) RETURNING id`,
			tenantID, make([]byte, 32)).Scan(&deviceID); err != nil {
			return err
		}
		// A superseded key must never answer -- rotation, not revocation.
		// key_id is globally unique (uq_m1_dkeys_key_id), so it rides the same
		// per-run tag every other row here uses.
		if _, err := tx.Exec(ctx,
			`INSERT INTO m1_device_keys (tenant_id, device_id, key_id, public_key, superseded_at) VALUES ($1, $2, $3, $4, now())`,
			tenantID, deviceID, tag+"-old", []byte(oldPub)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO m1_device_keys (tenant_id, device_id, key_id, public_key) VALUES ($1, $2, $3, $4)`,
			tenantID, deviceID, tag+"-live", []byte(pub))
		return err
	}); err != nil {
		t.Fatal(err)
	}

	tid, err := querychoke.FromClaims(auth.Claims{TenantID: tenantID, DeviceID: deviceID})
	if err != nil {
		t.Fatal(err)
	}
	dk := ingest.NewPGDeviceKeys(db)

	got, ok, err := dk.PublicKey(ctx, tid, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !bytes.Equal(got, pub) {
		t.Fatalf("want the LIVE key (not the superseded one), got ok=%v key=%x want=%x", ok, got, pub)
	}

	if _, ok, err := dk.PublicKey(ctx, tid, uuid.New()); err != nil || ok {
		t.Fatalf("unknown device must answer ok=false err=nil, got ok=%v err=%v", ok, err)
	}
}
