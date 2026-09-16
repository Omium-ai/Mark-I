//go:build integration

package receipts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"encoding/hex"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

func appendServerRecord(t *testing.T, h *harness, store *receipts.Store, tenant querychoke.TenantID) receipts.Appended {
	t.Helper()
	var out receipts.Appended
	err := h.db.WithTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		var err error
		out, err = store.AppendServerRecordTx(context.Background(), tx, tenant, receipts.ServerRecord{
			RecordType: "noise_certificate", SubjectID: v7(t), IssuedAt: time.Now(),
			Fields: map[string]any{"cert": "x"},
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func chainKeys(t *testing.T, h *harness, tenant querychoke.TenantID) (types, keys []string) {
	t.Helper()
	rows, err := h.admin.Query(context.Background(),
		`SELECT record_type, server_key_id FROM m1_receipts WHERE tenant_id = $1 ORDER BY seq`, tenant.UUID())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var ty, k string
		if err := rows.Scan(&ty, &k); err != nil {
			t.Fatal(err)
		}
		types, keys = append(types, ty), append(keys, k)
	}
	return types, keys
}

// ADR-0004 on live chains: the successor takes over each tenant's chain
// through ONE key_rotation record signed by the retiring key, the customer's
// verifier follows it offline, and a chain whose hand-over lost its
// successor_key_id is the named defect.
func TestIntegrationServerChainKeyRotation(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	// Two receipts under the original key on tenant A; tenant B stays empty.
	appendServerRecord(t, h, h.store, h.tenantA)
	appendServerRecord(t, h, h.store, h.tenantA)

	successor, err := receipts.NewSigner(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.RegisterSuccessorKey(ctx, h.pool, h.chainKey, successor); err != nil {
		t.Fatalf("RegisterSuccessorKey: %v", err)
	}
	rotated := receipts.NewStore(h.db, successor).WithRetiring(h.chainKey)

	// Server-record path: the crossover rides inside the caller's tx.
	appendServerRecord(t, h, rotated, h.tenantA)
	types, keys := chainKeys(t, h, h.tenantA)
	if strings.Join(types, ",") != "noise_certificate,noise_certificate,key_rotation,noise_certificate" {
		t.Fatalf("tenant A record types %v", types)
	}
	if keys[2] != h.chainKey.KeyID() || keys[3] != successor.KeyID() {
		t.Fatalf("tenant A keys %v", keys)
	}
	// Idempotent: the head is already under the successor.
	appendServerRecord(t, h, rotated, h.tenantA)
	if types, _ := chainKeys(t, h, h.tenantA); len(types) != 5 || types[4] != "noise_certificate" {
		t.Fatalf("second append after crossover: %v", types)
	}
	// An empty chain crosses nothing.
	appendServerRecord(t, h, rotated, h.tenantB)
	if types, _ := chainKeys(t, h, h.tenantB); strings.Join(types, ",") != "noise_certificate" {
		t.Fatalf("tenant B (no history under the old key) got %v", types)
	}

	// Checkpoint path: the announcement commits on its own, so the device
	// that sealed against the pre-rotation head is refused ONCE and re-seals.
	var tid uuid.UUID
	if err := h.admin.QueryRow(ctx, `INSERT INTO m1_tenants (org_id, name)
		SELECT org_id, 'tenant-c' FROM m1_tenants LIMIT 1 RETURNING id`).Scan(&tid); err != nil {
		t.Fatal(err)
	}
	var did uuid.UUID
	if err := h.admin.QueryRow(ctx,
		`INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) VALUES ($1, 'linux', $2) RETURNING id`,
		tid, make([]byte, 32)).Scan(&did); err != nil {
		t.Fatal(err)
	}
	devKey, _ := receipts.NewSigner(bytes.Repeat([]byte{0x44}, 32))
	if _, err := h.admin.Exec(ctx,
		`INSERT INTO m1_device_keys (tenant_id, device_id, key_id, public_key) VALUES ($1, $2, $3, $4)`,
		tid, did, devKey.KeyID(), []byte(devKey.Public())); err != nil {
		t.Fatal(err)
	}
	tenantC, _ := querychoke.FromClaims(auth.Claims{TenantID: tid, DeviceID: did})
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	seal := h.sealCheckpoint(t, tenantC, did, devKey, leavesOf(v7(t)), at)
	if _, err := h.store.AppendCheckpoint(ctx, tenantC, seal, nil); err != nil {
		t.Fatal(err)
	}
	stale := h.sealCheckpoint(t, tenantC, did, devKey, leavesOf(v7(t)), at.Add(time.Second))
	_, err = rotated.AppendCheckpoint(ctx, tenantC, stale, nil)
	if r, ok := receipts.AsRefusal(err); !ok || r.Code != receipts.DefectBadSignature {
		t.Fatalf("stale seal across the rotation: want a bad_signature refusal (sealed against the pre-rotation head), got %v", err)
	}
	if types, _ := chainKeys(t, h, tenantC); strings.Join(types, ",") != "checkpoint,key_rotation" {
		t.Fatalf("announcement must survive the refusal: %v", types)
	}
	fresh := h.sealCheckpoint(t, tenantC, did, devKey, leavesOf(v7(t)), at.Add(2*time.Second))
	if _, err := rotated.AppendCheckpoint(ctx, tenantC, fresh, nil); err != nil {
		t.Fatalf("re-seal after crossover: %v", err)
	}
	if _, keys := chainKeys(t, h, tenantC); keys[2] != successor.KeyID() {
		t.Fatalf("tenant C keys %v", keys)
	}

	// The customer's verifier, on tenant A's export and the served keys.
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found; skipping verifier leg")
	}
	repoRoot, _ := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	build := exec.Command("cargo", "build", "--locked", "-p", "mark1-verifier")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cargo build: %v\n%s", err, out)
	}
	mux := http.NewServeMux()
	receipts.NewModule(receipts.ModuleDeps{
		DB: h.db, PG: h.db, Verifier: auth.NewHMACVerifier([]byte("rot-key"), auth.StaticRevocations{}),
		ObsCfg: obs.Config{ServiceName: "controld-rot"},
	}).RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	token := auth.Mint([]byte("rot-key"), h.tenantA.UUID(), h.deviceA, time.Hour)
	fetch := func(path string) []byte {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
		return body
	}
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.jsonl")
	export := fetch("/api/v1/receipts/export")
	keysJSON := fetch("/api/v1/receipts/keys")
	if !bytes.Contains(keysJSON, []byte(`"cross_sig":{"by_key_id":"`+h.chainKey.KeyID()+`"`)) {
		t.Fatalf("served keys carry no cross_sig by the retiring key:\n%s", keysJSON)
	}
	_ = os.WriteFile(chainPath, export, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "keys.json"), keysJSON, 0o600)
	run := func() (int, string) {
		cmd := exec.Command(filepath.Join(repoRoot, "target", "debug", "mark1-verifier"), "verify",
			"--chain", "chain.jsonl", "--keys", "keys.json", "--json")
		cmd.Dir = dir
		out, _ := cmd.CombinedOutput()
		return cmd.ProcessState.ExitCode(), string(out)
	}
	if code, out := run(); code != 0 {
		t.Fatalf("verifier rejected the rotated chain (exit %d):\n%s", code, out)
	}

	// Mutation: the rotation record loses its successor_key_id (re-signed by
	// the retiring key so hash and signatures hold; only the hand-over is
	// missing) -- the verifier must go red on exactly that.
	var lines []map[string]any
	for _, l := range bytes.Split(bytes.TrimSpace(export), []byte("\n")) {
		var row map[string]any
		if err := json.Unmarshal(l, &row); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, row)
	}
	rot := lines[2]
	payload, _ := receipts.DecodePayload([]byte(rot["payload"].(string)))
	fields := payload.(map[string]any)
	delete(fields, "successor_key_id")
	text, _ := receipts.CanonicalJSON(fields)
	input := append([]byte(receipts.DomainPrefix), text...)
	sig, _ := h.chainKey.Sign(input)
	hash, _ := receipts.ReceiptHash(fields)
	rot["payload"], rot["receipt_hash_hex"], rot["server_signature_hex"] = text, hexOf(hash[:]), hexOf(sig)
	// Re-link the successor's rows onto the re-hashed record so broken_link
	// cannot be the reason.
	prev := hexOf(hash[:])
	for _, row := range lines[3:] {
		p, _ := receipts.DecodePayload([]byte(row["payload"].(string)))
		f := p.(map[string]any)
		f["prev_receipt_hash"] = prev
		txt, _ := receipts.CanonicalJSON(f)
		in := append([]byte(receipts.DomainPrefix), txt...)
		s, _ := successor.Sign(in)
		hh, _ := receipts.ReceiptHash(f)
		row["payload"], row["receipt_hash_hex"], row["server_signature_hex"] = txt, hexOf(hh[:]), hexOf(s)
		prev = hexOf(hh[:])
	}
	var buf bytes.Buffer
	for _, row := range lines {
		b, _ := json.Marshal(row)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	_ = os.WriteFile(chainPath, buf.Bytes(), 0o600)
	code, out := run()
	if code != 5 || !strings.Contains(out, string(receipts.DefectRotationUnchained)) {
		t.Fatalf("dropped successor_key_id: want exit 5 naming rotation_unchained, got %d:\n%s", code, out)
	}
	if n := len(regexp.MustCompile(`"kind"`).FindAllString(out, -1)); n != 1 {
		t.Fatalf("expected exactly one defect, got %d:\n%s", n, out)
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }
