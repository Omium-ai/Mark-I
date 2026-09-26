// The receipt retrieval surface (08 §3.4, interface class I-3/I-5) plus the
// offline verifier's food. Payloads are returned as the exact canonical text
// that was signed — text, never re-serialized JSON (the vendored canonical.py
// discipline) — so the verifier checks bytes, not interpretations.
//
// Routes:
//   GET /api/v1/receipts                  08 §3.4's list + chain_head
//   GET /api/v1/receipts/export           JSONL, one ExportRow per line — the
//                                         exact shape rust/verifier loads
//                                         (lib.rs ExportRow; 08 §7.7 "--from
//                                         <export.jsonl>")
//   GET /api/v1/receipts/keys             the key-manifest snapshot the
//                                         verifier's --keys flag reads
//                                         (KeysFile: role split = which list)
//   GET /api/v1/receipts/witness          the witness snapshot for --witness
//                                         (WitnessFile: {heads: [...]})
// All device-or-operator authenticated; tenancy from verified claims only.
// The export/keys/witness routes are ADDITIVE surface (08 §10.2's response
// discipline): §3.4 names the list endpoints, 08 §7.7 names the files the CLI
// feeds the verifier, and these three are the seam between them. The public
// unauthenticated key surface (08 §3.5 /.well-known/mark1-keys) belongs to
// policydist's key-ceremony machinery and is not served here — device keys
// are tenant-scoped (m1_001) and MUST NOT ride an unauthenticated path
// ("nothing tenant-identifying", 08 §3.5).

package receipts

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/server"
)

// PGReady is the readiness slice of pg.TenantDB.
type PGReady interface {
	Ready(ctx context.Context) error
}

type ModuleDeps struct {
	DB       DB
	PG       PGReady
	Verifier auth.Verifier
	ObsCfg   obs.Config
	// Store and IntelServiceToken serve the internal append route (append.go); an empty token verifies nothing, so the surface is absent, never open.
	Store             *Store
	IntelServiceToken string
	// Viewers narrows the listed rows to a team member's devices (15-teams); head, export, keys and witness stay tenant-wide. nil lists tenant-wide.
	Viewers querychoke.Viewers
}

type Module struct {
	db           DB
	pgReady      PGReady
	verifier     auth.Verifier
	obsCfg       obs.Config
	store        *Store
	serviceToken string
	viewers      querychoke.Viewers
}

func NewModule(d ModuleDeps) *Module {
	return &Module{db: d.DB, pgReady: d.PG, verifier: d.Verifier, obsCfg: d.ObsCfg, store: d.Store, serviceToken: d.IntelServiceToken, viewers: d.Viewers}
}

func (m *Module) Name() string { return "receipts" }

// Ready: Postgres ping — the chain is Postgres and nothing else (05 §1.4).
func (m *Module) Ready(ctx context.Context) error { return m.pgReady.Ready(ctx) }

func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	chain := server.Chain(m.verifier, m.obsCfg, nil)
	mux.Handle("GET /api/v1/receipts", chain(http.HandlerFunc(m.handleList)))
	mux.Handle("GET /api/v1/receipts/export", chain(http.HandlerFunc(m.handleExport)))
	mux.Handle("GET /api/v1/receipts/keys", chain(http.HandlerFunc(m.handleKeys)))
	mux.Handle("GET /api/v1/receipts/witness", chain(http.HandlerFunc(m.handleWitness)))
	mux.Handle("POST /internal/v1/receipts/append", m.obsCfg.HTTPMiddleware(nil)(http.HandlerFunc(m.handleAppend)))
}

// row is one m1_receipts read, column-shaped.
type row struct {
	Seq         int64
	Payload     string
	PrevHash    []byte
	ReceiptHash []byte
	RecordType  string
	DeviceKeyID *string
	DeviceSig   []byte
	ServerKeyID string
	ServerSig   []byte
}

// chainHead is the head row as the edge must see it. All THREE numbers travel
// together because all three are inputs to a signature: the device sealer
// rebuilds the checkpoint payload at seq+1 with prev_receipt_hash = hash and
// checkpoint_seq = checkpoint_seq+1, and AppendCheckpoint verifies its
// signature over exactly that reconstruction (store.go:196-217). A head that
// states two of the three is a head no device can seal against.
type chainHead struct {
	Seq           int64
	Hash          [32]byte
	CheckpointSeq int64
}

// readChain reads a page of the chain and its head; with viewer.Team only rows a viewer's device signed are paged (server acts carry no device and are left out), the head is always the tenant's.
func (m *Module) readChain(ctx context.Context, tenant querychoke.TenantID, sinceSeq int64, limit int, viewer querychoke.Viewer) ([]row, chainHead, error) {
	var rows []row
	head := chainHead{Hash: GenesisHash}
	err := m.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		q, args := `
			SELECT seq, payload, prev_receipt_hash, receipt_hash, record_type,
			       device_key_id, device_signature, server_key_id, server_signature
			  FROM m1_receipts WHERE seq > $1 ORDER BY seq LIMIT $2`, []any{sinceSeq, limit}
		if viewer.Team {
			q, args = `
			SELECT seq, payload, prev_receipt_hash, receipt_hash, record_type,
			       device_key_id, device_signature, server_key_id, server_signature
			  FROM m1_receipts WHERE seq > $1
			   AND device_key_id IN (SELECT key_id FROM m1_device_keys WHERE device_id = ANY($3::uuid[]))
			 ORDER BY seq LIMIT $2`, append(args, viewer.Devices)
		}
		res, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer res.Close()
		for res.Next() {
			var r row
			if err := res.Scan(&r.Seq, &r.Payload, &r.PrevHash, &r.ReceiptHash, &r.RecordType,
				&r.DeviceKeyID, &r.DeviceSig, &r.ServerKeyID, &r.ServerSig); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		if err := res.Err(); err != nil {
			return err
		}
		var h []byte
		scanErr := tx.QueryRow(ctx,
			`SELECT seq, head_hash, checkpoint_seq FROM m1_receipt_chain_head WHERE tenant_id = $1`,
			tenant.UUID()).Scan(&head.Seq, &h, &head.CheckpointSeq)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// A tenant that has never sealed has no head row; the genesis
			// zeros this returns ARE its head, and a sealer reading them
			// correctly claims seq 1 / checkpoint_seq 1.
			return nil
		}
		if scanErr == nil {
			head.Hash = [32]byte(h)
		}
		return scanErr
	})
	return rows, head, err
}

// tenantOf stamps tenancy from the verified claims — the ONLY identity source
// (08 §3: "a tenant identifier in a path or body is never trusted").
func tenantOf(w http.ResponseWriter, r *http.Request) (querychoke.TenantID, bool) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"M1E-9000","message":"auth middleware did not run"}}`, http.StatusInternalServerError)
		return querychoke.TenantID{}, false
	}
	tenant, err := querychoke.FromClaims(claims)
	if err != nil {
		http.Error(w, `{"error":{"code":"M1E-9000","message":"verified claims carry no tenant"}}`, http.StatusInternalServerError)
		return querychoke.TenantID{}, false
	}
	return tenant, true
}

func pageParams(r *http.Request) (sinceSeq int64, limit int) {
	sinceSeq, _ = strconv.ParseInt(r.URL.Query().Get("since_seq"), 10, 64)
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 500 // 08 §3.4's example page
	}
	if limit > 5000 {
		limit = 5000 // a full-chain export pages; one response never streams a year
	}
	return sinceSeq, limit
}

// kindOf maps record_type to 08 §3.4's kind vocabulary (the one divergence is
// noise_certificate → "noise_cert", the doc's own spelling).
func kindOf(recordType string) string {
	if recordType == "noise_certificate" {
		return "noise_cert"
	}
	return recordType
}

// handleList is GET /api/v1/receipts — the amended 08 §3.4 shape (D-O
// ruling): key_id names the DEVICE origin key (it rides inside the signed
// payload; absent on server-only records), server_key_id the countersigning
// server key — a per-receipt row fact the verifier resolves across rotations,
// because one key_id cannot name two keys. device_key_id stays as the
// pre-ruling alias for consumers that shipped against it.
func (m *Module) handleList(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(w, r)
	if !ok {
		return
	}
	sinceSeq, limit := pageParams(r)
	viewer, err := querychoke.ViewerFrom(r.Context(), m.viewers)
	if err != nil {
		http.Error(w, `{"error":{"code":"M1E-9500","message":"viewer lookup failed"}}`, http.StatusServiceUnavailable)
		return
	}
	rows, head, err := m.readChain(r.Context(), tenant, sinceSeq, limit, viewer)
	if err != nil {
		http.Error(w, `{"error":{"code":"M1E-9500","message":"chain read failed"}}`, http.StatusServiceUnavailable)
		return
	}
	type listReceipt struct {
		ReceiptSeq  int64   `json:"receipt_seq"`
		Kind        string  `json:"kind"`
		Payload     string  `json:"payload"`
		DeviceSig   *string `json:"device_sig"`
		ServerSig   string  `json:"server_sig"`
		KeyID       *string `json:"key_id,omitempty"`
		ServerKeyID string  `json:"server_key_id"`
		DeviceKeyID *string `json:"device_key_id,omitempty"`
		PrevHash    string  `json:"prev_hash"`
		ThisHash    string  `json:"this_hash"`
	}
	// checkpoint_seq was added additively on the same reasoning that added
	// server_key_id (D-O): a field arrives when a consumer exists to need it.
	// The edge checkpoint sealer is that consumer — see chainHead above.
	out := struct {
		Receipts  []listReceipt `json:"receipts"`
		ChainHead struct {
			Seq           int64  `json:"seq"`
			Hash          string `json:"hash"`
			CheckpointSeq int64  `json:"checkpoint_seq"`
		} `json:"chain_head"`
	}{Receipts: []listReceipt{}}
	for _, r := range rows {
		lr := listReceipt{
			ReceiptSeq: r.Seq, Kind: kindOf(r.RecordType), Payload: r.Payload,
			ServerSig: hex.EncodeToString(r.ServerSig), ServerKeyID: r.ServerKeyID,
			KeyID: r.DeviceKeyID, DeviceKeyID: r.DeviceKeyID,
			PrevHash: hex.EncodeToString(r.PrevHash), ThisHash: hex.EncodeToString(r.ReceiptHash),
		}
		if len(r.DeviceSig) > 0 {
			s := hex.EncodeToString(r.DeviceSig)
			lr.DeviceSig = &s
		}
		out.Receipts = append(out.Receipts, lr)
	}
	out.ChainHead.Seq = head.Seq
	out.ChainHead.Hash = hex.EncodeToString(head.Hash[:])
	out.ChainHead.CheckpointSeq = head.CheckpointSeq
	writeJSON(w, out)
}

// handleExport is the verifier-food form: JSONL, one rust/verifier ExportRow
// per line, byte-loadable by `mark1-verifier verify --chain <file>` with no
// translation layer in between — the round-trip the offline-verification
// product depends on.
func (m *Module) handleExport(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(w, r)
	if !ok {
		return
	}
	sinceSeq, limit := pageParams(r)
	rows, _, err := m.readChain(r.Context(), tenant, sinceSeq, limit, querychoke.Viewer{}) // verifier food: the whole chain, or its prev-hash links cannot verify
	if err != nil {
		http.Error(w, `{"error":{"code":"M1E-9500","message":"chain read failed"}}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	for _, r := range rows {
		line := map[string]any{
			"seq":                  r.Seq,
			"payload":              r.Payload,
			"receipt_hash_hex":     hex.EncodeToString(r.ReceiptHash),
			"server_key_id":        r.ServerKeyID,
			"server_signature_hex": hex.EncodeToString(r.ServerSig),
		}
		if r.DeviceKeyID != nil {
			line["device_key_id"] = *r.DeviceKeyID
		}
		if len(r.DeviceSig) > 0 {
			line["device_signature_hex"] = hex.EncodeToString(r.DeviceSig)
		}
		if err := enc.Encode(line); err != nil {
			return // client went away mid-stream; nothing to repair
		}
	}
}

// handleKeys serves the rust/verifier KeysFile shape: the role split IS
// which list a key sits in (lib.rs load_keys — flattening the lists is the S1
// the vectors lock). Retired/superseded/revoked keys stay published: past
// receipts must remain verifiable forever (m1_002 §1, m1_001 §5).
func (m *Module) handleKeys(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(w, r)
	if !ok {
		return
	}
	type crossSig struct {
		ByKeyID      string `json:"by_key_id"`
		SignatureHex string `json:"signature_hex"`
	}
	type keyRecord struct {
		PubkeyHex string    `json:"pubkey_hex"`
		KeyID     string    `json:"key_id"`
		TenantID  string    `json:"tenant_id,omitempty"`
		CrossSig  *crossSig `json:"cross_sig,omitempty"`
	}
	out := struct {
		ServerChainKeys []keyRecord `json:"server_chain_keys"`
		DeviceKeys      []keyRecord `json:"device_keys"`
	}{ServerChainKeys: []keyRecord{}, DeviceKeys: []keyRecord{}}
	err := m.db.WithTenant(r.Context(), tenant, func(tx pgx.Tx) error {
		// m1_server_signing_keys is global (no RLS): every tenant's verifier
		// needs it (m1_002 §1).
		res, err := tx.Query(r.Context(),
			`SELECT key_id, public_key, cross_signed_by, cross_signature FROM m1_server_signing_keys ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer res.Close()
		for res.Next() {
			var id string
			var by *string
			var pub, sig []byte
			if err := res.Scan(&id, &pub, &by, &sig); err != nil {
				return err
			}
			rec := keyRecord{PubkeyHex: hex.EncodeToString(pub), KeyID: id}
			if by != nil {
				rec.CrossSig = &crossSig{ByKeyID: *by, SignatureHex: hex.EncodeToString(sig)}
			}
			out.ServerChainKeys = append(out.ServerChainKeys, rec)
		}
		if err := res.Err(); err != nil {
			return err
		}
		// m1_device_keys is RLS-scoped: only THIS tenant's device keys serve.
		res, err = tx.Query(r.Context(),
			`SELECT key_id, public_key FROM m1_device_keys ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer res.Close()
		for res.Next() {
			var id string
			var pub []byte
			if err := res.Scan(&id, &pub); err != nil {
				return err
			}
			out.DeviceKeys = append(out.DeviceKeys, keyRecord{PubkeyHex: hex.EncodeToString(pub), KeyID: id, TenantID: tenant.String()})
		}
		return res.Err()
	})
	if err != nil {
		http.Error(w, `{"error":{"code":"M1E-9500","message":"key read failed"}}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, out)
}

// handleWitness serves the rust/verifier WitnessFile shape from m1_003's
// rows. This is Omium's OWN record of what it published — the trust anchor is
// the external copy (m1_003 header); this route exists so the verifier can
// FIND those copies and so `--witness` has a local snapshot to run against.
func (m *Module) handleWitness(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(w, r)
	if !ok {
		return
	}
	type head struct {
		WitnessedSeq     int64  `json:"witnessed_seq"`
		WitnessedHashHex string `json:"witnessed_hash_hex"`
		WitnessedAt      string `json:"witnessed_at"`
		Statement        string `json:"statement"`
		ServerKeyID      string `json:"server_key_id"`
		SignatureHex     string `json:"signature_hex"`
		BucketURI        string `json:"object_bucket_uri,omitempty"`
		LogBackend       string `json:"log_backend,omitempty"`
	}
	out := struct {
		Heads []head `json:"heads"`
	}{Heads: []head{}}
	err := m.db.WithTenant(r.Context(), tenant, func(tx pgx.Tx) error {
		res, err := tx.Query(r.Context(), `
			SELECT witnessed_seq, witnessed_hash, witnessed_at, statement,
			       server_key_id, server_signature, object_bucket_uri, log_backend
			  FROM m1_witness_heads ORDER BY witnessed_at`)
		if err != nil {
			return err
		}
		defer res.Close()
		for res.Next() {
			var h head
			var hash, sig []byte
			var at time.Time
			var bucket, backend *string
			if err := res.Scan(&h.WitnessedSeq, &hash, &at, &h.Statement,
				&h.ServerKeyID, &sig, &bucket, &backend); err != nil {
				return err
			}
			h.WitnessedHashHex = hex.EncodeToString(hash)
			h.WitnessedAt = at.UTC().Format(time.RFC3339)
			h.SignatureHex = hex.EncodeToString(sig)
			if bucket != nil {
				h.BucketURI = *bucket
			}
			if backend != nil {
				h.LogBackend = *backend
			}
			out.Heads = append(out.Heads, h)
		}
		return res.Err()
	})
	if err != nil {
		http.Error(w, `{"error":{"code":"M1E-9500","message":"witness read failed"}}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, out)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
