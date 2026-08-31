// controld — one Go binary, five modules (05 §0.1). The main is deliberately
// boring: the estate's policy-engine shape with the boot refusals made
// explicit (05 §1.1). Order matters and is fixed; every Must* is an
// un-caught refusal, so a broken deploy crashloops instead of quietly
// degrading (05 §1.2 — there is no --skip-checks flag).
//
// Wired: config/server/auth/obs/pg + ingest + enroll (device identity, the
// production Ed25519 verifier replacing the dev HMAC seam — which survives
// only behind AUTH_DEV_MODE=1) + querychoke (template registry R4, the
// 08 §3.3 report/query surface, and the flag-gated internal rollup write —
// ADR-0010 is unsigned, so the write route defaults OFF). Boot steps not yet
// wired, each waiting on its module's own delivery row: the worker pool
// (dissolved into mark1_federation_worker, see internal/pg) and KMS
// DescribeKey (R5 — policydist/ADR-0004).
package main

import (
	"context"
	"crypto/rand"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/config"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/enroll"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/policydist"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke/chconn"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/server"
)

func main() {
	ctx := context.Background()

	cfg := config.MustLoad() // 1. env → struct; any missing required ⇒ Fatal (R1)
	obsCfg := obs.Config{ServiceName: "controld", MetricsPort: cfg.MetricsPort}

	pgApp := pg.MustOpenApp(ctx, cfg.AppDSN()) // 2. request-path pool (controld_app role, 05 §7.2)
	pg.MustAssertNoBypassRLS(ctx, pgApp)       // 3. boot refusal R2: app role with BYPASSRLS ⇒ Fatal

	ch := chconn.MustOpen(ctx, chconn.Options{ // 4. asserts async_insert=1 + wait_for_async_insert=1 (R3)
		Addr:     cfg.CHAddr,
		Database: cfg.CHDatabase,
		Username: "m1p_ingest", // 07: exactly two runtime CH users; ingest's is fixed
		Password: cfg.CHIngestPassword,
	})

	// The SSE-KMS escape hatch is config-gated to AUTH_DEV_MODE=1 (R1 refuses
	// it anywhere else): the dev/compose MinIO has no KMS and rejects the
	// SSE-KMS headers, which would turn every landing PUT — and therefore every
	// ingest ack — into a 503 (05 §2.2's ack license is the landing).
	if cfg.S3DisableSSEKMS {
		log.Printf("WARNING: S3_DISABLE_SSEKMS=1 — landing objects are NOT SSE-KMS encrypted; dev MinIO only, NEVER production (05 §2.2)")
	}
	store := s3land.MustOpen(ctx, s3land.Options{ // 5. HeadBucket + per-tenant-KMS deny probe (R6)
		Bucket:         cfg.IngestBucket,
		Endpoint:       cfg.S3Endpoint,
		KMSAliasPrefix: cfg.KMSTenantKeyAliasPrefix,
		DisableSSEKMS:  cfg.S3DisableSSEKMS,
	})

	// 6. (KMS DescribeKey R5) still deferred: policydist derives its six
	//    section keys from a local seed rather than holding KMS handles, so
	//    there is no DescribeKey to assert yet. See policydist/doc.go for the
	//    seam and the upgrade path.

	// 7. Boot refusal R4 (05 §1.2): every query template validated — a
	// tenant-less template must never be registerable, even transiently.
	tmpl := querychoke.MustLoadTemplates()
	// querychoke's read principal (m1p_query, SELECT-only; 07: exactly two
	// runtime CH users). The write carve-outs ride the ingest principal's
	// handle opened above — both credentials live only inside querychoke's
	// subtree (05 §6.1 visibility layer).
	chQuery := chconn.MustOpenQuery(ctx, chconn.Options{
		Addr:     cfg.CHAddr,
		Database: cfg.CHDatabase,
		Username: "m1p_query",
		Password: cfg.CHQueryPassword,
	})
	// The offboarding-deletion principal (07 §"deletion path"): the DELETE
	// carve-out must NOT ride m1p_ingest — INSERT-only, ACCESS_DENIED on a
	// DELETE. Optional until the offboarding job wave lands a caller; nil ⇒
	// querychoke refuses the template loudly at run time.
	var chOffboard *chconn.Conn
	if cfg.CHOffboardPassword != "" {
		var err error
		if chOffboard, err = chconn.OpenOffboard(ctx, chconn.Options{
			Addr:     cfg.CHAddr,
			Database: cfg.CHDatabase,
			Username: "m1p_offboard",
			Password: cfg.CHOffboardPassword,
		}); err != nil {
			log.Fatalf("chconn: boot refusal (05 §1.2): %v", err)
		}
	}
	if cfg.RollupWriteEnabled {
		log.Printf("WARNING: QUERYCHOKE_ROLLUP_WRITE=1 — the internal tvo_rollup_tenant_day write route is ARMED; ADR-0010 is unsigned, test/dev lanes only, NEVER production")
	}

	tenantDB := pg.NewTenantDB(pgApp)
	proj := chproj.New(ch, 16, 1000) // 05 §8.1: projection pool

	// The server CHAIN key (m1_002; distinct from the device-token signer —
	// the 05 §4.5 key-class split). Same dev-mode-only ephemeral escape hatch
	// as the token seed: an ephemeral chain key means receipts die
	// unverifiable with the process, tolerable only in a throwaway stack.
	chainSeed := cfg.ServerChainSeed
	if chainSeed == nil {
		chainSeed = make([]byte, 32)
		if _, err := rand.Read(chainSeed); err != nil {
			log.Fatalf("cannot generate ephemeral chain seed: %v", err)
		}
		log.Printf("WARNING: SERVER_CHAIN_ED25519_SEED unset — EPHEMERAL server chain key; every receipt countersigned by this process becomes unverifiable at restart (dev mode only)")
	}
	chainSigner, err := receipts.NewSigner(chainSeed)
	if err != nil {
		log.Fatalf("receipts: boot refusal (05 §1.2 R1): %v", err)
	}
	// Publish the key BEFORE the first countersignature: m1_receipts FKs
	// server_key_id, and an unpublished key is one nobody can verify (m1_002).
	if err := receipts.RegisterServerKey(ctx, pgApp, chainSigner); err != nil {
		log.Fatalf("receipts: cannot publish server chain key (boot refusal, m1_002): %v", err)
	}
	chainStore := receipts.NewStore(tenantDB, chainSigner)

	// Stage-11 security seam: chain refusals that are tampering-shaped land in
	// the ledger as GuardDecision-class rows via the projector, same posture
	// as ingest's M1E-8003 recorder.
	sfxSecurity := func(tenant, device, event uuid.UUID, detail string, at time.Time) {
		log.Printf("SECURITY sidefx: tenant=%s device=%s event=%s: %s", tenant, device, event, detail)
		proj.Enqueue([][]any{chproj.SecurityEventRow(tenant, device, event, detail, at)}, at)
	}
	sfx := sidefx.New(tenantDB, chainStore, sfxSecurity, 16, 1000) // 05 §8.1: same worker tier

	// One binary, one verifier, one revocation posture (05 §0.1): the
	// production Ed25519 verifier with the ≤60 s fail-closed cache (05 §3.3-
	// 3.4) is the DEFAULT. The dev HMAC seam survives only behind the
	// explicit flag — and even then the production verifier stays first in
	// line so enroll-minted tokens keep working in dev stacks.
	revocations := enroll.NewRevocationCache(tenantDB, cfg.RevocationCacheMaxAge)
	signingSeed := cfg.TokenSigningSeed
	if signingSeed == nil {
		// Only reachable under AUTH_DEV_MODE=1 (config R1 refuses otherwise):
		// an ephemeral key keeps enroll functional in throwaway dev stacks,
		// at the cost of tokens dying with the process.
		signingSeed = make([]byte, 32)
		if _, err := rand.Read(signingSeed); err != nil {
			log.Fatalf("cannot generate ephemeral signing seed: %v", err)
		}
		log.Printf("WARNING: AUTH_TOKEN_ED25519_SEED unset — EPHEMERAL device-token signing key; every issued token dies with this process (dev mode only)")
	}
	signer, err := auth.NewSigner(signingSeed)
	if err != nil {
		log.Fatalf("auth: boot refusal (05 §1.2 R1): %v", err) // bad seed = no verifier at all
	}
	var verifier auth.Verifier = auth.NewEd25519Verifier(signer.Public(), revocations)
	if cfg.AuthDevMode {
		log.Printf("WARNING: AUTH_DEV_MODE=1 — dev HMAC token verifier ACTIVE alongside the production verifier; NEVER run production traffic with this flag")
		// The dev leg shares the SAME revocation cache as the production leg:
		// one revocation posture per binary (05 §0.1) — a hand-minted dev token
		// for a revoked device must die exactly like an enroll-minted one.
		verifier = auth.Multi(verifier,
			auth.NewHMACVerifier([]byte(cfg.DevTokenHMACKey), revocations))
	}

	// The bundle section ring (05 §4.5). Absent seed ⇒ nil ring ⇒ this process
	// serves bundles and takes ACKs but refuses to publish; publication has no
	// public route (05 §4.1), so nothing on the request path degrades. NOT an
	// ephemeral fallback like the two seeds above: an ephemeral bundle key
	// would publish signed policy that every edge rejects after the next
	// deploy, which is worse than not publishing.
	var bundleRing *policydist.Keyring
	if cfg.BundleSectionSeed != nil {
		bundleRing, err = policydist.DeriveKeyring(cfg.BundleSectionSeed)
		if err != nil {
			log.Fatalf("policydist: boot refusal (05 §1.2 R1): %v", err)
		}
	} else {
		log.Printf("WARNING: BUNDLE_SECTION_ED25519_SEED unset — policydist SERVES and ACKs but cannot publish bundles")
	}
	// The tlog head signer is the server CHAIN key: 05 §4.4 requires the
	// log key class (specifically NOT a bundle section key), and this is that
	// class. Domain prefixes keep a receipt countersignature and a log-head
	// signature non-interchangeable.
	policy := policydist.NewModule(policydist.ModuleDeps{
		Store:    policydist.NewStore(tenantDB, chainStore, bundleRing, chainSigner),
		PG:       tenantDB,
		Verifier: verifier,
		ObsCfg:   obsCfg,
	})

	srv := server.New(cfg.Port, cfg.DrainTimeout)
	srv.Register(ingest.New(ingest.Deps{ // 8. each module contributes routes + readiness
		Verifier: verifier,
		ObsCfg:   obsCfg,
		PG:       tenantDB,
		Store:    store,
		Proj:     proj,
		Sidefx:   sfx,
	}), enroll.New(enroll.Deps{
		DB:            tenantDB,
		PG:            tenantDB,
		Signer:        signer,
		Verifier:      verifier,
		ObsCfg:        obsCfg,
		Cache:         revocations,
		PublicBaseURL: cfg.PublicBaseURL,
		ServerMinEdge: cfg.ServerMinEdge,
	}), receipts.NewModule(receipts.ModuleDeps{ // 08 §3.4 retrieval + verifier food
		DB:       tenantDB,
		PG:       tenantDB,
		Verifier: verifier,
		ObsCfg:   obsCfg,
	}), policy, querychoke.New(querychoke.Deps{ // 08 §3.3 report/query chokepoint
		Registry:           tmpl,
		Runner:             querychoke.NewRunner(chQuery, ch, chOffboard),
		Verifier:           verifier,
		ObsCfg:             obsCfg,
		RollupWriteEnabled: cfg.RollupWriteEnabled,
		IntelServiceToken:  cfg.IntelServiceToken,
	}))

	// The hourly witness-head job (m1_003; 05 §4.4). Runs only when a
	// destination is configured: a dev stack without a witness bucket is
	// honest about having no external anchor, and prod alerting owns the gap.
	witnessCtx, stopWitness := context.WithCancel(ctx)
	defer stopWitness()
	if cfg.WitnessBucket != "" {
		pub, err := receipts.NewS3Publisher(ctx, receipts.S3PublisherOptions{
			Bucket:   cfg.WitnessBucket,
			Endpoint: cfg.S3Endpoint,
			Retain:   cfg.WitnessRetain,
		})
		if err != nil {
			log.Fatalf("receipts: witness publisher boot refusal (05 §1.2): %v", err)
		}
		tenants := make([]uuid.UUID, 0, len(cfg.WitnessTenants))
		for _, s := range cfg.WitnessTenants {
			id, err := uuid.Parse(s)
			if err != nil {
				log.Fatalf("config: WITNESS_TENANTS entry %q is not a uuid (boot refusal R1): %v", s, err)
			}
			tenants = append(tenants, id)
		}
		job := receipts.NewWitnessJob(tenantDB, chainSigner, pub, receipts.StaticTenants(tenants), time.Hour)
		go job.Run(witnessCtx)
	} else {
		log.Printf("receipts: WITNESS_BUCKET unset — hourly witness job NOT running; chain heads have no external anchor (m1_003)")
	}

	// 9. /metrics /healthz on MetricsPort (pod-annotation scrape, 05 §1.7);
	// /readyz mirrored there for the same scraper.
	obsCfg.StartMetricsServer(map[string]http.Handler{"/readyz": srv.ReadyHandler()})

	// 10. serve; block on SIGTERM → 05 §1.5 drain.
	err = srv.Run(ctx)

	// Drain step 4–5 (05 §1.5): stop background workers at their iteration
	// boundary, close pools, exit.
	stopWitness()
	proj.Close()
	sfx.Close()
	_ = chQuery.Close()
	_ = ch.Close()
	pgApp.Close()
	if err != nil {
		panic(err)
	}
}
