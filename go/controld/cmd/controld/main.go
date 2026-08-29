// controld — one Go binary, five modules (05 §0.1). The main is deliberately
// boring: the estate's policy-engine shape with the boot refusals made
// explicit (05 §1.1). Order matters and is fixed; every Must* is an
// un-caught refusal, so a broken deploy crashloops instead of quietly
// degrading (05 §1.2 — there is no --skip-checks flag).
//
// C4 wiring: config/server/auth/obs/pg + ingest in full. Boot steps not yet
// wired, each waiting on its module's own delivery row: the worker pool
// (dissolved into mark1_federation_worker, see internal/pg), KMS DescribeKey
// (R5 — policydist/ADR-0004), and querychoke.MustLoadTemplates (R4 — WS-6).
package main

import (
	"context"
	"net/http"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/config"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke/chconn"
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

	store := s3land.MustOpen(ctx, s3land.Options{ // 5. HeadBucket + per-tenant-KMS deny probe (R6)
		Bucket:         cfg.IngestBucket,
		Endpoint:       cfg.S3Endpoint,
		KMSAliasPrefix: cfg.KMSTenantKeyAliasPrefix,
	})

	// 6.–7. (KMS DescribeKey R5, template validation R4) arrive with
	// policydist and querychoke in WS-6 — see the package doc.go stubs.

	tenantDB := pg.NewTenantDB(pgApp)
	proj := chproj.New(ch, 16, 1000)      // 05 §8.1: projection pool
	sfx := sidefx.New(tenantDB, 16, 1000) // 05 §8.1: same worker tier
	verifier := auth.NewHMACVerifier([]byte(cfg.DevTokenHMACKey), auth.StaticRevocations{})

	srv := server.New(cfg.Port, cfg.DrainTimeout)
	srv.Register(ingest.New(ingest.Deps{ // 8. each module contributes routes + readiness
		Verifier: verifier,
		ObsCfg:   obsCfg,
		PG:       tenantDB,
		Store:    store,
		Proj:     proj,
		Sidefx:   sfx,
	}))

	// 9. /metrics /healthz on MetricsPort (pod-annotation scrape, 05 §1.7);
	// /readyz mirrored there for the same scraper.
	obsCfg.StartMetricsServer(map[string]http.Handler{"/readyz": srv.ReadyHandler()})

	// 10. serve; block on SIGTERM → 05 §1.5 drain.
	err := srv.Run(ctx)

	// Drain step 4–5 (05 §1.5): stop background workers at their iteration
	// boundary, close pools, exit.
	proj.Close()
	sfx.Close()
	_ = ch.Close()
	pgApp.Close()
	if err != nil {
		panic(err)
	}
}
