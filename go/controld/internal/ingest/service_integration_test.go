//go:build integration

package ingest

// Stores-backed proof of the adjudicator→ingest seam: a service batch lands
// on real MinIO under the ServiceDevice stamp and projects into real
// ClickHouse through the same pipeline as the device batch before it, and
// the ledger's own readers (the querychoke templates over m1_ch_001 +
// m1_ch_002) then prefer the re-entered stage per task. Gate: the three
// store vars (justfile / 12 §11.4); M1_REQUIRE_STORES=1 fails instead of
// skipping.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke/chconn"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func svcRequire(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatalf("%s required (M1_REQUIRE_STORES=1) but unset", name)
		}
		t.Skipf("%s unset; skipping stores-backed test", name)
	}
	return v
}

func svcCHSQL(t *testing.T, dsn, sql string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	user, pass := "default", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	u.User = nil
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(sql))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-ClickHouse-User", user)
	if pass != "" {
		req.Header.Set("X-ClickHouse-Key", pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("ClickHouse over %s: %v", dsn, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ClickHouse %d for %q: %s", resp.StatusCode, sql, body)
	}
	return strings.TrimSpace(string(body))
}

// svcCH builds a scratch database with the REAL m1_ch_001 + m1_ch_002 DDL and
// opens the projector's write connection and the choke's read connection.
func svcCH(t *testing.T) (*chconn.Conn, chconn.Options, string) {
	t.Helper()
	dsn := svcRequire(t, "M1_TEST_CH_DSN")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	user, pass := "default", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	addr := net.JoinHostPort(u.Hostname(), svcCHSQL(t, dsn, "SELECT getServerPort('tcp_port')"))
	scratch := fmt.Sprintf("c4_svc_%d", time.Now().UnixNano())
	svcCHSQL(t, dsn, "CREATE DATABASE "+scratch)
	t.Cleanup(func() { svcCHSQL(t, dsn, "DROP DATABASE IF EXISTS "+scratch) })
	for _, file := range []string{"m1_ch_001_events.sql", "m1_ch_002_rollups.sql"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "migrations", file))
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, line := range strings.Split(string(raw), "\n") {
			if i := strings.Index(line, "--"); i >= 0 {
				line = line[:i]
			}
			b.WriteString(line + "\n")
		}
		for _, stmt := range strings.Split(b.String(), ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			stmt = strings.ReplaceAll(stmt, "mark1.", scratch+".")
			stmt = strings.ReplaceAll(stmt, "EXISTS mark1", "EXISTS "+scratch)
			svcCHSQL(t, dsn, stmt)
		}
	}
	ctx := context.Background()
	opts := chconn.Options{Addr: addr, Database: scratch, Username: user, Password: pass}
	write, err := chconn.Open(ctx, opts)
	if err != nil {
		t.Fatalf("chconn.Open (R3): %v", err)
	}
	t.Cleanup(func() { _ = write.Close() })
	return write, opts, svcScratchDSN(t, dsn, scratch)
}

func svcScratchDSN(t *testing.T, dsn, scratch string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("database", scratch)
	u.RawQuery = q.Encode()
	return u.String()
}

func svcS3(t *testing.T) *s3land.Client {
	t.Helper()
	c, _, _ := svcS3Direct(t)
	return c
}

// svcS3Direct also hands back the raw client + bucket for tests that inspect or disturb objects behind the seam.
func svcS3Direct(t *testing.T) (*s3land.Client, *s3.Client, string) {
	t.Helper()
	endpoint := svcRequire(t, "M1_TEST_S3_ENDPOINT")
	ak, sk := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")
	if ak == "" {
		ak, sk = "minioadmin", "minioadmin"
	}
	t.Setenv("AWS_ACCESS_KEY_ID", ak)
	t.Setenv("AWS_SECRET_ACCESS_KEY", sk)
	t.Setenv("AWS_REGION", "us-east-1")
	ctx := context.Background()
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	direct := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
	bucket := "m1-svc-" + uuid.NewString()
	if _, err := direct.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		pg := s3.NewListObjectsV2Paginator(direct, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
		for pg.HasMorePages() {
			page, err := pg.NextPage(bg)
			if err != nil {
				break
			}
			for _, o := range page.Contents {
				_, _ = direct.DeleteObject(bg, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: o.Key})
			}
		}
		_, _ = direct.DeleteBucket(bg, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	})
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject",
	  "Resource":"arn:aws:s3:::` + bucket + `/t/*",
	  "Condition":{"StringNotLike":{"s3:x-amz-server-side-encryption-aws-kms-key-id":"*alias/mark1-tenant-*"}}}]}`
	if _, err := direct.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: aws.String(policy)}); err != nil {
		t.Fatalf("bucket policy: %v", err)
	}
	c, err := s3land.Open(ctx, s3land.Options{Bucket: bucket, Endpoint: endpoint, KMSAliasPrefix: "alias/mark1-tenant-", DisableSSEKMS: true})
	if err != nil {
		t.Fatalf("s3land.Open: %v", err)
	}
	return c, direct, bucket
}

func svcPost(t *testing.T, srvURL, path, bearer string, headers map[string]string, batchID uuid.UUID, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srvURL+path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/x-m1p-protobuf")
	req.Header.Set("Content-Encoding", "zstd")
	req.Header.Set("M1P-Schema", "m1p.v1")
	req.Header.Set("M1P-Batch-Id", batchID.String())
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestIntegrationServiceVerdictReentersTheLedger(t *testing.T) {
	store := svcS3(t)
	write, chOpts, readDSN := svcCH(t)
	ctx := context.Background()
	proj := chproj.New(write, 2, 256)
	sfx := sidefx.New(&fakeDB{}, nil, nil, 1, 256)
	sfx.SetLeafStore(sidefx.NewMemoryLeafStore())
	t.Cleanup(sfx.Close)
	mux := http.NewServeMux()
	New(Deps{
		Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-svc-it"},
		PG:       fakeReady{}, Store: store, Proj: proj, Sidefx: sfx, PoolSize: 4,
		IntelServiceToken: testServiceToken,
	}).RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	tenant, device := uuid.New(), uuid.New()
	deviceToken := auth.Mint(testKey, tenant, device, time.Hour)
	session, task := mustV7(t), mustV7(t)
	day := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	windowClose := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)

	// The edge's own story for the task: a Usage and the PROVISIONAL fusion.
	usage := usageEvent(t, session, 1)
	usage.TaskId, usage.SessionEpoch, usage.OccurredAt = task[:], 3, timestamppb.New(day)
	prov := verdictEvent(t, session, 2)
	prov.TaskId, prov.SessionEpoch, prov.OccurredAt = task[:], 3, timestamppb.New(day.Add(time.Minute))
	deviceBatch, deviceBatchID := testBatch(t, usage, prov)
	if code, body := svcPost(t, srv.URL, "/m1p/v1/ingest", deviceToken, nil, deviceBatchID, encodeBatch(t, deviceBatch)); code != http.StatusOK {
		t.Fatalf("device batch: %d %s", code, body)
	}

	// The adjudicator's re-entry: REVISED (it overturned satisfied), filed at
	// the window close under the sentinel epoch so it sorts after every edge event.
	revisedID := mustV7(t)
	revised := &m1pv1.Event{
		EventId: revisedID[:], Seq: uint64(windowClose.UnixMilli()), SessionId: session[:], TaskId: task[:],
		SessionEpoch: 0xFFFFFFFF, OccurredAt: timestamppb.New(windowClose),
		Body: &m1pv1.Event_VerdictEvent{VerdictEvent: &m1pv1.VerdictEvent{
			Stage: m1pv1.VerdictStage_VERDICT_STAGE_REVISED, Verdict: m1pv1.Verdict_VERDICT_VIOLATED,
			Posterior: []float64{0.12, 0.83, 0.03, 0.02}, NoiseCertId: uuid.NewString(), VoteCount: 3,
			Certification: m1pv1.CertificationStatus_CERTIFICATION_STATUS_BOOTSTRAPPING,
		}},
	}
	serviceBatch, serviceBatchID := testBatch(t, revised)
	serviceBatch.SessionId, serviceBatch.AdvisoryTenantId = session[:], tenant[:]
	serviceBatch.Sdk = &m1pv1.SdkInfo{Name: "adjudicator-svc", Version: "it"}
	serviceBytes := encodeBatch(t, serviceBatch)
	svcHeaders := map[string]string{TenantHeader: tenant.String()}

	reg, err := querychoke.LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	runner, closeRead, err := querychoke.OpenRunner(context.Background(), chOpts, write)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeRead() })
	run := func(name string, params querychoke.Params) []map[string]any {
		t.Helper()
		tpl, err := reg.Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		cred, _ := querychoke.VerifyServiceCredential(testServiceToken, testServiceToken)
		tid, err := querychoke.FromServiceJob(cred, tenant)
		if err != nil {
			t.Fatal(err)
		}
		q, err := querychoke.Build(tid, tpl, params)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := runner.Run(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return rows.Rows
	}
	window := querychoke.Params{"from": "2026-08-28", "to": "2026-08-30"}
	closed := querychoke.Params{"from": "2026-08-28", "to": "2026-08-29"}

	// Positive control before the seam fires: the task is provisional-only —
	// no stage-final row for gold, the attempt's verdict is the edge's.
	svcAwaitEvent(t, readDSN, tenant, uuid.UUID(prov.EventId))
	if rows := run("gold_vs_verdict", closed); len(rows) != 0 {
		t.Fatalf("provisional-only task must have no stage-final row: %v", rows)
	}
	if rows := run("tvo_task_window", window); len(rows) != 1 || fmt.Sprint(rows[0]["fused_verdict"]) != "satisfied" || fmt.Sprint(rows[0]["verdict_stage"]) != "provisional" {
		t.Fatalf("before re-entry: %v", rows)
	}

	code, body := svcPost(t, srv.URL, "/internal/v1/ingest/service", testServiceToken, svcHeaders, serviceBatchID, serviceBytes)
	if code != http.StatusOK || !strings.Contains(body, `"accepted":1`) {
		t.Fatalf("service batch: %d %s", code, body)
	}
	// Real S3: the object sits under the tenant's ingest prefix for the window-close day
	// and carries the sentinel as its device stamp — the replay path's only identity.
	keys, err := store.List(ctx, s3land.IngestPrefix(tenant, time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	var landed int
	for _, k := range keys {
		if !strings.HasSuffix(k, serviceBatchID.String()+".m1p.zst") {
			continue
		}
		landed++
		got, dev, err := store.Get(ctx, k)
		if err != nil || string(got) != string(serviceBytes) || dev != ServiceDevice {
			t.Fatalf("landing object %s: err=%v bytes_equal=%v device=%s", k, err, string(got) == string(serviceBytes), dev)
		}
	}
	if landed != 1 {
		t.Fatalf("service batch landed %d times under %v", landed, keys)
	}

	svcAwaitEvent(t, readDSN, tenant, revisedID)
	var stage, dev string
	svcScan(t, readDSN, "SELECT verdict_stage, toString(device_id) FROM m1p_events WHERE tenant_id = {tenant:UUID} AND event_id = {event:UUID} LIMIT 1 BY event_id",
		map[string]string{"tenant": tenant.String(), "event": revisedID.String()}, &stage, &dev)
	if stage != "revised" || dev != ServiceDevice.String() {
		t.Fatalf("projected row: stage=%s device=%s", stage, dev)
	}

	// The readers prefer the re-entered stage per task: the attempt's fused
	// verdict flips to the adjudicator's, gold sees a stage-final row bound to
	// the ORIGINAL session, and the session rollup credits the task as violated.
	if rows := run("tvo_task_window", window); len(rows) != 1 || fmt.Sprint(rows[0]["fused_verdict"]) != "violated" || fmt.Sprint(rows[0]["verdict_stage"]) != "revised" || fmt.Sprint(rows[0]["attempt_n"]) != "1" {
		t.Fatalf("after re-entry tvo_task_window: %v", rows)
	}
	gold := run("gold_vs_verdict", closed)
	if len(gold) != 1 || fmt.Sprint(gold[0]["fused_verdict"]) != "violated" || fmt.Sprint(gold[0]["verdict_stage"]) != "revised" || fmt.Sprint(gold[0]["session_id"]) != session.String() {
		t.Fatalf("after re-entry gold_vs_verdict: %v", gold)
	}
	var violated, satisfied uint64
	for _, r := range run("usage_by_session", closed) {
		if fmt.Sprint(r["session_id"]) == session.String() {
			violated += asUint(t, r["tasks_violated"])
			satisfied += asUint(t, r["tasks_satisfied"])
		}
	}
	if violated != 1 || satisfied != 0 {
		t.Fatalf("usage_by_session: violated=%d satisfied=%d (the service verdict must ride the original session_id)", violated, satisfied)
	}

	// Idempotency, both layers: the same bytes re-POST as a duplicate (S3
	// conditional write), and a rerun under a NEW batch id but the same
	// deterministic event_id collapses in the ledger's reader discipline.
	if code, body := svcPost(t, srv.URL, "/internal/v1/ingest/service", testServiceToken, svcHeaders, serviceBatchID, serviceBytes); code != http.StatusOK || !strings.Contains(body, `"duplicates":1`) {
		t.Fatalf("re-POST: %d %s", code, body)
	}
	rerun, rerunID := testBatch(t, revised)
	rerun.SessionId, rerun.AdvisoryTenantId = session[:], tenant[:]
	if code, body := svcPost(t, srv.URL, "/internal/v1/ingest/service", testServiceToken, svcHeaders, rerunID, encodeBatch(t, rerun)); code != http.StatusOK {
		t.Fatalf("rerun: %d %s", code, body)
	}
	svcAwaitRaw(t, readDSN, tenant, revisedID, 2)
	var n string
	svcScan(t, readDSN, "SELECT count() FROM (SELECT event_id FROM m1p_events WHERE tenant_id = {tenant:UUID} AND event_id = {event:UUID} LIMIT 1 BY event_id)",
		map[string]string{"tenant": tenant.String(), "event": revisedID.String()}, &n)
	if n != "1" {
		t.Fatalf("rerun minted %s ledger identities for one verdict", n)
	}
	if rows := run("gold_vs_verdict", closed); len(rows) != 1 {
		t.Fatalf("rerun doubled the gold row: %v", rows)
	}

	// A device token cannot author the adjudicator's position.
	cert := verdictEvent(t, session, 9)
	cert.TaskId, cert.SessionEpoch = task[:], 3
	cert.GetVerdictEvent().Stage = m1pv1.VerdictStage_VERDICT_STAGE_CERTIFIED
	certBatch, certID := testBatch(t, cert)
	if code, body := svcPost(t, srv.URL, "/m1p/v1/ingest", deviceToken, nil, certID, encodeBatch(t, certBatch)); code != http.StatusUnprocessableEntity || !strings.Contains(body, "verdict_stage_origin") {
		t.Fatalf("device CERTIFIED: %d %s", code, body)
	}
	proj.Close()
}

func svcScan(t *testing.T, readDSN, sql string, params map[string]string, dest ...*string) {
	t.Helper()
	for k, v := range params {
		sql = strings.ReplaceAll(sql, "{"+k+":UUID}", "toUUID('"+v+"')")
	}
	line := strings.TrimSpace(svcCHSQL(t, readDSN, sql+" FORMAT TabSeparated"))
	if line == "" {
		t.Fatalf("no row for %s", sql)
	}
	cols := strings.Split(line, "\t")
	if len(cols) != len(dest) {
		t.Fatalf("%d columns for %d destinations: %q", len(cols), len(dest), line)
	}
	for i, d := range dest {
		*d = cols[i]
	}
}

// svcAwaitRaw waits for the async projector: n raw rows (pre-dedupe) for one event_id.
func svcAwaitRaw(t *testing.T, readDSN string, tenant, event uuid.UUID, n uint64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var raw string
		svcScan(t, readDSN, "SELECT count() FROM m1p_events WHERE tenant_id = {tenant:UUID} AND event_id = {event:UUID}",
			map[string]string{"tenant": tenant.String(), "event": event.String()}, &raw)
		got, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("event %s: %d/%d rows projected within 20s", event, got, n)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func svcAwaitEvent(t *testing.T, readDSN string, tenant, event uuid.UUID) {
	t.Helper()
	svcAwaitRaw(t, readDSN, tenant, event, 1)
}

func asUint(t *testing.T, v any) uint64 {
	t.Helper()
	switch x := v.(type) {
	case uint64:
		return x
	case *uint64:
		return *x
	case int64:
		return uint64(x)
	}
	t.Fatalf("unexpected count type %T", v)
	return 0
}
