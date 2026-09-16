//go:build integration && chaos

package ingest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke/chconn"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// tcpProxy sits between controld and one store; sever() is the outage
// (every live connection reset, new dials refused), heal() re-listens on the
// same port so the store's clients reconnect on their own.
type tcpProxy struct {
	t      *testing.T
	target string
	addr   string
	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
}

func newTCPProxy(t *testing.T, target string) *tcpProxy {
	t.Helper()
	p := &tcpProxy{t: t, target: target, conns: map[net.Conn]struct{}{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.addr = ln.Addr().String()
	p.serve(ln)
	t.Cleanup(p.sever)
	return p
}

func (p *tcpProxy) serve(ln net.Listener) {
	p.mu.Lock()
	p.ln, p.closed = ln, false
	p.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				_ = c.Close()
				_ = up.Close()
				continue
			}
			p.conns[c], p.conns[up] = struct{}{}, struct{}{}
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
}

func (p *tcpProxy) sever() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	_ = p.ln.Close()
	for c := range p.conns {
		_ = c.Close()
		delete(p.conns, c)
	}
}

func (p *tcpProxy) heal() {
	p.t.Helper()
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", p.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		p.t.Fatalf("re-listen on %s: %v", p.addr, err)
	}
	p.serve(ln)
}

// chaosS3 opens the real s3land client on a scratch MinIO bucket, through the proxy.
func chaosS3(t *testing.T, proxy *tcpProxy) *s3land.Client {
	t.Helper()
	endpoint := os.Getenv("M1_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Fatal("M1_TEST_S3_ENDPOINT unset — run `just stores-up`")
	}
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
	bucket := "m1-chaos-" + uuid.NewString()
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
	c, err := s3land.Open(ctx, s3land.Options{
		Bucket: bucket, Endpoint: "http://" + proxy.addr, KMSAliasPrefix: "alias/mark1-tenant-", DisableSSEKMS: true,
	})
	if err != nil {
		t.Fatalf("s3land.Open through the proxy: %v", err)
	}
	return c
}

func chHTTP(t *testing.T, sql string) string {
	t.Helper()
	dsn := os.Getenv("M1_TEST_CH_DSN")
	if dsn == "" {
		t.Fatal("M1_TEST_CH_DSN unset — run `just stores-up`")
	}
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

// chaosCH builds a scratch database with the real DDL and opens the
// projector's chconn through the proxy; user/pass ride the DSN's userinfo.
func chaosCH(t *testing.T) (scratch, nativeAddr, user, pass string) {
	t.Helper()
	u, err := url.Parse(os.Getenv("M1_TEST_CH_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	user = "default"
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	nativeAddr = net.JoinHostPort(u.Hostname(), chHTTP(t, "SELECT getServerPort('tcp_port')"))
	scratch = fmt.Sprintf("c4_chaos_%d", time.Now().UnixNano())
	chHTTP(t, "CREATE DATABASE "+scratch)
	t.Cleanup(func() { chHTTP(t, "DROP DATABASE IF EXISTS "+scratch) })
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "migrations", "m1_ch_001_events.sql"))
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
		chHTTP(t, stmt)
	}
	return scratch, nativeAddr, user, pass
}

type postResult struct {
	id      uuid.UUID
	body    []byte
	events  int
	status  int
	latency time.Duration
	at      time.Time
}

// poster is the synthetic edge: distinct batches, one HTTP POST each, every
// answer recorded with its latency. Re-posting is the edge automaton's job and
// is done explicitly by the test after the heal.
type poster struct {
	t       *testing.T
	url     string
	token   string
	mu      sync.Mutex
	results []postResult
}

func (p *poster) post(id uuid.UUID, body []byte, events int) postResult {
	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		p.t.Error(err)
		return postResult{}
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/x-m1p-protobuf")
	req.Header.Set("Content-Encoding", "zstd")
	req.Header.Set("M1P-Schema", "m1p.v1")
	req.Header.Set("M1P-Batch-Id", id.String())
	req.Header.Set("X-Mark1-Edge-Version", "0.0.1-chaos")
	started := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		p.t.Error(err)
		return postResult{}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	r := postResult{id: id, body: body, events: events, status: resp.StatusCode, latency: time.Since(started), at: started}
	p.mu.Lock()
	p.results = append(p.results, r)
	p.mu.Unlock()
	return r
}

func (p *poster) run(ctx context.Context, wg *sync.WaitGroup, pace time.Duration) {
	defer wg.Done()
	for ctx.Err() == nil {
		b, id := testBatch(p.t, usageEvent(p.t, mustV7(p.t), 1), usageEvent(p.t, mustV7(p.t), 2))
		p.post(id, encodeBatch(p.t, b), len(b.GetEvents()))
		time.Sleep(pace)
	}
}

func (p *poster) snapshot() []postResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]postResult(nil), p.results...)
}

// statusesBetween buckets answers by the instant they were ANSWERED: a request
// in flight at the cut belongs to the outage, one retried past the heal does not.
func statusesBetween(rs []postResult, from, to time.Time) map[int]int {
	out := map[int]int{}
	for _, r := range rs {
		if end := r.at.Add(r.latency); !end.Before(from) && end.Before(to) {
			out[r.status]++
		}
	}
	return out
}

func p99(rs []postResult) time.Duration {
	ds := make([]time.Duration, 0, len(rs))
	for _, r := range rs {
		ds = append(ds, r.latency)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[len(ds)*99/100]
}

type chaosRig struct {
	t                *testing.T
	s3               *s3land.Client
	s3Proxy, chProxy *tcpProxy
	conn             *chconn.Conn
	proj             *chproj.Projector
	mod              *Module
	post             *poster
	tenant           uuid.UUID
	device           uuid.UUID
	ch               struct{ scratch, addr, user, pass string }
}

func newChaosRig(t *testing.T) *chaosRig {
	t.Helper()
	r := &chaosRig{t: t, tenant: uuid.New(), device: uuid.New()}
	r.ch.scratch, r.ch.addr, r.ch.user, r.ch.pass = chaosCH(t)
	r.chProxy = newTCPProxy(t, r.ch.addr)
	r.s3Proxy = newTCPProxy(t, strings.TrimPrefix(os.Getenv("M1_TEST_S3_ENDPOINT"), "http://"))
	r.s3 = chaosS3(t, r.s3Proxy)
	conn, err := chconn.Open(context.Background(), chconn.Options{Addr: r.chProxy.addr, Database: r.ch.scratch, Username: r.ch.user, Password: r.ch.pass})
	if err != nil {
		t.Fatalf("chconn.Open through the proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	r.conn = conn
	r.proj = chproj.New(conn, 2, 256)
	sfx := sidefx.New(&fakeDB{}, nil, nil, 1, 256)
	t.Cleanup(sfx.Close)
	r.mod = New(Deps{
		Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-chaos"},
		PG:       fakeReady{}, Store: r.s3, Proj: r.proj, Sidefx: sfx, PoolSize: 16,
	})
	mux := http.NewServeMux()
	r.mod.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	r.post = &poster{t: t, url: srv.URL + "/m1p/v1/ingest", token: auth.Mint(testKey, r.tenant, r.device, time.Hour)}
	return r
}

// landedEvents lists every event_id under today's ingest prefix, straight off S3.
func (r *chaosRig) landedEvents() (map[uuid.UUID]bool, int) {
	r.t.Helper()
	ctx := context.Background()
	ids := map[uuid.UUID]bool{}
	objects := 0
	for _, day := range []time.Time{time.Now().UTC().Add(-24 * time.Hour), time.Now().UTC()} {
		keys, err := r.s3.List(ctx, s3land.IngestPrefix(r.tenant, day))
		if err != nil {
			r.t.Fatal(err)
		}
		for _, key := range keys {
			objects++
			compressed, _, err := r.s3.Get(ctx, key)
			if err != nil {
				r.t.Fatal(err)
			}
			decoded, err := decodeZstdBounded(compressed)
			if err != nil {
				r.t.Fatal(err)
			}
			var b m1pv1.Batch
			if err := proto.Unmarshal(decoded, &b); err != nil {
				r.t.Fatal(err)
			}
			for _, ev := range b.GetEvents() {
				ids[uuid.UUID(ev.GetEventId())] = true
			}
		}
	}
	return ids, objects
}

// TestChaosS3OutageNoFalseAck is 05 §9's S3 row: with the landing store cut
// mid-load, no 2xx leaves without an object behind it, and after the heal the
// edge's re-POSTs bring the landed set to exactly the posted set.
func TestChaosS3OutageNoFalseAck(t *testing.T) {
	r := newChaosRig(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	loadCtx, cancelLoad := context.WithCancel(ctx)
	wg.Add(4)
	for i := 0; i < 4; i++ {
		go r.post.run(loadCtx, &wg, 20*time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
	cut := time.Now()
	r.s3Proxy.sever()
	if err := r.mod.Ready(ctx); err == nil {
		t.Error("ingest reported ready with the landing store cut (05 §1.4: S3 HeadBucket is a readiness contributor)")
	}
	time.Sleep(2500 * time.Millisecond)
	healed := time.Now()
	r.s3Proxy.heal()
	time.Sleep(1500 * time.Millisecond)
	cancelLoad()
	wg.Wait()

	first := r.post.snapshot()
	// THE invariant: every 2xx has its object, byte-for-byte, right now.
	acked := 0
	for _, res := range first {
		if res.status/100 != 2 {
			continue
		}
		acked++
		if got, err := r.s3.Probe(ctx, s3land.IngestKey(r.tenant, res.id), res.body); err != nil || got != s3land.Duplicate {
			t.Fatalf("batch %s was acked %d but Probe says %v (err %v): an ack without a landed object", res.id, res.status, got, err)
		}
	}
	before, during, after := statusesBetween(first, time.Time{}, cut), statusesBetween(first, cut, healed), statusesBetween(first, healed, time.Now().Add(time.Hour))
	if before[http.StatusOK] == 0 || after[http.StatusOK] == 0 {
		t.Fatalf("no 200s before (%v) or after (%v) the outage: the load never exercised a healthy store", before, after)
	}
	if during[http.StatusServiceUnavailable] == 0 {
		t.Fatalf("no 503 during the outage (%v): the cut never reached a landing", during)
	}
	for _, res := range first {
		switch res.status {
		case http.StatusOK:
		case http.StatusServiceUnavailable:
			if res.at.Add(res.latency).Before(cut) {
				t.Fatalf("batch %s got 503 before the cut: the store was failing on its own", res.id)
			}
		default:
			t.Fatalf("batch %s got %d: a landing failure must be the retryable 503 M1E-9500, nothing else", res.id, res.status)
		}
	}

	// The edge's half: every refused batch is re-POSTed byte-identical after the heal.
	replayed, lostAck := 0, 0
	for _, res := range first {
		if res.status/100 == 2 {
			continue
		}
		prior, err := r.s3.Probe(ctx, s3land.IngestKey(r.tenant, res.id), res.body)
		if err != nil {
			t.Fatal(err)
		}
		if prior == s3land.Duplicate {
			lostAck++
		}
		if again := r.post.post(res.id, res.body, res.events); again.status != http.StatusOK {
			t.Fatalf("re-POST of %s after the heal: %d, want 200", res.id, again.status)
		}
		replayed++
	}
	landed, objects := r.landedEvents()
	posted := map[uuid.UUID]bool{}
	for _, res := range first {
		posted[res.id] = true
	}
	if objects != len(posted) {
		t.Fatalf("%d landed objects for %d distinct batches posted: a batch double-landed or never landed", objects, len(posted))
	}
	if len(landed) != 2*len(posted) {
		t.Fatalf("%d events in the landing objects for %d batches of 2: billing-grade loss end to end", len(landed), len(posted))
	}
	r.proj.Close()
	t.Logf("chaos_s3_outage: %d posts (%d acked with objects proven, %d refused then replayed, %d of those had landed with the ack lost); statuses before/during/after = %v/%v/%v",
		len(first), acked, replayed, lostAck, before, during, after)
}

// TestChaosCHOutageIngestUnaffected is 05 §9's ClickHouse row: the ledger view
// goes away under load, the ack SLI holds because S3 is the promise, and a
// post-heal replay makes the ledger equal the landing objects exactly.
func TestChaosCHOutageIngestUnaffected(t *testing.T) {
	r := newChaosRig(t)
	ctx := context.Background()

	loadCtx, cancelLoad := context.WithCancel(ctx)
	var wg sync.WaitGroup
	// One poster at 50 ms: the projector parks a job only after 1+2+3 s of retries
	// and holds a worker for all of it, so heavier load turns the post-heal drain into minutes.
	wg.Add(1)
	go r.post.run(loadCtx, &wg, 50*time.Millisecond)
	time.Sleep(1500 * time.Millisecond)
	parkedBefore := counterValue(t, "controld_ingest_ch_project_failures_total")
	cut := time.Now()
	r.chProxy.sever()
	if err := r.mod.Ready(ctx); err != nil {
		t.Errorf("ingest reported unready with only ClickHouse cut: %v (05 §1.4 keeps CH out of ingest readiness)", err)
	}
	// Longer than the projector's 1+2+3 s retry ladder, so some jobs park.
	time.Sleep(8 * time.Second)
	healed := time.Now()
	r.chProxy.heal()
	time.Sleep(1500 * time.Millisecond)
	cancelLoad()
	wg.Wait()

	all := r.post.snapshot()
	during := statusesBetween(all, cut, healed)
	if n := during[http.StatusOK]; n == 0 || len(during) != 1 {
		t.Fatalf("statuses during the ClickHouse outage = %v, want only 200s: the ack promise is S3, not the ledger", during)
	}
	var underOutage []postResult
	for _, res := range all {
		if end := res.at.Add(res.latency); !end.Before(cut) && end.Before(healed) {
			underOutage = append(underOutage, res)
		}
	}
	var beforeCut []postResult
	for _, res := range all {
		if res.at.Add(res.latency).Before(cut) {
			beforeCut = append(beforeCut, res)
		}
	}
	// The SLI is 800 ms at p99 (05 §2.7); on a shared box the baseline is the honest yardstick.
	if p, base := p99(underOutage), p99(beforeCut); p > max(800*time.Millisecond, 3*base) {
		t.Fatalf("ack p99 under the ClickHouse outage = %v against a %v baseline: the cut reached the ack path", p, base)
	}

	r.proj.Close()
	landed, objects := r.landedEvents()
	count := func() int {
		n, err := strconv.Atoi(chHTTP(t, fmt.Sprintf("SELECT uniqExact(event_id) FROM %s.m1p_events WHERE tenant_id = '%s'", r.ch.scratch, r.tenant)))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	projected := count()
	if projected > len(landed) {
		t.Fatalf("ledger holds %d events for %d landed: projection invented rows", projected, len(landed))
	}
	// The positive control is the projector's own park counter, not the hole: an
	// insert cut mid-reply lands its rows and still parks, so the hole can be zero.
	if parked := counterValue(t, "controld_ingest_ch_project_failures_total") - parkedBefore; parked < 1 {
		t.Fatalf("projector parked %v batches across an %v outage: the cut never reached a projection, so the replay below proves nothing", parked, healed.Sub(cut))
	}
	tid, err := querychoke.FromClaims(auth.Claims{TenantID: r.tenant})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := Replay(ctx, r.s3, r.conn, nil, tid, time.Now().UTC().Add(-24*time.Hour), time.Now().UTC())
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed != objects {
		t.Fatalf("replay visited %d objects, %d landed", replayed, objects)
	}
	if got := count(); got != len(landed) {
		t.Fatalf("ledger holds %d distinct events after replay, landing objects hold %d", got, len(landed))
	}
	t.Logf("chaos_ch_outage: %d posts all 200 (p99 %v under the outage, %v before), ledger had %d/%d events before replay and %d/%d after",
		len(all), p99(underOutage), p99(beforeCut), projected, len(landed), len(landed), len(landed))
}
