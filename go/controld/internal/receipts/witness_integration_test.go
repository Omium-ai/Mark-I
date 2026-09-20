//go:build integration

// FR-SPINE-019's hourly witness clause, end to end, against real stores:
// the witness job → the REAL NewS3Publisher → a MinIO bucket created WITH
// object lock. Until this file the job had only ever been observed calling
// integration_test.go's in-process fakePublisher, and the publisher had
// only ever been observed at the request it sends (witness_s3_test.go), never
// at a bucket that enforces it. The row's product claim is the enforcement:
// "nobody, including the bucket owner, can remove the head before the
// retain-until date". So the assertions here are the bucket's, not ours —
// GetObjectRetention reports COMPLIANCE, and a version-specific DELETE inside
// the window is REFUSED by the server while the same DELETE on an unlocked
// object in the same bucket succeeds (the positive control that proves the
// refusal is retention and not a broken delete).
//
// Cadence: the job's ticker and clock are injected (WitnessJob.Clock), so two
// "hours" pass in milliseconds and the second publish is observed as a
// consequence of ELAPSED (fake) time through Run's loop — a tick with no
// elapsed hour publishes nothing, a tick after one does.
//
// Gates: M1_MIGRATE_PG_DSN (the receipts harness) and M1_TEST_S3_ENDPOINT.
// Unreachable S3 is fatal, not a skip, on s3land/integration_test.go's terms.
//
// Litter, stated honestly: COMPLIANCE retention cannot be shortened by anyone,
// so the locked head cannot be deleted at cleanup and its bucket cannot be
// removed until the horizon lapses. The horizon is therefore the shortest
// that still brackets the test (witnessRetain), cleanup is best-effort, and
// every run first sweeps the previous runs' lapsed buckets.

package receipts_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

const (
	witnessBucketPrefix = "m1-witness-it-"
	witnessRetain       = 2 * time.Minute
)

type staticCreds aws.Credentials

func (c staticCreds) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials(c), nil
}

// s3Setup resolves the store-contract endpoint, exports the credentials the
// publisher's default chain will read (IRSA in prod, MinIO's documented
// local-dev constant here), and returns a raw client for the assertions.
func s3Setup(t *testing.T) (endpoint string, cl *s3.Client) {
	t.Helper()
	endpoint = os.Getenv("M1_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Fatal("M1_TEST_S3_ENDPOINT unset — the S3 lane cannot pass by not running (12 §0.3); run `just stores-up`")
	}
	creds := aws.Credentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	if creds.AccessKeyID == "" {
		creds = aws.Credentials{AccessKeyID: "minioadmin", SecretAccessKey: "minioadmin"}
	}
	t.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	t.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
	t.Setenv("AWS_REGION", "us-east-1")
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"), awsconfig.WithCredentialsProvider(staticCreds(creds)))
	if err != nil {
		t.Fatal(err)
	}
	cl = s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
	if _, err := cl.ListBuckets(context.Background(), &s3.ListBucketsInput{}); err != nil {
		t.Fatalf("M1_TEST_S3_ENDPOINT=%s unreachable: %v — run `just stores-up`", endpoint, err)
	}
	return endpoint, cl
}

// emptyBucket deletes every version and delete marker it can; a COMPLIANCE-
// locked version refuses and stays, which is the property under test.
func emptyBucket(ctx context.Context, cl *s3.Client, bucket string) {
	p := s3.NewListObjectVersionsPaginator(cl, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return
		}
		for _, v := range page.Versions {
			_, _ = cl.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: v.Key, VersionId: v.VersionId})
		}
		for _, d := range page.DeleteMarkers {
			_, _ = cl.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: d.Key, VersionId: d.VersionId})
		}
	}
}

// sweepLapsed removes earlier runs' buckets whose retention has lapsed.
func sweepLapsed(ctx context.Context, cl *s3.Client) {
	out, err := cl.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return
	}
	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		if !strings.HasPrefix(name, witnessBucketPrefix) {
			continue
		}
		emptyBucket(ctx, cl, name)
		_, _ = cl.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(name)})
	}
}

func TestIntegrationWitnessJobLocksHeadInRealBucketAndTicksHourly(t *testing.T) {
	h := setup(t)
	endpoint, cl := s3Setup(t)
	ctx := context.Background()
	sweepLapsed(ctx, cl)

	// The bucket, created WITH object lock — the only kind of bucket on which
	// the publisher's headers mean anything. A bucket without it accepts the
	// same PUT and stores an unlocked object.
	bucket := witnessBucketPrefix + uuid.NewString()
	if _, err := cl.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket), ObjectLockEnabledForBucket: aws.Bool(true),
	}); err != nil {
		t.Fatalf("create object-lock bucket on %s: %v (MinIO needs a versioning-capable backend for lock)", endpoint, err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		emptyBucket(bg, cl, bucket)
		_, _ = cl.DeleteBucket(bg, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	})
	lockCfg, err := cl.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(bucket)})
	if err != nil || lockCfg.ObjectLockConfiguration == nil ||
		lockCfg.ObjectLockConfiguration.ObjectLockEnabled != s3types.ObjectLockEnabledEnabled {
		t.Fatalf("bucket does not report object lock enabled: %+v %v", lockCfg, err)
	}

	// A chain head to witness.
	ev := h.sealCheckpoint(t, h.tenantA, h.deviceA, h.deviceKey, leavesOf(v7(t)), time.Now())
	if _, err := h.store.AppendCheckpoint(ctx, h.tenantA, ev, nil); err != nil {
		t.Fatal(err)
	}

	// The REAL publisher, on the default credential chain, against the
	// locked bucket. Retain is the horizon the row's claim is made for.
	pub, err := receipts.NewS3Publisher(ctx, receipts.S3PublisherOptions{
		Bucket: bucket, Endpoint: endpoint, Retain: witnessRetain,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Fake clock for the job's freshness check; the publisher keeps real time
	// so retain-until is a real future instant the server will enforce.
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	tick := make(chan time.Time) // unbuffered: a send completes only when Run is back at its select
	job := receipts.NewWitnessJob(h.db, h.chainKey, pub, receipts.StaticTenants([]uuid.UUID{h.tenantA.UUID()}), time.Hour)
	job.Clock(now, tick)

	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); job.Run(runCtx) }()
	t.Cleanup(func() { stop(); <-done })

	rowCount := func() int64 {
		t.Helper()
		var n int64
		if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_witness_heads`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	waitRows := func(want int64) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for rowCount() != want {
			if time.Now().After(deadline) {
				t.Fatalf("m1_witness_heads has %d rows, want %d", rowCount(), want)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Hour 0: Run's first pass publishes.
	waitRows(1)

	// Two ticks with NO elapsed hour. Each send completes only when Run is
	// back at its select, i.e. when the previous tick's RunOnce has
	// finished — so after the second send, one full un-advanced pass has
	// run to completion under an unchanged clock, and it must not have
	// published. (The pass the second tick started is also un-advanced; it
	// cannot publish either unless the clock moves under it, below.)
	tick <- now()
	tick <- now()
	if n := rowCount(); n != 1 {
		t.Fatalf("a tick with no elapsed hour published: %d rows", n)
	}

	// Hour 1: the clock advances and the tick fires. Whichever pass reads the
	// advanced clock first publishes; the freshness check makes the other a
	// skip, so exactly one more head lands.
	clock.Add(int64(time.Hour))
	tick <- now()
	waitRows(2)
	stop()
	<-done
	if n := rowCount(); n != 2 {
		t.Fatalf("after two hours: %d rows, want exactly 2", n)
	}

	// ---- The bucket's side of the story.
	prefix := "witness/heads/" + h.tenantA.UUID().String() + "/"
	versions, err := cl.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket), Prefix: aws.String(prefix)})
	if err != nil {
		t.Fatal(err)
	}
	// Two publishes ⇒ two versions (distinct keys, or the same second-
	// resolution key twice in a versioned bucket — either way two heads).
	if len(versions.Versions) != 2 {
		t.Fatalf("want 2 published head versions under %s, got %d", prefix, len(versions.Versions))
	}

	for _, v := range versions.Versions {
		key, vid := aws.ToString(v.Key), aws.ToString(v.VersionId)
		// (1) The head is retained in COMPLIANCE mode until a future instant —
		// reported by the bucket, not by the request we sent.
		ret, err := cl.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
			Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(vid),
		})
		if err != nil || ret.Retention == nil {
			t.Fatalf("GetObjectRetention %s@%s: %+v %v — the head landed UNLOCKED", key, vid, ret, err)
		}
		if ret.Retention.Mode != s3types.ObjectLockRetentionModeCompliance {
			t.Fatalf("head %s retained in %s, want COMPLIANCE (GOVERNANCE is bypassable by an administrator)", key, ret.Retention.Mode)
		}
		if until := aws.ToTime(ret.Retention.RetainUntilDate); !until.After(time.Now()) {
			t.Fatalf("head %s retain-until %s is not in the future", key, until)
		}
		// (2) The immutability the row is about: a version-specific DELETE
		// inside the window is refused by the bucket.
		_, err = cl.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(vid),
		})
		if err == nil {
			t.Fatalf("DELETE of the locked head %s@%s SUCCEEDED inside the retention window", key, vid)
		}
		// AWS refuses with 403 AccessDenied; MinIO with 400 InvalidRequest
		// "Object is WORM protected". Either is the bucket saying no — what
		// would NOT be is a transport error, which the HEAD below would also
		// not distinguish from success.
		var respErr *awshttp.ResponseError
		if !errors.As(err, &respErr) || (respErr.HTTPStatusCode() != 403 && respErr.HTTPStatusCode() != 400) {
			t.Fatalf("DELETE of the locked head failed with something other than a server refusal: %v", err)
		}
		if _, err := cl.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(vid),
		}); err != nil {
			t.Fatalf("the locked head %s@%s is gone after the refused DELETE: %v", key, vid, err)
		}
	}

	// The rows cross-check the bucket: each names a copy inside it and a
	// horizon that has not lapsed.
	var uris []string
	rows, err := h.admin.Query(ctx, `SELECT object_bucket_uri, object_retain_until FROM m1_witness_heads ORDER BY witnessed_at`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var uri string
		var retain time.Time
		if err := rows.Scan(&uri, &retain); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(uri, "s3://"+bucket+"/"+prefix) {
			t.Fatalf("row names a copy outside the witness bucket/prefix: %s", uri)
		}
		if retain.Before(time.Now().Add(witnessRetain / 2)) {
			t.Fatalf("row records an already-lapsed or too-short horizon: %s", retain)
		}
		uris = append(uris, uri)
	}
	rows.Close()
	if len(uris) != 2 {
		t.Fatalf("want 2 rows, got %d", len(uris))
	}

	// Positive control: the same DELETE on an UNLOCKED object in the same
	// bucket succeeds — so the refusals above are retention, not a broken
	// delete path or a bucket that refuses everything.
	plain, err := cl.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("witness/control/unlocked.json"),
		Body: bytes.NewReader([]byte(`{}`)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("witness/control/unlocked.json"), VersionId: plain.VersionId,
	}); err != nil {
		t.Fatalf("positive control: DELETE of an unlocked version in the lock-enabled bucket failed: %v", err)
	}
}

// TestIntegrationDirectoryTenantsUnionsThePinnedList: m1_084's trigger mirrors every tenant into the directory; the source answers those plus the pinned ids, deduplicated, with the zero GUC.
func TestIntegrationDirectoryTenantsUnionsThePinnedList(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	pinned := uuid.New()
	ids, err := receipts.DirectoryTenants(h.db, []uuid.UUID{pinned, h.tenantA.UUID()})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uuid.UUID]int{}
	for _, id := range ids {
		seen[id]++
	}
	if seen[pinned] != 1 || seen[h.tenantA.UUID()] != 1 || seen[h.tenantB.UUID()] != 1 {
		t.Fatalf("directory ∪ pinned must hold every active tenant once: %v", ids)
	}
}
