//go:build integration

// Real-S3 integration for the landing stage (05 §2.2). Until this file existed
// nothing in the repo read M1_TEST_S3_ENDPOINT: `just stores-up` started MinIO
// on 9002 and every s3land assertion in the tree was a pure-function check over
// key strings and JSON fixtures. Land's conditional PUT, the 412 checksum
// compare, the m1-device-id metadata round trip and the t/<tenant>/ prefix as
// an ENFORCEMENT boundary were all unexercised against a server.
//
// Gate: M1_TEST_S3_ENDPOINT (the ONE store-contract var, justfile / 12 §11.4).
//
// This file deliberately does NOT carry chproj's `absent ⇒ skip unless
// M1_REQUIRE_STORES=1` escape. Three traceability rows cite these tests as
// their only evidence that a real S3 was driven, and a test that can answer
// "no store, therefore pass" is exactly the green-because-skipped failure the
// rows were opened against. Missing or unreachable endpoint is always fatal
// here; the justfile defaults the var, so no sanctioned lane can hit it.
//
// Credentials: MinIO's documented local-dev root constant (justfile stores-up,
// allowlisted in .gitleaks.toml), overridable from the ambient AWS env for a
// lane pointed at some other S3.
//
// Ceiling, stated once and honestly: MinIO has no KMS, so Options.DisableSSEKMS
// is set throughout and the SSE-KMS half of 05 §2.2 — per-tenant CMK, per-tenant
// grants — is NOT exercised anywhere below. What IS exercised is the other half
// of the same boundary: the t/<tenant>/ key prefix, evaluated by a real server's
// IAM engine against a real non-owner principal. See the cross-tenant test.

package s3land

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
)

const (
	itRegion        = "us-east-1"
	itAliasPrefix   = "alias/mark1-tenant-"
	itPersonalAlias = "alias/mark1-personal"
)

// s3Endpoint resolves the store-contract var and proves the server answers
// before any test builds expectations on it. Unreachable is fatal, not a skip.
func s3Endpoint(t *testing.T) string {
	t.Helper()
	ep := os.Getenv("M1_TEST_S3_ENDPOINT")
	if ep == "" {
		t.Fatal("M1_TEST_S3_ENDPOINT unset — the S3 lane cannot pass by not running (12 §0.3); run `just stores-up`")
	}
	resp, err := http.Get(strings.TrimSuffix(ep, "/") + "/minio/health/live") //nolint:noctx // liveness probe
	if err != nil {
		t.Fatalf("M1_TEST_S3_ENDPOINT=%s unreachable: %v — run `just stores-up`", ep, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("M1_TEST_S3_ENDPOINT=%s liveness returned %d", ep, resp.StatusCode)
	}
	return ep
}

func rootCreds() aws.Credentials {
	c := aws.Credentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	if c.AccessKeyID == "" {
		c = aws.Credentials{AccessKeyID: "minioadmin", SecretAccessKey: "minioadmin"}
	}
	return c
}

// staticCreds is aws.CredentialsProvider in four lines — the SDK's own static
// provider lives in a module this one only requires indirectly, and pulling it
// in to hold two strings would edit go.mod for no behaviour.
type staticCreds aws.Credentials

func (c staticCreds) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials(c), nil
}

func clientFor(t *testing.T, endpoint string, creds aws.Credentials) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(itRegion),
		awsconfig.WithCredentialsProvider(staticCreds(creds)))
	if err != nil {
		t.Fatalf("aws config: %v", err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
}

// r6Policy is the shape Open's R6 probe demands (05 §1.2; ADR-0011 §3): a Deny
// on t/* conditioned on the KMS alias — per-tenant, plus the pooled personal
// alias. MinIO stores and returns it verbatim-enough (it normalises Action and
// Principal to arrays), which is what lets the R6 test below read the policy
// back off a real server instead of a Go string literal. MinIO rejects
// NotResource outright, so the AWS-side statement that pins the pooled key to
// t/* (the docs/09 form) cannot be round-tripped here; this Resource-scoped
// form is the one the dev stack carries.
func r6Policy(bucket string) string {
	return `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Deny","Principal":"*","Action":"s3:PutObject",
	   "Resource":"arn:aws:s3:::` + bucket + `/t/*",
	   "Condition":{"StringNotLike":{"s3:x-amz-server-side-encryption-aws-kms-key-id":["*` + itAliasPrefix + `*","*` + itPersonalAlias + `"]}}}]}`
}

// r6TenantOnlyPolicy is the pre-ADR-0011 shape: per-tenant deny, no pooled statement.
func r6TenantOnlyPolicy(bucket string) string {
	return `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Deny","Principal":"*","Action":"s3:PutObject",
	   "Resource":"arn:aws:s3:::` + bucket + `/t/*",
	   "Condition":{"StringNotLike":{"s3:x-amz-server-side-encryption-aws-kms-key-id":"*` + itAliasPrefix + `*"}}}]}`
}

// orgKind is the default seam below: every tenant is an organization, the posture the older lanes assume.
func orgKind(context.Context, uuid.UUID) (string, error) { return "org", nil }

// newBucket creates a scratch bucket, applies policy (nil ⇒ no bucket policy
// at all) and registers the cleanup that empties and removes it: this suite
// leaves nothing behind on the server it ran against.
func newBucket(t *testing.T, endpoint string, creds aws.Credentials, policy func(string) string) string {
	t.Helper()
	ctx := context.Background()
	cl := clientFor(t, endpoint, creds)
	bucket := "m1-s3land-it-" + uuid.NewString()
	if _, err := cl.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create scratch bucket %s: %v", bucket, err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		p := s3.NewListObjectsV2Paginator(cl, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
		for p.HasMorePages() {
			page, err := p.NextPage(bg)
			if err != nil {
				break
			}
			for _, o := range page.Contents {
				_, _ = cl.DeleteObject(bg, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: o.Key})
			}
		}
		_, _ = cl.DeleteBucket(bg, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	})
	if policy != nil {
		if _, err := cl.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: aws.String(bucket),
			Policy: aws.String(policy(bucket)),
		}); err != nil {
			t.Fatalf("put bucket policy on %s: %v", bucket, err)
		}
	}
	return bucket
}

// setup opens a real s3land.Client — through Open, so every test below has
// also passed boot refusal R6 against a live server — on a fresh bucket.
func setup(t *testing.T) (*Client, string, string) {
	t.Helper()
	endpoint := s3Endpoint(t)
	creds := rootCreds()
	// Open resolves credentials from the ambient chain exactly as it does in
	// prod (IRSA there, these two constants here).
	t.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	t.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
	t.Setenv("AWS_REGION", itRegion)

	bucket := newBucket(t, endpoint, creds, r6Policy)
	c, err := Open(context.Background(), Options{
		Bucket:           bucket,
		Endpoint:         endpoint,
		KMSAliasPrefix:   itAliasPrefix,
		PersonalKMSAlias: itPersonalAlias,
		TenantKind:       orgKind,
		DisableSSEKMS:    true, // MinIO has no KMS (Options doc); the ceiling, stated in the file header
	})
	if err != nil {
		t.Fatalf("Open against real S3: %v", err)
	}
	return c, bucket, endpoint
}

// ADR-0011 §2 against a real store: a refused landing leaves NOTHING behind (the alias itself is proven on the wire in sse_kms_test.go).
func TestIntegrationLandRefusesUnresolvedTenantKind(t *testing.T) {
	c, _, _ := setup(t)
	ctx := context.Background()
	tenant, device := uuid.New(), uuid.New()
	key := IngestKey(tenant, uuid.Must(uuid.NewV7()))
	body := []byte("batch-whose-tenant-kind-is-unknown")

	c.opt.TenantKind = func(context.Context, uuid.UUID) (string, error) {
		return "", errors.New("m1_tenants: row unreadable")
	}
	if out, err := c.Land(ctx, key, body, tenant, device); !errors.Is(err, ErrTenantKind) {
		t.Fatalf("Land with an erroring kind seam: out %v, err %v; want ErrTenantKind", out, err)
	}
	if got, err := c.Probe(ctx, key, body); err != nil || got != NotLanded {
		t.Fatalf("a refused landing left an object behind: Probe %v, err %v; want NotLanded", got, err)
	}

	// Positive controls, both branches: the refusal above was the kind check, not an unreachable bucket.
	c.opt.TenantKind = func(context.Context, uuid.UUID) (string, error) { return "personal", nil }
	if out, err := c.Land(ctx, key, body, tenant, device); err != nil || out != Landed {
		t.Fatalf("personal tenant Land: out %v, err %v", out, err)
	}
	c.opt.TenantKind = orgKind
	if out, err := c.Land(ctx, IngestKey(uuid.New(), uuid.Must(uuid.NewV7())), body, uuid.New(), device); err != nil || out != Landed {
		t.Fatalf("org tenant Land: out %v, err %v", out, err)
	}
}

// ─── FR-SPINE-010: the conditional PUT, against a server that enforces it ────
//
// The ack is licensed by this call and nothing else (05 §2.2), so the three
// outcomes are not a taxonomy — they are the difference between acking data we
// hold, acking data we already held, and refusing to lose data we hold.

func TestIntegrationLandNeverOverwritesALandedBatch(t *testing.T) {
	c, bucket, endpoint := setup(t)
	ctx := context.Background()

	if err := c.Ready(ctx); err != nil {
		t.Fatalf("Ready on a bucket Open just accepted: %v", err)
	}

	tenant, device := uuid.New(), uuid.New()
	batch := uuid.Must(uuid.NewV7())
	key := IngestKey(tenant, batch)
	original := []byte("m1p-batch-original-bytes\x00\x01\x02")
	colliding := []byte("m1p-batch-DIFFERENT-bytes-same-batch-id")

	// Anti-vacuity: the key is empty before this test touches it, so every
	// outcome below is this test's own doing and not a stale object's.
	if got, err := c.Probe(ctx, key, original); err != nil || got != NotLanded {
		t.Fatalf("Probe on an unwritten key: got %v, err %v; want NotLanded", got, err)
	}

	if got, err := c.Land(ctx, key, original, tenant, device); err != nil || got != Landed {
		t.Fatalf("first Land: got %v, err %v; want Landed", got, err)
	}

	// Positive control for everything that follows: the object is really
	// there and really readable. A suite that only ever asserts refusals
	// cannot tell "correctly refused" from "never wrote anything".
	body, _, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get after Land: %v", err)
	}
	if !bytes.Equal(body, original) {
		t.Fatalf("Get returned %q, want the landed bytes %q", body, original)
	}

	// The checksum leg: compareLanded prefers the server's stored
	// ChecksumSHA256 and only falls back to GET+hash when it is absent, so
	// pin that the PUT actually persisted one. Without this the fallback
	// would silently cover a PUT that stopped sending the checksum.
	head, err := clientFor(t, endpoint, rootCreds()).HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:       aws.String(bucket),
		Key:          aws.String(key),
		ChecksumMode: s3types.ChecksumModeEnabled,
	})
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	sum := sha256.Sum256(original)
	if want := base64.StdEncoding.EncodeToString(sum[:]); aws.ToString(head.ChecksumSHA256) != want {
		t.Fatalf("server stored ChecksumSHA256 %q, want %q — the 412 compare would be running on the GET fallback",
			aws.ToString(head.ChecksumSHA256), want)
	}

	// A re-POST of an acked batch (08 §2.3): identical bytes, same key. The
	// server answers 412 and the compare resolves it to a cheap second ack.
	if got, err := c.Land(ctx, key, original, tenant, device); err != nil || got != Duplicate {
		t.Fatalf("re-Land of identical bytes: got %v, err %v; want Duplicate", got, err)
	}

	// batch_id reuse with different bytes: edge spool corruption.
	if got, err := c.Land(ctx, key, colliding, tenant, device); err != nil || got != Divergent {
		t.Fatalf("Land of colliding bytes: got %v, err %v; want Divergent", got, err)
	}

	// THE invariant. The landed object IS the replay log; if a second Land
	// under the same key can replace its bytes, every downstream rebuild is
	// reading a batch nobody acked and the original is gone with no trace.
	body, _, err = c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get after the colliding Land: %v", err)
	}
	if !bytes.Equal(body, original) {
		t.Fatalf("a colliding Land REPLACED a landed batch: key now holds %q, want %q — the replay log is not append-only",
			body, original)
	}

	// Probe reaches the same two verdicts read-only.
	if got, err := c.Probe(ctx, key, original); err != nil || got != Duplicate {
		t.Fatalf("Probe with the landed bytes: got %v, err %v; want Duplicate", got, err)
	}
	if got, err := c.Probe(ctx, key, colliding); err != nil || got != Divergent {
		t.Fatalf("Probe with colliding bytes: got %v, err %v; want Divergent", got, err)
	}

	// The §2.5 replay lister sees exactly the one landed object — and nothing
	// the Divergent path might have written on the side.
	keys, err := c.List(ctx, IngestPrefix(tenant, batchTime(batch)))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("replay listing = %v, want exactly [%s]", keys, key)
	}
}

// ─── FR-SPINE-010: the device stamp, through a real server ──────────────────
//
// Replay (05 §2.5) re-stamps device_id from object metadata with no token to
// read it from, so the stamp is only as good as the SDK/server agreement about
// x-amz-meta-* key casing — which is precisely the class of bug a fake Store
// cannot have.

func TestIntegrationDeviceStampRoundTrips(t *testing.T) {
	c, _, _ := setup(t)
	ctx := context.Background()

	tenant := uuid.New()
	devA, devB := uuid.New(), uuid.New()
	keyA := IngestKey(tenant, uuid.Must(uuid.NewV7()))
	keyB := IngestKey(tenant, uuid.Must(uuid.NewV7()))

	for _, l := range []struct {
		key    string
		device uuid.UUID
	}{{keyA, devA}, {keyB, devB}} {
		if got, err := c.Land(ctx, l.key, []byte("stamped:"+l.device.String()), tenant, l.device); err != nil || got != Landed {
			t.Fatalf("Land %s: got %v, err %v", l.key, got, err)
		}
	}

	// Two distinct stamps, read back per key: a Get that returned uuid.Nil,
	// a constant, or the most recently written stamp all fail here, and one
	// object could not tell those apart.
	for _, l := range []struct {
		key    string
		device uuid.UUID
	}{{keyA, devA}, {keyB, devB}} {
		body, got, err := c.Get(ctx, l.key)
		if err != nil {
			t.Fatalf("Get %s: %v", l.key, err)
		}
		if got != l.device {
			t.Fatalf("m1-device-id did not survive the round trip through a real S3: got %s, want %s "+
				"(replay re-stamps device_id from this metadata and has no other source)", got, l.device)
		}
		if want := "stamped:" + l.device.String(); string(body) != want {
			t.Fatalf("body/stamp pairing crossed: %q with %s", body, got)
		}
	}
}

// ─── NFR-PRIVACY-004 / NFR-SECURITY-003: a real cross-tenant denial ─────────
//
// What the estate keeps re-learning: the connecting principal decides whether
// an isolation control is a control. MinIO's root credential is the bucket
// owner and bypasses bucket policy outright — verified: root PUTs into t/*
// under the R6 Deny above without the KMS header and succeeds. So a
// "cross-tenant" test run as root would PASS while proving nothing, which is
// the trap NFR-SECURITY-003's own note names.
//
// The principal here is therefore NOT root. MinIO's STS AssumeRole mints
// credentials whose effective permissions are the intersection of the parent's
// and an inline session policy; scoping that policy to one tenant's
// t/<uuid>/* ARN produces a genuine non-owner principal, and MinIO's IAM
// engine — not this test — decides what it may read.
//
// The ceiling, precisely: this proves the KEY PREFIX is an enforcement
// boundary on a real server. It does NOT prove the SSE-KMS half of 05 §2.2 —
// MinIO has no KMS, so per-tenant CMK grants (the control that makes a
// mis-stamped tenant a write FAILURE rather than a cross-tenant write) remain
// provable only by policy simulation or a real-AWS run. VerifyTenantKMSDeny
// is what stands in for it, and the R6 test below at least drives that parser
// over a document a real S3 server accepted, stored and returned.

func TestIntegrationCrossTenantPrefixReadDenied(t *testing.T) {
	c, bucket, endpoint := setup(t)
	ctx := context.Background()

	tenantA, tenantB := uuid.New(), uuid.New()
	keyA := IngestKey(tenantA, uuid.Must(uuid.NewV7()))
	keyB := IngestKey(tenantB, uuid.Must(uuid.NewV7()))
	bodyA := []byte("tenant-A-batch")
	bodyB := []byte("tenant-B-batch-that-A-must-never-read")

	for _, l := range []struct {
		key    string
		body   []byte
		tenant uuid.UUID
	}{{keyA, bodyA, tenantA}, {keyB, bodyB, tenantB}} {
		if got, err := c.Land(ctx, l.key, l.body, l.tenant, uuid.New()); err != nil || got != Landed {
			t.Fatalf("Land %s: got %v, err %v", l.key, got, err)
		}
	}

	// Anti-vacuity, part 1: both objects EXIST and are readable by a
	// principal entitled to them. A 404 from an empty bucket is not a proof
	// of isolation, and this is what rules that reading out.
	for _, l := range []struct {
		key  string
		body []byte
	}{{keyA, bodyA}, {keyB, bodyB}} {
		got, _, err := c.Get(ctx, l.key)
		if err != nil {
			t.Fatalf("owner Get %s: %v — the denial below would be vacuous", l.key, err)
		}
		if !bytes.Equal(got, l.body) {
			t.Fatalf("owner Get %s returned %q, want %q", l.key, got, l.body)
		}
	}

	scoped := clientFor(t, endpoint, assumeRoleScopedToPrefix(t, endpoint, bucket,
		fmt.Sprintf("t/%s/*", tenantA), rootCreds()))

	// Anti-vacuity, part 2 — the positive control. The scoped principal can
	// really read its OWN tenant's object. Without this, every refusal below
	// is equally explained by a broken credential, and a check that refuses
	// everything is not an isolation boundary, it is an outage.
	out, err := scoped.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(keyA)})
	if err != nil {
		t.Fatalf("tenant-A principal cannot read tenant A's own object: %v — the denials below prove nothing", err)
	}
	own, err := io.ReadAll(out.Body)
	_ = out.Body.Close()
	if err != nil || !bytes.Equal(own, bodyA) {
		t.Fatalf("tenant-A principal read %q from its own prefix, want %q (err %v)", own, bodyA, err)
	}

	// The denial. 403, specifically: a 404 would mean the object was not
	// there, which is a different (and here, false) statement.
	_, err = scoped.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(keyB)})
	assertForbidden(t, err, "cross-tenant GET of "+keyB)

	// And the write direction: A must not be able to plant an object in B's
	// replay log either.
	_, err = scoped.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(IngestKey(tenantB, uuid.Must(uuid.NewV7()))),
		Body:   bytes.NewReader([]byte("forged")),
	})
	assertForbidden(t, err, "cross-tenant PUT into t/"+tenantB.String())

	// B's batch is byte-identical after the intrusion attempts.
	after, _, err := c.Get(ctx, keyB)
	if err != nil || !bytes.Equal(after, bodyB) {
		t.Fatalf("tenant B's landed batch changed under a foreign principal: %q (err %v)", after, err)
	}
}

func assertForbidden(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s SUCCEEDED — the t/<tenant>/ prefix is not an enforcement boundary on this server", what)
	}
	var respErr *awshttp.ResponseError
	if !errors.As(err, &respErr) {
		t.Fatalf("%s failed with a non-HTTP error (%v); wanted an explicit 403 from the server's IAM engine", what, err)
	}
	if code := respErr.HTTPStatusCode(); code != http.StatusForbidden {
		t.Fatalf("%s was refused with HTTP %d, want 403. A 404 in particular is NOT an isolation proof — "+
			"it says the object is absent, and this test already proved it present.", what, code)
	}
}

// assumeRoleScopedToPrefix mints MinIO STS credentials confined by an inline
// session policy to one tenant prefix. Hand-signed rather than via the STS
// client: aws-sdk-go-v2/service/sts is an indirect requirement of this module
// and importing it would make `go mod tidy -diff` (justfile:225) demand a
// go.mod edit for what is twenty lines of form POST.
func assumeRoleScopedToPrefix(t *testing.T, endpoint, bucket, prefix string, root aws.Credentials) aws.Credentials {
	t.Helper()
	ctx := context.Background()
	sessionPolicy := fmt.Sprintf(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::%s/%s"]}]}`,
		bucket, prefix)
	form := url.Values{
		"Action":          {"AssumeRole"},
		"Version":         {"2011-06-15"},
		"RoleArn":         {"arn:minio:iam:::role/m1-s3land-it"},
		"RoleSessionName": {"m1-s3land-it"},
		"DurationSeconds": {"900"},
		"Policy":          {sessionPolicy},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	payload := sha256.Sum256([]byte(form))
	if err := v4.NewSigner().SignHTTP(ctx, root, req, hex.EncodeToString(payload[:]), "sts", itRegion, time.Now()); err != nil {
		t.Fatalf("sign STS AssumeRole: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("STS AssumeRole: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("STS AssumeRole returned %d: %s", resp.StatusCode, raw)
	}
	var doc struct {
		AccessKeyID     string `xml:"AssumeRoleResult>Credentials>AccessKeyId"`
		SecretAccessKey string `xml:"AssumeRoleResult>Credentials>SecretAccessKey"`
		SessionToken    string `xml:"AssumeRoleResult>Credentials>SessionToken"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("STS AssumeRole response unparseable: %v\n%s", err, raw)
	}
	if doc.AccessKeyID == "" || doc.SessionToken == "" {
		t.Fatalf("STS AssumeRole returned no scoped credentials — a root-credentialled client would "+
			"bypass bucket policy and pass this test vacuously, so this is fatal:\n%s", raw)
	}
	return aws.Credentials{
		AccessKeyID:     doc.AccessKeyID,
		SecretAccessKey: doc.SecretAccessKey,
		SessionToken:    doc.SessionToken,
		Source:          "minio-sts",
	}
}

// ─── NFR-PRIVACY-004: R6 over a policy a real server round-tripped ──────────
//
// TestVerifyTenantKMSDeny drives the parser over Go string literals, which
// cannot catch the parser agreeing with a document no S3 would ever store.
// Here the policies go through PutBucketPolicy and come back out of
// GetBucketPolicy — MinIO normalises Action and Principal to arrays on the way
// through, which is exactly the kind of reshaping a literal-only test is blind
// to — and Open's boot refusal runs on what came back.

func TestIntegrationOpenR6AgainstRealBucketPolicies(t *testing.T) {
	endpoint := s3Endpoint(t)
	creds := rootCreds()
	t.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	t.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
	t.Setenv("AWS_REGION", itRegion)
	ctx := context.Background()

	open := func(bucket string) error {
		_, err := Open(ctx, Options{Bucket: bucket, Endpoint: endpoint, KMSAliasPrefix: itAliasPrefix,
			PersonalKMSAlias: itPersonalAlias, TenantKind: orgKind, DisableSSEKMS: true})
		return err
	}

	// Positive control first: a refusal that refuses everything is not a
	// control. The deny-bearing policy must actually boot.
	if err := open(newBucket(t, endpoint, creds, r6Policy)); err != nil {
		t.Fatalf("R6 refused a bucket carrying the per-tenant-KMS Deny: %v", err)
	}

	// Pre-ADR-0011 policy: boots without a pooled alias, refused with one, naming the ADR.
	tenantOnly := newBucket(t, endpoint, creds, r6TenantOnlyPolicy)
	if _, err := Open(ctx, Options{Bucket: tenantOnly, Endpoint: endpoint, KMSAliasPrefix: itAliasPrefix, DisableSSEKMS: true}); err != nil {
		t.Fatalf("R6 refused the per-tenant-only policy with no pooled alias configured: %v", err)
	}
	if err := open(tenantOnly); err == nil || !strings.Contains(err.Error(), "ADR-0011") {
		t.Fatalf("R6 booted with a pooled alias on a stored policy that never binds it (err %v) — a personal PUT would be refused by nobody", err)
	}

	// A policy MinIO accepts and stores, without the Deny.
	weak := newBucket(t, endpoint, creds, func(b string) string {
		return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::` + b + `/t/*"}]}`
	})
	if err := open(weak); err == nil {
		t.Fatal("R6 booted on a bucket whose stored policy has no per-tenant-KMS Deny — a stamping bug upstream would become a cross-tenant write")
	}

	// No bucket policy at all: GetBucketPolicy 404s and R6 must not read that
	// as permission.
	if err := open(newBucket(t, endpoint, creds, nil)); err == nil {
		t.Fatal("R6 booted on a bucket with NO policy at all")
	}

	// And the bucket that isn't there.
	if err := open("m1-s3land-it-absent-" + uuid.NewString()); err == nil {
		t.Fatal("R6 booted against a nonexistent bucket")
	}
}
