// Per-tenant SSE-KMS on the landing PUT (05 §2.2; FR-SPINE-010).
//
// integration_test.go states its own ceiling honestly: MinIO has no KMS, so
// every lane there sets Options.DisableSSEKMS and the SSE-KMS arm of Land is
// never entered. That made the security-critical half of §2.2 — "each tenant's
// objects are encrypted under THAT tenant's key" — unobserved by any test. A
// cross-tenant key reuse (or a hardcoded key id) would ship green.
//
// This file closes it without a KMS, a bucket, or a network: s3.Options carries
// an HTTPClient seam, so the real *s3.Client runs the real serializer over the
// real PutObjectInput that Land builds and hands the finished request to a fake
// transport that answers 200 from memory. What is asserted is the wire request
// AWS would receive, one serialization step PAST the struct — it cannot drift
// from production, because it IS production up to the socket.
//
// ZERO production change: Client's fields are package-private and this test is
// in-package, so the client seam needs no exported constructor.

package s3land

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

// putCapture is an s3.HTTPClient (Do(*http.Request)) that records every request
// and answers a canned 200. No socket is opened.
type putCapture struct{ reqs []*http.Request }

func (c *putCapture) Do(r *http.Request) (*http.Response, error) {
	c.reqs = append(c.reqs, r)
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Etag": {`"0f0f0f"`}},
		Body:   http.NoBody, Request: r,
	}, nil
}

// only returns the single captured request, failing loudly if the transport
// never fired or fired more than once. Every field assertion below runs ONLY
// after this: "the request had header X" is also what a test reports when it
// read a zero value off a request that was never made.
func (c *putCapture) only(t *testing.T) *http.Request {
	t.Helper()
	if len(c.reqs) != 1 {
		t.Fatalf("capture never fired as expected: want exactly 1 PUT, got %d", len(c.reqs))
	}
	return c.reqs[0]
}

// testClient is the HTTPClient-swap seam itself: a REAL *s3.Client — real
// serializer, real deserializer, real paginator — whose only fake part is the
// transport. Shared with list_pagination_test.go so there is exactly one fake
// client construction in the package.
func testClient(o Options, tr s3.HTTPClient) *Client {
	cl := s3.New(s3.Options{
		Region: "us-east-1",
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test", Source: "s3land test"}, nil
		}),
		HTTPClient:   tr,
		BaseEndpoint: aws.String("https://s3.invalid"),
		UsePathStyle: true,
	})
	return &Client{s3: cl, opt: o}
}

func capturingClient(o Options) (*Client, *putCapture) {
	cap := &putCapture{}
	return testClient(o, cap), cap
}

const (
	sseHeader = "X-Amz-Server-Side-Encryption"
	kmsHeader = "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"
)

// TestLandEncryptsUnderPerTenantKMSKey is FR-SPINE-010's core claim: the key id
// on the landing PUT is derived from the STAMPED tenant, so two tenants never
// share a CMK. Asserting "the header is non-empty" would pass a hardcoded
// constant — which is exactly the defect worth catching — so the differ-check
// between two tenants is the load-bearing assertion here.
func TestLandEncryptsUnderPerTenantKMSKey(t *testing.T) {
	const prefix = "alias/mark1-tenant-"
	opt := Options{Bucket: "mark1-ingest", KMSAliasPrefix: prefix}
	tenantA := uuid.MustParse("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	tenantB := uuid.MustParse("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
	batch := uuid.MustParse("0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01")
	device := uuid.MustParse("dddddddd-3333-4333-8333-dddddddddddd")

	land := func(tenant uuid.UUID) *http.Request {
		t.Helper()
		c, cap := capturingClient(opt)
		key := IngestKey(tenant, batch)
		out, err := c.Land(context.Background(), key, []byte("payload"), tenant, device)
		if err != nil {
			t.Fatalf("Land(%s): %v", tenant, err)
		}
		if out != Landed {
			t.Fatalf("Land(%s) outcome = %v, want Landed", tenant, out)
		}
		req := cap.only(t)
		// Anti-vacuity: this is the PUT we asked for, not some other call.
		if req.Method != http.MethodPut {
			t.Fatalf("captured a %s, not the landing PUT", req.Method)
		}
		if !strings.Contains(req.URL.Path, opt.Bucket) || !strings.Contains(req.URL.Path, key) {
			t.Fatalf("captured request is not the landing of %s: %s", key, req.URL.Path)
		}
		return req
	}

	reqA, reqB := land(tenantA), land(tenantB)
	kmsA, kmsB := reqA.Header.Get(kmsHeader), reqB.Header.Get(kmsHeader)

	// t.Errorf, not Fatalf: a regression should report every property it broke,
	// not just the first one.
	if got := reqA.Header.Get(sseHeader); got != "aws:kms" {
		t.Errorf("%s = %q, want aws:kms — the landing object is not KMS-encrypted (05 §2.2)", sseHeader, got)
	}
	if want := prefix + tenantA.String(); kmsA != want {
		t.Errorf("%s for tenant A = %q, want %q", kmsHeader, kmsA, want)
	}
	if want := prefix + tenantB.String(); kmsB != want {
		t.Errorf("%s for tenant B = %q, want %q", kmsHeader, kmsB, want)
	}
	// THE cross-tenant assertion: the tenant must actually be in the key.
	if kmsA == kmsB {
		t.Errorf("tenants A and B landed under the SAME KMS key %q — cross-tenant key reuse; "+
			"the per-tenant CMK boundary of 05 §2.2 is decorative", kmsA)
	}
	if strings.Contains(kmsA, tenantB.String()) || strings.Contains(kmsB, tenantA.String()) {
		t.Errorf("KMS key id carries the wrong tenant: A=%q B=%q", kmsA, kmsB)
	}
}

// TestLandDisableSSEKMSOmitsEncryptionHeaders proves the arm above is genuinely
// conditional (the MinIO escape hatch still escapes), not merely on by luck.
func TestLandDisableSSEKMSOmitsEncryptionHeaders(t *testing.T) {
	opt := Options{Bucket: "mark1-ingest", KMSAliasPrefix: "alias/mark1-tenant-", DisableSSEKMS: true}
	tenant := uuid.MustParse("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	batch := uuid.MustParse("0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01")
	key := IngestKey(tenant, batch)

	c, cap := capturingClient(opt)
	if _, err := c.Land(context.Background(), key, []byte("payload"), tenant, uuid.New()); err != nil {
		t.Fatal(err)
	}
	req := cap.only(t)
	if !strings.Contains(req.URL.Path, key) {
		t.Fatalf("captured request is not the landing of %s: %s", key, req.URL.Path)
	}
	for _, h := range []string{sseHeader, kmsHeader} {
		if got := req.Header.Get(h); got != "" {
			t.Errorf("DisableSSEKMS still sent %s = %q; MinIO lanes would 400", h, got)
		}
	}
}

// ADR-0011 §2: alias by tenant KIND from the enrollment seam; the assertion is the SSEKMSKeyId AWS would receive.
func TestLandSelectsKMSKeyByTenantKind(t *testing.T) {
	const prefix, pooled = "alias/mark1-tenant-", "alias/mark1-personal"
	org := uuid.MustParse("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	personal := uuid.MustParse("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
	batch := uuid.MustParse("0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01")
	kinds := map[uuid.UUID]string{org: "org", personal: "personal"}
	var asked []uuid.UUID
	opt := Options{Bucket: "mark1-ingest", KMSAliasPrefix: prefix, PersonalKMSAlias: pooled,
		TenantKind: func(_ context.Context, tenant uuid.UUID) (string, error) {
			asked = append(asked, tenant)
			return kinds[tenant], nil
		}}

	land := func(tenant uuid.UUID) string {
		t.Helper()
		c, cap := capturingClient(opt)
		key := IngestKey(tenant, batch)
		if out, err := c.Land(context.Background(), key, []byte("payload"), tenant, uuid.New()); err != nil || out != Landed {
			t.Fatalf("Land(%s): out %v, err %v", tenant, out, err)
		}
		req := cap.only(t)
		if req.Method != http.MethodPut || !strings.Contains(req.URL.Path, key) {
			t.Fatalf("captured %s %s, not the landing PUT of %s", req.Method, req.URL.Path, key)
		}
		if got := req.Header.Get(sseHeader); got != "aws:kms" {
			t.Errorf("%s = %q, want aws:kms", sseHeader, got)
		}
		return req.Header.Get(kmsHeader)
	}

	// An org tenant lands under ITS key and can never name the pooled one.
	if got := land(org); got != prefix+org.String() {
		t.Errorf("org tenant SSEKMSKeyId = %q, want %q", got, prefix+org.String())
	} else if strings.Contains(got, pooled) {
		t.Errorf("org tenant landed under the pooled personal key %q — ADR-0011 §1 broken", got)
	}
	// A personal tenant lands under the pooled key and never under alias/mark1-tenant-*.
	got := land(personal)
	if got != pooled {
		t.Errorf("personal tenant SSEKMSKeyId = %q, want %q", got, pooled)
	}
	if strings.Contains(got, prefix) || strings.Contains(got, personal.String()) {
		t.Errorf("personal tenant named a per-tenant key %q — a CMK the enrollment never created (ADR-0011 §2)", got)
	}
	// The kind came from the seam per stamped tenant, not a constant.
	if len(asked) != 2 || asked[0] != org || asked[1] != personal {
		t.Errorf("TenantKind consulted for %v, want [%s %s]", asked, org, personal)
	}
}

// Fail-closed: an unresolved kind refuses the landing and NOTHING is PUT — no fallback to either alias (ADR-0011 §2).
func TestLandRefusesUnresolvedTenantKind(t *testing.T) {
	const prefix, pooled = "alias/mark1-tenant-", "alias/mark1-personal"
	tenant := uuid.MustParse("cccccccc-3333-4333-8333-cccccccccccc")
	key := IngestKey(tenant, uuid.MustParse("0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01"))
	fixed := func(kind string, err error) func(context.Context, uuid.UUID) (string, error) {
		return func(context.Context, uuid.UUID) (string, error) { return kind, err }
	}
	cases := map[string]Options{
		"lookup_error":            {KMSAliasPrefix: prefix, PersonalKMSAlias: pooled, TenantKind: fixed("", errors.New("pg: connection refused"))},
		"empty_kind":              {KMSAliasPrefix: prefix, PersonalKMSAlias: pooled, TenantKind: fixed("", nil)},
		"unknown_kind":            {KMSAliasPrefix: prefix, PersonalKMSAlias: pooled, TenantKind: fixed("team", nil)},
		"personal_without_pool":   {KMSAliasPrefix: prefix, TenantKind: fixed("personal", nil)},
		"lookup_error_minio_lane": {KMSAliasPrefix: prefix, PersonalKMSAlias: pooled, DisableSSEKMS: true, TenantKind: fixed("", errors.New("pg: connection refused"))},
		"unknown_kind_minio_lane": {KMSAliasPrefix: prefix, PersonalKMSAlias: pooled, DisableSSEKMS: true, TenantKind: fixed("Personal", nil)},
	}
	for name, opt := range cases {
		t.Run(name, func(t *testing.T) {
			opt.Bucket = "mark1-ingest"
			c, cap := capturingClient(opt)
			out, err := c.Land(context.Background(), key, []byte("payload"), tenant, uuid.New())
			if !errors.Is(err, ErrTenantKind) {
				t.Fatalf("Land: out %v, err %v; want ErrTenantKind", out, err)
			}
			if len(cap.reqs) != 0 {
				t.Fatalf("landing refused but %d request(s) were still sent — a refused batch must leave NO partial state", len(cap.reqs))
			}
		})
	}
	// Positive control: the org branch still lands, so the refusals above are the kind check, not a broken fake.
	c, cap := capturingClient(Options{Bucket: "mark1-ingest", KMSAliasPrefix: prefix, PersonalKMSAlias: pooled, TenantKind: fixed("org", nil)})
	if out, err := c.Land(context.Background(), key, []byte("payload"), tenant, uuid.New()); err != nil || out != Landed {
		t.Fatalf("org control: out %v, err %v", out, err)
	}
	if got := cap.only(t).Header.Get(kmsHeader); got != prefix+tenant.String() {
		t.Fatalf("org control SSEKMSKeyId = %q", got)
	}
}

// A pooled alias with no kind seam is refused before any AWS call (ADR-0011 §2).
func TestOpenRefusesPooledAliasWithoutKindSeam(t *testing.T) {
	_, err := Open(context.Background(), Options{Bucket: "mark1-ingest", Endpoint: "https://s3.invalid",
		KMSAliasPrefix: "alias/mark1-tenant-", PersonalKMSAlias: "alias/mark1-personal"})
	if err == nil || !strings.Contains(err.Error(), "TenantKind") || !strings.Contains(err.Error(), "ADR-0011") {
		t.Fatalf("Open with PersonalKMSAlias and no TenantKind: err %v; want a refusal naming TenantKind and ADR-0011", err)
	}
}
