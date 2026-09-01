// Object lock on the witness head (m1_003 destination 2; 05 §4.4;
// FR-SPINE-019).
//
// Object lock is the whole product claim here: it is what turns "we uploaded a
// copy" into "nobody, including Omium and including the bucket owner, can
// remove it before this date" — verify Omium, don't trust Omium. Until this
// file, the only Publisher any test drove was integration_test.go's in-process
// fakePublisher, so witness_s3.go's ObjectLockMode/RetainUntilDate lines were
// reached by no test at all. Silently downgrading Compliance to Governance —
// which an administrator with the right permission CAN delete under — would
// have falsified the claim with CI still green.
//
// Same seam as s3land's sse_kms_test.go: s3.Options.HTTPClient lets the real
// *s3.Client run the real serializer over the real PutObjectInput Publish
// builds, then hands the finished request to a fake transport. No bucket, no
// object-lock configuration, no network. Zero production change — S3Publisher's
// fields are package-private and this test is in-package.

package receipts

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
)

type witnessPutCapture struct{ reqs []*http.Request }

func (c *witnessPutCapture) Do(r *http.Request) (*http.Response, error) {
	c.reqs = append(c.reqs, r)
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Etag": {`"w1tn3ss"`}},
		Body:   http.NoBody, Request: r,
	}, nil
}

// only fails loudly when the transport never fired. Every header assertion in
// this file runs only after it: reading a header off a request that was never
// made reports the same shape as a passing test.
func (c *witnessPutCapture) only(t *testing.T) *http.Request {
	t.Helper()
	if len(c.reqs) != 1 {
		t.Fatalf("capture never fired as expected: want exactly 1 witness PUT, got %d", len(c.reqs))
	}
	return c.reqs[0]
}

func capturingPublisher(o S3PublisherOptions) (*S3Publisher, *witnessPutCapture) {
	cap := &witnessPutCapture{}
	cl := s3.New(s3.Options{
		Region: "us-east-1",
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test", Source: "receipts test"}, nil
		}),
		HTTPClient:   cap,
		BaseEndpoint: aws.String("https://s3.invalid"),
		UsePathStyle: true,
	})
	return &S3Publisher{client: cl, opts: o}, cap
}

const (
	lockModeHeader   = "X-Amz-Object-Lock-Mode"
	lockRetainHeader = "X-Amz-Object-Lock-Retain-Until-Date"
)

// TestS3PublisherLocksHeadInCompliance drives the REAL publisher (not
// integration_test.go's fakePublisher) and asserts the two properties that make
// the witness evidence rather than decoration: the lock mode is COMPLIANCE
// specifically, and the retain-until date is the configured horizon past now.
func TestS3PublisherLocksHeadInCompliance(t *testing.T) {
	// The retention the publisher is CONFIGURED with; every date assertion below
	// is derived from it and from the injected clock, never from a constant
	// copied out of witness_s3.go.
	const retain = 37 * 24 * time.Hour
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	tenant := uuid.MustParse("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")

	p, cap := capturingPublisher(S3PublisherOptions{
		Bucket: "mark1-witness",
		Retain: retain,
		Now:    func() time.Time { return now },
	})
	dest, err := p.Publish(context.Background(), tenant, []byte(`{"seq":1}`), []byte{0xde, 0xad}, "key-1")
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// --- anti-vacuity gate: prove we captured OUR PUT before reading a header.
	req := cap.only(t)
	if req.Method != http.MethodPut {
		t.Fatalf("captured a %s, not the witness PUT", req.Method)
	}
	wantKey := "witness/heads/" + tenant.String() + "/"
	if !strings.Contains(req.URL.Path, "mark1-witness") || !strings.Contains(req.URL.Path, wantKey) {
		t.Fatalf("captured request is not the head publication for %s: %s", tenant, req.URL.Path)
	}
	if dest.BucketURI == nil || !strings.Contains(*dest.BucketURI, wantKey) {
		t.Fatalf("Destination does not name the object that was PUT: %+v", dest.BucketURI)
	}

	// --- FR-SPINE-019 property 1: COMPLIANCE, not merely non-empty.
	// GOVERNANCE is deletable by a principal holding
	// s3:BypassGovernanceRetention; accepting it here would make the
	// "verify Omium, don't trust Omium" claim false with CI green.
	if got := req.Header.Get(lockModeHeader); got != string(s3types.ObjectLockModeCompliance) {
		t.Errorf("%s = %q, want %q — a head Omium can still delete is not a witness",
			lockModeHeader, got, s3types.ObjectLockModeCompliance)
	}

	// --- FR-SPINE-019 property 2: retained by the CONFIGURED horizon.
	raw := req.Header.Get(lockRetainHeader)
	if raw == "" {
		t.Fatalf("no %s header: the object carries no retention at all", lockRetainHeader)
	}
	got, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("%s = %q is not RFC3339: %v", lockRetainHeader, raw, err)
	}
	if want := now.Add(retain); !got.Equal(want) {
		t.Errorf("%s = %s, want %s (publish time + the configured Retain of %s); "+
			"retention short of the configured horizon is silent evidence loss",
			lockRetainHeader, got.Format(time.RFC3339), want.Format(time.RFC3339), retain)
	}
	if !got.After(now) {
		t.Errorf("retain-until %s is not in the future of publish time %s — the lock expires on arrival",
			got.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	// The m1_witness_heads row must record the retention that was actually put
	// on the wire, or the ledger and the bucket disagree.
	if dest.RetainUntil == nil || !dest.RetainUntil.Equal(got) {
		t.Errorf("Destination.RetainUntil = %v, want the wire value %s", dest.RetainUntil, got.Format(time.RFC3339))
	}
}

// TestS3PublisherWithoutRetainOmitsObjectLock proves the lock is conditional on
// the configured horizon (the dev-MinIO escape in S3PublisherOptions.Retain's
// doc comment), so the test above is asserting a real branch and not a header
// the SDK always sends.
func TestS3PublisherWithoutRetainOmitsObjectLock(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	tenant := uuid.MustParse("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")

	p, cap := capturingPublisher(S3PublisherOptions{
		Bucket: "mark1-witness-dev",
		Retain: 0,
		Now:    func() time.Time { return now },
	})
	dest, err := p.Publish(context.Background(), tenant, []byte(`{"seq":1}`), []byte{0xde, 0xad}, "key-1")
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	req := cap.only(t)
	if !strings.Contains(req.URL.Path, "witness/heads/"+tenant.String()+"/") {
		t.Fatalf("captured request is not the head publication for %s: %s", tenant, req.URL.Path)
	}
	for _, h := range []string{lockModeHeader, lockRetainHeader} {
		if got := req.Header.Get(h); got != "" {
			t.Errorf("Retain=0 still sent %s = %q; a bucket without object lock 400s on it", h, got)
		}
	}
	if dest.RetainUntil == nil || !dest.RetainUntil.Equal(now) {
		t.Errorf("Destination.RetainUntil = %v, want the honest 'no retention' value %s", dest.RetainUntil, now)
	}
}
