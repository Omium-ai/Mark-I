// Package s3land is stage 8 of the ingest pipeline: the S3-first landing
// (05 §2.2). The governing invariant, from the frozen plan: the ack happens
// ONLY after the batch object lands durably in S3, and that object IS the
// replay log — everything downstream is a rebuildable view, everything
// upstream is stateless.
package s3land

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
)

// Outcome is the three-way result of the conditional PUT (05 §2.2).
type Outcome int

const (
	// Landed: first landing; proceed to ack.
	Landed Outcome = iota
	// Duplicate: the key already holds these exact bytes — a re-POST of an
	// acked batch (08 §2.3); ack again, cheaply, with no side effects.
	Duplicate
	// Divergent: the key holds DIFFERENT bytes — edge spool corruption;
	// 409 M1E-2003, and we never overwrite a landed batch.
	Divergent
	// NotLanded (Probe only): no object at the key; a first landing is still
	// available.
	NotLanded
)

// Store is the landing seam ingest and replay consume; the AWS client below
// implements it, unit tests fake it.
type Store interface {
	// Land conditionally PUTs body at key under the tenant's KMS key. The
	// device stamp rides as object metadata: the landing object is the
	// replay log, and replay (05 §2.5) must re-stamp device_id without a
	// token to read it from. Any error means the batch has NOT landed: no
	// partial state exists.
	Land(ctx context.Context, key string, body []byte, tenant, device uuid.UUID) (Outcome, error)
	// Probe reports whether key already holds a landed object and, if so,
	// whether its bytes match body — without writing anything. The pipeline's
	// quarantine path uses it to see a batch that first landed under the
	// ingest prefix before a scanner-ruleset change (08 §2.3: a re-POST must
	// get the original response, never a second landing).
	Probe(ctx context.Context, key string, body []byte) (Outcome, error)
	// Ready is the ingest readiness contributor's S3 half (05 §1.4):
	// a cached (≤30 s) HeadBucket.
	Ready(ctx context.Context) error
	// List returns the keys under prefix, lexicographic — which for the key
	// scheme below approximates chronological replay order by design (05 §2.5).
	List(ctx context.Context, prefix string) ([]string, error)
	// Get fetches a landed object, its device stamp and when it landed (the replay log is written once, at receipt: replay's received_at, ADR-0013).
	Get(ctx context.Context, key string) ([]byte, uuid.UUID, time.Time, error)
	// Delete removes key; a missing key is not an error (the sweep receipts what it observed, 07 §S3 layout).
	Delete(ctx context.Context, key string) error
}

// quarantineTag is what 09's lifecycle rule filters on: prefixes cannot wildcard the tenant segment, the tag can.
const quarantineTag = "class=quarantine"

// contributionTag carries the 12-month contribution expiry (09 lifecycle rule "contribution-ttl").
const contributionTag = "class=contribution"

// evidenceTag carries the 32 d E1 backstop expiry (09 lifecycle rule "evidence-ttl"); the sweep deletes at 30 d, receipted.
const evidenceTag = "class=evidence"

// batchTime is the uuidv7 batch_id's embedded millisecond timestamp — the
// batch's own creation time, validated as v7 at stage 1 before any key exists.
func batchTime(batchID uuid.UUID) time.Time {
	sec, nsec := batchID.Time().UnixTime()
	return time.Unix(sec, nsec).UTC()
}

// IngestKey derives the landing key (05 §2.2, 07 S3 layout). <tenant> comes
// from the stage-3 stamp, never the envelope. dt/hh derive from the uuidv7
// batch_id's embedded timestamp, NOT from the receiving wall clock: 07's
// layout ("batch_uuidv7 in the key ⇒ idempotent re-PUT on retry") and
// 08 §2.3 (a re-POST detects the already-landed object) both require
// batch_id→key to be a pure function, and a receipt-time key breaks exactly
// at hour boundaries — the common lost-ack retry case under 08 §2.5's
// 6s..30min backoff. The same derivation keeps lexicographic listing ≈
// chronological replay order (05 §2.5) by construction. A skewed edge clock
// can misfile a batch's dt= partition, which costs replay-listing accuracy
// only — projection and dedupe key on event_id, never on the key's date.
func IngestKey(tenant uuid.UUID, batchID uuid.UUID) string {
	t := batchTime(batchID)
	return fmt.Sprintf("t/%s/ingest/v1/dt=%s/hh=%02d/%s.m1p.zst",
		tenant, t.Format("2006-01-02"), t.Hour(), batchID)
}

// QuarantineKey derives the quarantine key (05 §2.3): a DIFFERENT prefix, not
// a tag, because the ingest prefix is replayed mechanically and a secret in
// the replay log would resurface on every rebuild forever. dt= derives from
// the batch_id for the same determinism reasons as IngestKey.
func QuarantineKey(tenant uuid.UUID, batchID uuid.UUID) string {
	return fmt.Sprintf("t/%s/quarantine/v1/dt=%s/%s.m1p.zst",
		tenant, batchTime(batchID).Format("2006-01-02"), batchID)
}

// IngestPrefix is the replay lister's entry point for a tenant + day (05 §2.5).
func IngestPrefix(tenant uuid.UUID, day time.Time) string {
	return fmt.Sprintf("t/%s/ingest/v1/dt=%s/", tenant, day.UTC().Format("2006-01-02"))
}

// ContributionKey lands a consented OutcomeContribution batch (16 L8) outside the replay log's own prefix, so withdrawal can delete it; same batch_id purity as IngestKey.
func ContributionKey(tenant uuid.UUID, batchID uuid.UUID) string {
	t := batchTime(batchID)
	return fmt.Sprintf("t/%s/contributions/v1/dt=%s/hh=%02d/%s.m1p.zst",
		tenant, t.Format("2006-01-02"), t.Hour(), batchID)
}

// ContributionPrefix is replay's second lister for a tenant + day.
func ContributionPrefix(tenant uuid.UUID, day time.Time) string {
	return fmt.Sprintf("t/%s/contributions/v1/dt=%s/", tenant, day.UTC().Format("2006-01-02"))
}

// EvidenceKey lands a task's E1 part (08 §2.1) under the tenant's evidence prefix; one part per task makes the key a pure function of (tenant, task).
func EvidenceKey(tenant, task uuid.UUID) string {
	return fmt.Sprintf("t/%s/evidence/v1/%s.e1", tenant, task)
}

// EvidenceQuarantineKey is a flagged E1 part's twin: the quarantine prefix, so the 30 d sweep and the lifecycle backstop own it.
func EvidenceQuarantineKey(tenant, task uuid.UUID, at time.Time) string {
	return fmt.Sprintf("t/%s/quarantine/v1/dt=%s/e1-%s.bin", tenant, at.UTC().Format("2006-01-02"), task)
}

// ---------------------------------------------------------------------------
// AWS implementation
// ---------------------------------------------------------------------------

type Options struct {
	Bucket string
	// Endpoint overrides the AWS resolver for the dev/compose MinIO stack
	// (13 §11 C4). Path-style addressing is implied when set.
	Endpoint       string
	KMSAliasPrefix string // "alias/mark1-tenant-" (05 §2.2), kind='org' tenants
	// PersonalKMSAlias is the one pooled key for kind='personal' (ADR-0011 §2); "" refuses every personal landing.
	PersonalKMSAlias string
	// TenantKind reads "org" | "personal" from the tenant row, never the request (ADR-0011 §2); nil ⇒ all org.
	TenantKind func(ctx context.Context, tenant uuid.UUID) (string, error)
	// DisableSSEKMS exists ONLY for MinIO, which has no KMS. The R6 bucket-
	// policy probe and the kind lookup still run — the refusal shape is
	// preserved even where enforcement is cosmetic (05 §1.2: no --skip-checks).
	DisableSSEKMS bool
}

// ErrTenantKind: nothing landed; the pipeline answers 503 and the edge retries — never a fallback key (ADR-0011 §2).
var ErrTenantKind = errors.New("s3land: tenant kind unresolved, landing refused (ADR-0011)")

type Client struct {
	s3          *s3.Client
	opt         Options
	readyMu     sync.Mutex
	readyAt     time.Time
	readyErr    error
	readyProbed bool
}

// Open builds the client and runs boot refusal R6 (05 §1.2): HeadBucket on
// the ingest bucket, then the bucket-policy probe for the per-tenant-KMS deny
// statement — the "cross-tenant encryption is a write failure" property §2
// assumes; run without it and every ack is a false promise.
func Open(ctx context.Context, o Options) (*Client, error) {
	if o.PersonalKMSAlias != "" && o.TenantKind == nil {
		return nil, errors.New("s3land: PersonalKMSAlias set without a TenantKind seam — the pooled key would be unreachable by kind and reachable by accident (ADR-0011 §2)")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("s3land: aws config: %w", err)
	}
	cl := s3.NewFromConfig(awsCfg, func(s3o *s3.Options) {
		if o.Endpoint != "" {
			s3o.BaseEndpoint = aws.String(o.Endpoint)
			s3o.UsePathStyle = true
		}
	})
	c := &Client{s3: cl, opt: o}
	if _, err := cl.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(o.Bucket)}); err != nil {
		return nil, fmt.Errorf("s3land: ingest bucket %q missing/unreachable (R6): %w", o.Bucket, err)
	}
	pol, err := cl.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(o.Bucket)})
	if err != nil {
		return nil, fmt.Errorf("s3land: bucket policy unreadable (R6 probe): %w", err)
	}
	if err := VerifyTenantKMSDeny(aws.ToString(pol.Policy), o.KMSAliasPrefix, o.PersonalKMSAlias); err != nil {
		return nil, fmt.Errorf("s3land: R6: %w", err)
	}
	return c, nil
}

// MustOpen is boot step 5 (05 §1.1); refusal crashloops on purpose.
func MustOpen(ctx context.Context, o Options) *Client {
	c, err := Open(ctx, o)
	if err != nil {
		log.Fatalf("s3land: boot refusal R6 (05 §1.2): %v", err)
	}
	return c
}

// VerifyTenantKMSDeny checks the bucket policy carries a Deny statement
// conditioned on the per-tenant KMS key prefix (05 §1.2 R6; the policy body
// itself is 07's) and, when personalAlias is set, a second Deny binding the
// pooled personal key to the t/* prefix (ADR-0011 §3). Structural, not
// string-equality: any Deny statement whose condition names the SSE-KMS key
// id and the alias satisfies it; the pooled statement must also scope t/*.
func VerifyTenantKMSDeny(policyJSON, aliasPrefix, personalAlias string) error {
	var doc struct {
		Statement []struct {
			Effect      string          `json:"Effect"`
			Resource    json.RawMessage `json:"Resource"`
			NotResource json.RawMessage `json:"NotResource"`
			Condition   json.RawMessage `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return fmt.Errorf("bucket policy is not parseable JSON: %w", err)
	}
	tenantDeny, pooledDeny := false, false
	for _, st := range doc.Statement {
		if st.Effect != "Deny" || len(st.Condition) == 0 {
			continue
		}
		cond := string(st.Condition)
		if !strings.Contains(cond, "s3:x-amz-server-side-encryption-aws-kms-key-id") {
			continue
		}
		if strings.Contains(cond, aliasPrefix) {
			tenantDeny = true
		}
		if personalAlias != "" && strings.Contains(cond, personalAlias) &&
			strings.Contains(string(st.Resource)+string(st.NotResource), "/t/*") {
			pooledDeny = true
		}
	}
	if !tenantDeny {
		return errors.New("bucket policy lacks the per-tenant-KMS Deny statement — a stamping bug upstream would become a cross-tenant write, not a write failure")
	}
	if personalAlias != "" && !pooledDeny {
		return fmt.Errorf("bucket policy lacks the Deny binding the pooled key %s to the t/* prefix (ADR-0011 §3)", personalAlias)
	}
	return nil
}

// kmsKeyFor: org ⇒ the tenant's own alias, personal ⇒ the pooled alias, anything else ⇒ refused (ADR-0011 §2).
func (c *Client) kmsKeyFor(ctx context.Context, tenant uuid.UUID) (string, error) {
	if c.opt.TenantKind == nil {
		return c.opt.KMSAliasPrefix + tenant.String(), nil
	}
	kind, err := c.opt.TenantKind(ctx, tenant)
	if err != nil {
		return "", fmt.Errorf("%w: tenant %s: %v", ErrTenantKind, tenant, err)
	}
	switch {
	case kind == "org":
		return c.opt.KMSAliasPrefix + tenant.String(), nil
	case kind == "personal" && c.opt.PersonalKMSAlias != "":
		return c.opt.PersonalKMSAlias, nil
	}
	return "", fmt.Errorf("%w: tenant %s kind %q (pooled alias %q)", ErrTenantKind, tenant, kind, c.opt.PersonalKMSAlias)
}

func (c *Client) Land(ctx context.Context, key string, body []byte, tenant, device uuid.UUID) (Outcome, error) {
	kmsKey, err := c.kmsKeyFor(ctx, tenant)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(body)
	shaB64 := base64.StdEncoding.EncodeToString(sum[:])
	in := &s3.PutObjectInput{
		Bucket:            aws.String(c.opt.Bucket),
		Key:               aws.String(key),
		Body:              bytes.NewReader(body),
		IfNoneMatch:       aws.String("*"), // conditional write: first landing wins, forever
		ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256,
		ChecksumSHA256:    aws.String(shaB64),
		Metadata:          map[string]string{"m1-device-id": device.String()},
	}
	if strings.Contains(key, "/quarantine/v1/") {
		in.Tagging = aws.String(quarantineTag)
	}
	if strings.Contains(key, "/contributions/v1/") {
		in.Tagging = aws.String(contributionTag)
	}
	if strings.Contains(key, "/evidence/v1/") {
		in.Tagging = aws.String(evidenceTag)
	}
	if !c.opt.DisableSSEKMS {
		in.ServerSideEncryption = s3types.ServerSideEncryptionAwsKms
		in.SSEKMSKeyId = aws.String(kmsKey)
	}
	_, err = c.s3.PutObject(ctx, in)
	if err == nil {
		// S3 returns 200 only after durable multi-AZ persistence — this
		// return IS the ack license (05 §2.2).
		return Landed, nil
	}
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 412 {
		return c.compareLanded(ctx, key, shaB64)
	}
	// Throttle, 5xx, KMS throttle: the batch has NOT landed; the caller
	// answers 503 and the edge retries under 08 §2.5. No partial state.
	return 0, fmt.Errorf("s3land: put %s: %w", key, err)
}

// Probe is the read-only duplicate check: NotLanded when the key is empty,
// otherwise the same checksum comparison a 412 resolves to. It exists for the
// pipeline's quarantine path only, so the HEAD never rides the clean hot path.
func (c *Client) Probe(ctx context.Context, key string, body []byte) (Outcome, error) {
	sum := sha256.Sum256(body)
	out, err := c.compareLanded(ctx, key, base64.StdEncoding.EncodeToString(sum[:]))
	if err != nil {
		var nf *s3types.NotFound
		var respErr *awshttp.ResponseError
		if errors.As(err, &nf) || (errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404) {
			return NotLanded, nil
		}
		return 0, err
	}
	return out, nil
}

// compareLanded resolves a 412: identical bytes ⇒ Duplicate (re-POST of an
// acked batch), different ⇒ Divergent (batch_id reuse = spool corruption).
func (c *Client) compareLanded(ctx context.Context, key, shaB64 string) (Outcome, error) {
	head, err := c.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:       aws.String(c.opt.Bucket),
		Key:          aws.String(key),
		ChecksumMode: s3types.ChecksumModeEnabled,
	})
	if err != nil {
		return 0, fmt.Errorf("s3land: head %s: %w", key, err)
	}
	existing := aws.ToString(head.ChecksumSHA256)
	if existing == "" {
		// Object landed without a stored checksum (shouldn't happen for our
		// own PUTs; possible for MinIO) — fall back to GET + hash.
		body, _, _, err := c.Get(ctx, key)
		if err != nil {
			return 0, err
		}
		sum := sha256.Sum256(body)
		existing = base64.StdEncoding.EncodeToString(sum[:])
	}
	if existing == shaB64 {
		return Duplicate, nil
	}
	return Divergent, nil
}

func (c *Client) Ready(ctx context.Context) error {
	c.readyMu.Lock()
	defer c.readyMu.Unlock()
	// ≤30 s cache (05 §1.4): readiness must not turn the LB's poll into an
	// S3 request storm.
	if c.readyProbed && time.Since(c.readyAt) < 30*time.Second {
		return c.readyErr
	}
	_, err := c.s3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(c.opt.Bucket)})
	c.readyProbed, c.readyAt, c.readyErr = true, time.Now(), err
	return err
}

func (c *Client) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	p := s3.NewListObjectsV2Paginator(c.s3, &s3.ListObjectsV2Input{
		Bucket: aws.String(c.opt.Bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("s3land: list %s: %w", prefix, err)
		}
		for _, o := range page.Contents {
			keys = append(keys, aws.ToString(o.Key))
		}
	}
	return keys, nil
}

// Delete is a plain DeleteObject: under versioning it writes a delete marker and the lifecycle's noncurrent
// expiry finishes the job, which is exactly the 32 d backstop 09 configures.
func (c *Client) Delete(ctx context.Context, key string) error {
	if _, err := c.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(c.opt.Bucket), Key: aws.String(key)}); err != nil {
		return fmt.Errorf("s3land: delete %s: %w", key, err)
	}
	return nil
}

func (c *Client) Get(ctx context.Context, key string) ([]byte, uuid.UUID, time.Time, error) {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.opt.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, uuid.Nil, time.Time{}, fmt.Errorf("s3land: get %s: %w", key, err)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, uuid.Nil, time.Time{}, fmt.Errorf("s3land: get %s: %w", key, err)
	}
	device := uuid.Nil
	if d, perr := uuid.Parse(out.Metadata["m1-device-id"]); perr == nil {
		device = d
	}
	return body, device, aws.ToTime(out.LastModified).UTC(), nil
}
