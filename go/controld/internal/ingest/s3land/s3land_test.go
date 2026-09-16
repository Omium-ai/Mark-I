package s3land

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIngestKeyLayout(t *testing.T) {
	tenant := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	// uuidv7 with embedded timestamp 2024-09-05T16:10:22.096Z — dt/hh MUST
	// come from it, never from a wall clock, or the 08 §2.3 idempotent
	// re-PUT breaks at every hour boundary.
	batch := uuid.MustParse("0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01")
	want := "t/11111111-2222-3333-4444-555555555555/ingest/v1/dt=2024-09-05/hh=16/0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01.m1p.zst"
	if got := IngestKey(tenant, batch); got != want {
		t.Fatalf("key layout drifted from 05 §2.2 / 07 S3 layout:\n got %s\nwant %s", got, want)
	}
	q := QuarantineKey(tenant, batch)
	if !strings.Contains(q, "/quarantine/v1/dt=2024-09-05/") || strings.Contains(q, "/ingest/") {
		t.Fatalf("quarantine key must live under its own never-replayed prefix: %s", q)
	}
	if !strings.HasPrefix(IngestKey(tenant, batch), IngestPrefix(tenant, time.Date(2024, 9, 5, 0, 0, 0, 0, time.UTC))) {
		t.Fatal("IngestPrefix must prefix IngestKey (the §2.5 replay lister)")
	}
}

func TestVerifyTenantKMSDeny(t *testing.T) {
	const goodPolicy = `{
	  "Version": "2012-10-17",
	  "Statement": [
	    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
	    {"Effect": "Deny", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::mark1-ingest/t/*",
	     "Condition": {"StringNotLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "*alias/mark1-tenant-*"}}}
	  ]}`
	if err := VerifyTenantKMSDeny(goodPolicy, "alias/mark1-tenant-", ""); err != nil {
		t.Fatalf("valid policy refused: %v", err)
	}

	cases := map[string]string{
		"no_deny":        `{"Statement":[{"Effect":"Allow","Condition":{"StringNotLike":{"s3:x-amz-server-side-encryption-aws-kms-key-id":"*alias/mark1-tenant-*"}}}]}`,
		"deny_wrong_key": `{"Statement":[{"Effect":"Deny","Condition":{"StringNotLike":{"s3:x-amz-acl":"private"}}}]}`,
		"wrong_alias":    `{"Statement":[{"Effect":"Deny","Condition":{"StringNotLike":{"s3:x-amz-server-side-encryption-aws-kms-key-id":"*alias/other-*"}}}]}`,
		"not_json":       `nope`,
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			if err := VerifyTenantKMSDeny(policy, "alias/mark1-tenant-", ""); err == nil {
				t.Fatal("R6 probe passed a policy without the per-tenant-KMS deny")
			}
		})
	}
}

// R6 extension (ADR-0011 §3): with a pooled alias configured, boot also demands a t/*-scoped Deny naming it.
func TestVerifyPooledKMSDeny(t *testing.T) {
	const tenantDeny = `{"Effect": "Deny", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::mark1-ingest/t/*",
	     "Condition": {"StringNotLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": ["*alias/mark1-tenant-*", "*alias/mark1-personal"]}}}`
	const pooledDeny = `{"Effect": "Deny", "Action": "s3:PutObject", "NotResource": "arn:aws:s3:::mark1-ingest/t/*",
	     "Condition": {"StringLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "*alias/mark1-personal"}}}`
	both := `{"Version": "2012-10-17", "Statement": [` + tenantDeny + `, ` + pooledDeny + `]}`
	if err := VerifyTenantKMSDeny(both, "alias/mark1-tenant-", "alias/mark1-personal"); err != nil {
		t.Fatalf("valid two-statement policy refused: %v", err)
	}
	// MinIO cannot store NotResource; the Resource-scoped form the dev stack round-trips must pass too.
	resourceForm := `{"Statement": [` + tenantDeny + `, {"Effect": "Deny", "Resource": ["arn:aws:s3:::mark1-ingest/t/*"],
	     "Condition": {"StringNotLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "*alias/mark1-personal"}}}]}`
	if err := VerifyTenantKMSDeny(resourceForm, "alias/mark1-tenant-", "alias/mark1-personal"); err != nil {
		t.Fatalf("Resource-scoped pooled deny refused: %v", err)
	}

	cases := map[string]string{
		"pooled_absent":       `{"Statement": [{"Effect": "Deny", "Resource": "arn:aws:s3:::mark1-ingest/t/*", "Condition": {"StringNotLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "*alias/mark1-tenant-*"}}}]}`,
		"pooled_allow_only":   `{"Statement": [{"Effect": "Deny", "Resource": "arn:aws:s3:::mark1-ingest/t/*", "Condition": {"StringNotLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "*alias/mark1-tenant-*"}}}, {"Effect": "Allow", "Resource": "arn:aws:s3:::mark1-ingest/t/*", "Condition": {"StringLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "*alias/mark1-personal"}}}]}`,
		"pooled_not_prefixed": `{"Statement": [{"Effect": "Deny", "Resource": "arn:aws:s3:::mark1-ingest/t/*", "Condition": {"StringNotLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "*alias/mark1-tenant-*"}}}, {"Effect": "Deny", "Resource": "arn:aws:s3:::mark1-ingest/*", "Condition": {"StringLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "*alias/mark1-personal"}}}]}`,
		"pooled_wrong_alias":  `{"Statement": [{"Effect": "Deny", "Resource": "arn:aws:s3:::mark1-ingest/t/*", "Condition": {"StringNotLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "*alias/mark1-tenant-*"}}}, {"Effect": "Deny", "NotResource": "arn:aws:s3:::mark1-ingest/t/*", "Condition": {"StringLike": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "*alias/mark1-shared"}}}]}`,
		"tenant_absent":       `{"Statement": [` + pooledDeny + `]}`,
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			err := VerifyTenantKMSDeny(policy, "alias/mark1-tenant-", "alias/mark1-personal")
			if err == nil {
				t.Fatal("R6 probe booted a policy that does not bind the pooled personal key to t/*")
			}
			if name != "tenant_absent" && !strings.Contains(err.Error(), "ADR-0011") {
				t.Fatalf("refusal must name ADR-0011 so the operator finds the statement to add: %v", err)
			}
		})
	}
	// Unset alias ⇒ pre-ADR posture: the pooled statement is not demanded.
	for name, policy := range cases {
		if name == "tenant_absent" {
			continue
		}
		if err := VerifyTenantKMSDeny(policy, "alias/mark1-tenant-", ""); err != nil {
			t.Fatalf("%s: with no pooled alias configured the per-tenant deny alone must boot: %v", name, err)
		}
	}
}
