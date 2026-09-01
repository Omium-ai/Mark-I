// Replay listing across an S3 page boundary (05 §2.5; FR-SPINE-010).
//
// FR-SPINE-010's acceptance clause is "an acked batch is reconstructable from
// S3 alone", and List is the whole replay path — replay.go:38 is its only
// production caller. S3 caps a ListObjectsV2 response at 1000 keys, so any
// tenant-day busier than that is served in pages, and List's paginator loop
// (s3land.go:295-303) is the only thing that fetches page 2.
//
// Nothing tested it. The integration lane lists exactly one object, and the
// unit tests never touched List at all: delete the loop, return page 1, and the
// suite stays green while replay silently drops every batch past the first
// page. Silent truncation is the worst shape this component can fail in —
// the customer is trying to PROVE capture, and the missing events look
// identical to events that were never sent.
//
// Technique is sse_kms_test.go's: swap s3.Options.HTTPClient (testClient) so a
// real *s3.Client runs the real ListObjectsV2Paginator against pages served
// from memory. No bucket, no network, no production change.

package s3land

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// pagedLister is an s3.HTTPClient that answers the i-th ListObjectsV2 request
// with pages[i], marking every page but the last truncated and handing out a
// NextContinuationToken. It records the continuation-token each request
// carried, so the test can prove the token was actually round-tripped rather
// than the second page arriving by luck.
type pagedLister struct {
	bucket, prefix string
	pages          [][]string
	seen           []string // continuation-token per request, in order
}

func (p *pagedLister) Do(r *http.Request) (*http.Response, error) {
	i := len(p.seen)
	p.seen = append(p.seen, r.URL.Query().Get("continuation-token"))
	if i >= len(p.pages) {
		// Loud, not silent: a paginator that re-asks forever is as broken as
		// one that stops early.
		return nil, fmt.Errorf("List requested page %d but the fake only has %d pages — pagination is looping", i+1, len(p.pages))
	}
	next := ""
	if i < len(p.pages)-1 {
		next = fmt.Sprintf("token-page-%d", i+2)
	}
	body := listBucketResultXML(p.bucket, p.prefix, p.pages[i], next)
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": {"application/xml"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       r,
	}, nil
}

// listBucketResultXML is S3's ListObjectsV2 response on the wire. The real SDK
// deserializer parses it, so IsTruncated/NextContinuationToken mean here
// exactly what they mean against AWS.
func listBucketResultXML(bucket, prefix string, keys []string, nextToken string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	fmt.Fprintf(&b, "<Name>%s</Name><Prefix>%s</Prefix><MaxKeys>1000</MaxKeys><KeyCount>%d</KeyCount>",
		bucket, prefix, len(keys))
	if nextToken == "" {
		b.WriteString("<IsTruncated>false</IsTruncated>")
	} else {
		fmt.Fprintf(&b, "<IsTruncated>true</IsTruncated><NextContinuationToken>%s</NextContinuationToken>", nextToken)
	}
	for _, k := range keys {
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>7</Size><StorageClass>STANDARD</StorageClass></Contents>", k)
	}
	b.WriteString("</ListBucketResult>")
	return b.String()
}

var listTenant = uuid.MustParse("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")

// replayKeys builds n landing keys under the tenant-day prefix, distinguishable
// by the batch uuid's last hex digits: page-1 keys and page-2 keys can never be
// confused for each other, so returning only page 1 cannot accidentally pass.
func replayKeys(prefix string, ids ...string) []string {
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = prefix + "hh=16/0191c2f3-7a10-7cc3-b1aa-" + id + ".m1p.zst"
	}
	return keys
}

func TestListCrossesAPageBoundary(t *testing.T) {
	const bucket = "mark1-ingest"
	prefix := IngestPrefix(listTenant, batchTime(uuid.MustParse("0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01")))

	page1 := replayKeys(prefix, "a00000000001", "a00000000002", "a00000000003")
	page2 := replayKeys(prefix, "b00000000001", "b00000000002")
	want := slices.Concat(page1, page2)

	fake := &pagedLister{bucket: bucket, prefix: prefix, pages: [][]string{page1, page2}}
	got, err := testClient(Options{Bucket: bucket}, fake).List(context.Background(), prefix)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	// THE assertion: the union, not the first page. Ordered, because 05 §2.5
	// leans on lexicographic listing ≈ chronological replay order.
	if !slices.Equal(got, want) {
		missing := 0
		for _, k := range page2 {
			if !slices.Contains(got, k) {
				missing++
			}
		}
		t.Fatalf("replay listing TRUNCATED at the page boundary: got %d objects, want %d "+
			"(%d of page 2's %d keys missing).\nAn acked batch past the first page is not "+
			"reconstructable from S3 — FR-SPINE-010's acceptance clause fails silently.\n got: %v\nwant: %v",
			len(got), len(want), missing, len(page2), got, want)
	}

	// Anti-vacuity on the fake: page 2 came from a SECOND request that carried
	// the token page 1 handed out — not from one oversized canned response.
	if len(fake.seen) != 2 {
		t.Fatalf("ListObjectsV2 requests = %d, want 2 (one per page)", len(fake.seen))
	}
	if fake.seen[0] != "" {
		t.Errorf("first request already carried continuation-token %q; the paginator should start unpositioned", fake.seen[0])
	}
	if fake.seen[1] != "token-page-2" {
		t.Errorf("second request continuation-token = %q, want %q — the token from page 1 was not propagated",
			fake.seen[1], "token-page-2")
	}
}

// TestListSinglePageReturnsEveryKey is the positive control: with one
// non-truncated page the same fake yields exactly its keys in one request. If
// this fails too, the failure above is a broken fake, not a broken paginator.
func TestListSinglePageReturnsEveryKey(t *testing.T) {
	const bucket = "mark1-ingest"
	prefix := IngestPrefix(listTenant, batchTime(uuid.MustParse("0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01")))
	want := replayKeys(prefix, "c00000000001", "c00000000002")

	fake := &pagedLister{bucket: bucket, prefix: prefix, pages: [][]string{want}}
	got, err := testClient(Options{Bucket: bucket}, fake).List(context.Background(), prefix)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("single-page List = %v, want %v", got, want)
	}
	if len(fake.seen) != 1 {
		t.Errorf("ListObjectsV2 requests = %d, want 1 — an untruncated page must not be re-fetched", len(fake.seen))
	}
}
