//go:build integration && chaos

package policydist

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// flakyHeadSigner is the transparency log's key class going away: every head
// signature fails while down, which is the append the publication transaction
// cannot commit without.
type flakyHeadSigner struct {
	SectionSigner
	down atomic.Bool
}

func (f *flakyHeadSigner) Sign(b []byte) ([]byte, error) {
	if f.down.Load() {
		return nil, errors.New("tlog: log key unavailable (chaos)")
	}
	return f.SectionSigner.Sign(b)
}

// streamHints tails one SSE stream and counts bundle hints by seq.
func streamHints(t *testing.T, h *itHarness) (hints func() []string, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.api.URL+"/api/v1/policy/stream?channel=stable", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.tokenA1)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	var mu sync.Mutex
	var seen []string
	go func() {
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		event := ""
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event:"):
				event = strings.TrimSpace(line[6:])
			case strings.HasPrefix(line, "data:") && event == "bundle":
				mu.Lock()
				seen = append(seen, strings.TrimSpace(line[5:]))
				mu.Unlock()
			}
		}
	}()
	return func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), seen...)
		}, func() {
			cancel()
		}
}

func (h *itHarness) getBundle(t *testing.T, etag string) (status int, gotETag, seq, proof string, body []byte) {
	t.Helper()
	hdr := map[string]string{}
	if etag != "" {
		hdr["If-None-Match"] = etag
	}
	resp := h.req(http.MethodGet, "/api/v1/policy/bundle?channel=stable", h.tokenA1, nil, hdr)
	defer itClose(resp)
	body, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("ETag"), resp.Header.Get("X-Mark1-Bundle-Seq"), resp.Header.Get("X-Mark1-Tlog-Proof"), body
}

// leavesAndHeads reads the log as the witness would: every leaf in index
// order and every signed head, straight off the table owner's view.
func (h *itHarness) leavesAndHeads(t *testing.T) (leaves [][]byte, heads []struct {
	size int64
	root []byte
	sig  []byte
}) {
	t.Helper()
	ctx := context.Background()
	rows, err := h.admin.Query(ctx, `SELECT leaf_hash FROM tlog_leaves WHERE tenant_id = $1 ORDER BY leaf_index`, h.tenantAID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var l []byte
		if err := rows.Scan(&l); err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, l)
	}
	rows.Close()
	rows, err = h.admin.Query(ctx, `SELECT tree_size, root_hash, signature FROM tlog_signed_heads WHERE tenant_id = $1 ORDER BY tree_size`, h.tenantAID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var hd struct {
			size int64
			root []byte
			sig  []byte
		}
		if err := rows.Scan(&hd.size, &hd.root, &hd.sig); err != nil {
			t.Fatal(err)
		}
		heads = append(heads, hd)
	}
	rows.Close()
	return leaves, heads
}

// TestChaosTlogOutagePublicationHalts is 05 §9's transparency-log row.
func TestChaosTlogOutagePublicationHalts(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	fs := &flakyHeadSigner{SectionSigner: h.mod.store.headSigner}
	h.mod.store.headSigner = fs
	logPub := fs.Public()

	hints, stopStream := streamHints(t, h)
	defer stopStream()
	first, err := h.mod.Publish(ctx, h.tenantA, h.draft("stable"))
	if err != nil {
		t.Fatalf("publish before the outage: %v", err)
	}
	status, etag1, seq1, proof1, body1 := h.getBundle(t, "")
	if status != http.StatusOK || etag1 != first.ETag || seq1 != "1" || proof1 == "" {
		t.Fatalf("GET before the outage: %d etag %q seq %q proof %q", status, etag1, seq1, proof1)
	}
	served1, err := Unmarshal(body1)
	if err != nil || served1.Inclusion == nil {
		t.Fatalf("served seq 1 does not decode with an inclusion proof: %v", err)
	}
	waitHints := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for len(hints()) < want && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitHints(1)
	if got := hints(); len(got) != 1 {
		t.Fatalf("stream hints after one publication: %v, want exactly one", got)
	}
	counts := func() map[string]int64 {
		out := map[string]int64{}
		for _, tbl := range []string{"tlog_leaves", "tlog_signed_heads", "policy_bundles", "m1_receipts"} {
			out[tbl] = h.adminCount(tbl)
		}
		return out
	}
	before := counts()
	headBefore := h.headSeq("stable")

	// ---- the outage: three publications, none may burn a seq or become servable.
	fs.down.Store(true)
	for i := 0; i < 3; i++ {
		if _, err := h.mod.Publish(ctx, h.tenantA, h.draft("stable")); err == nil {
			t.Fatalf("publication %d succeeded with the transparency log down (05 §4.1: never servable before logged)", i)
		}
	}
	if after := counts(); after["tlog_leaves"] != before["tlog_leaves"] || after["tlog_signed_heads"] != before["tlog_signed_heads"] ||
		after["policy_bundles"] != before["policy_bundles"] || after["m1_receipts"] != before["m1_receipts"] {
		t.Fatalf("a failed publication left rows behind: before %v after %v", before, after)
	}
	if got := h.headSeq("stable"); got != headBefore {
		t.Fatalf("head_seq moved %d→%d on a publication that never committed: the chain burned a sequence number", headBefore, got)
	}
	status, etag, seq, proof, body := h.getBundle(t, "")
	if status != http.StatusOK || etag != etag1 || seq != "1" || proof != proof1 || string(body) != string(body1) {
		t.Fatalf("GET during the outage: %d etag %q seq %q — the edge must keep being served seq 1 with its proof", status, etag, seq)
	}
	if status, _, _, _, _ := h.getBundle(t, etag1); status != http.StatusNotModified {
		t.Fatalf("conditional GET during the outage: %d, want 304 (last-known-good unchanged)", status)
	}
	time.Sleep(300 * time.Millisecond)
	if got := hints(); len(got) != 1 {
		t.Fatalf("stream hints during the outage: %v — a hint for a bundle that never committed sends the fleet to fetch nothing", got)
	}

	// ---- heal: publication resumes at seq 2 on a log that grew by exactly one leaf.
	fs.down.Store(false)
	second, err := h.mod.Publish(ctx, h.tenantA, h.draft("stable"))
	if err != nil {
		t.Fatalf("publish after the heal: %v", err)
	}
	if second.Seq != 2 || second.TreeSize != 2 || second.TLogIndex != 1 {
		t.Fatalf("post-heal publication: seq %d tree %d leaf %d, want 2/2/1 — the failed attempts left a gap", second.Seq, second.TreeSize, second.TLogIndex)
	}
	status, etag2, seq2, _, body2 := h.getBundle(t, etag1)
	if status != http.StatusOK || etag2 != second.ETag || seq2 != "2" {
		t.Fatalf("GET after the heal: %d etag %q seq %q", status, etag2, seq2)
	}
	served2, err := Unmarshal(body2)
	if err != nil || served2.Inclusion == nil {
		t.Fatalf("served seq 2 does not decode with an inclusion proof: %v", err)
	}
	waitHints(2)
	if got := hints(); len(got) != 2 || !strings.Contains(got[0], `"seq":1`) || !strings.Contains(got[1], `"seq":2`) {
		t.Fatalf("stream hints after the heal: %v, want the seq-2 hint and nothing from the outage", got)
	}

	// Witness continuity: both served proofs verify against their own heads, the
	// old head is the root of the new log's prefix, and every signed head verifies
	// under the log key across the gap.
	leaves, heads := h.leavesAndHeads(t)
	if len(leaves) != 2 || len(heads) != 2 {
		t.Fatalf("log holds %d leaves and %d signed heads, want 2 and 2", len(leaves), len(heads))
	}
	for i, served := range []*Bundle{served1, served2} {
		incl := served.Inclusion
		leaf := sha256.Sum256(mustCanonicalBody(t, served))
		if string(leaf[:]) != string(leaves[i]) {
			t.Fatalf("served seq %d: body hash is not leaf %d of the log", i+1, i)
		}
		if !VerifyInclusion(leaf[:], incl.LeafIndex, incl.TreeSize, incl.AuditPath, [32]byte(incl.RootHash)) {
			t.Fatalf("served seq %d: inclusion proof does not verify against its root", i+1)
		}
		if incl.LeafIndex != uint64(i) || incl.TreeSize != uint64(i)+1 { //nolint:gosec // G115: i is 0 or 1
			t.Fatalf("served seq %d claims leaf %d of %d", i+1, incl.LeafIndex, incl.TreeSize)
		}
	}
	oldRoot, err := MerkleRoot(leaves[:1])
	if err != nil {
		t.Fatal(err)
	}
	if string(oldRoot[:]) != string(served1.Inclusion.RootHash) || string(heads[0].root) != string(oldRoot[:]) {
		t.Fatal("the pre-outage head is not the root of the post-outage log's prefix: the log was rewritten across the gap")
	}
	newRoot, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if string(newRoot[:]) != string(served2.Inclusion.RootHash) || string(heads[1].root) != string(newRoot[:]) {
		t.Fatal("the post-heal head is not the root over both leaves")
	}
	for _, hd := range heads {
		input, err := TLogHeadSigningInput(h.tenantAID, uint64(hd.size), [32]byte(hd.root)) //nolint:gosec // G115: tree_size is 1 or 2
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(logPub, input, hd.sig) {
			t.Fatalf("signed head at size %d does not verify under the log key", hd.size)
		}
	}
	// The receipt chain kept its own continuity: exactly one publication receipt per committed seq.
	if after := counts(); after["m1_receipts"] != before["m1_receipts"]+1 || after["policy_bundles"] != 2 {
		t.Fatalf("after the heal: %v, want one more receipt and two bundles", after)
	}
	t.Logf("chaos_tlog_outage: 3 publications refused with the log key down (no seq burned, seq 1 served with its proof, no hint); seq 2 published on heal at leaf 1 of 2, both heads verify, old head == root(prefix)")
}

func mustCanonicalBody(t *testing.T, b *Bundle) []byte {
	t.Helper()
	body, err := CanonicalBody(b)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
