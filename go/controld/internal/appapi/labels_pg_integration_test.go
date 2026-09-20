//go:build integration

package appapi

// Human gold labels under FORCE RLS: a closed task is labeled into the tenant's open set with m1_021's digest, a relabel updates in place, an open or unknown task is refused, and tenant B sees none of it.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
)

func TestHumanLabelsFormTheGoldSet(t *testing.T) {
	r := setupPG(t)
	tenantA, tenantB := r.tenant("labels-a", "us-east-1"), r.tenant("labels-b", "us-east-1")
	deviceA := uuid.New()
	tokA := auth.Mint([]byte(testKey), tenantA, deviceA, time.Hour)
	tokB := auth.Mint([]byte(testKey), tenantB, uuid.New(), time.Hour)
	session, task := uuid.New(), uuid.New()
	body := func(label string) string {
		b, _ := json.Marshal(map[string]string{"session_id": session.String(), "task_id": task.String(), "label": label})
		return string(b)
	}

	// Unknown to the ledger: refused, nothing written.
	if code, out := r.send(http.MethodPost, "/api/v1/verify/labels", tokA, body("satisfied")); code != http.StatusNotFound {
		t.Fatalf("unknown task: %d %s", code, out)
	}
	// Still open: refused (selection is post-hoc, 06 §5.1).
	r.run.add("task_for_label", tenantA, map[string]any{"agent": "claudecode", "closed": uint64(0)})
	if code, out := r.send(http.MethodPost, "/api/v1/verify/labels", tokA, body("satisfied")); code != http.StatusConflict {
		t.Fatalf("open task: %d %s", code, out)
	}
	r.run.rows["task_for_label"][tenantA.String()] = []map[string]any{{"agent": "claudecode", "closed": uint64(1)}}
	code, out := r.send(http.MethodPost, "/api/v1/verify/labels", tokA, body("satisfied"))
	if code != http.StatusOK {
		t.Fatalf("label: %d %s", code, out)
	}
	p := r.decode("labels.json", out)
	if p["recorded"] != true || p["labels"].(float64) != 1 || p["human"].(float64) != 1 || p["open"].(float64) != 1 || p["certify_at"].(float64) != 200 {
		t.Fatalf("progress after one label: %s", out)
	}
	// Relabel: an UPDATE, never a second row.
	if code, out := r.send(http.MethodPost, "/api/v1/verify/labels", tokA, body("violated")); code != http.StatusOK {
		t.Fatalf("relabel: %d %s", code, out)
	}
	var (
		digest        []byte
		label, source string
		device        *uuid.UUID
		n             int
	)
	ctx := context.Background()
	if err := r.admin.QueryRow(ctx, `SELECT count(*) FROM gold_set_members WHERE tenant_id = $1`, tenantA).Scan(&n); err != nil || n != 1 {
		t.Fatalf("members after relabel: n=%d err=%v", n, err)
	}
	if err := r.admin.QueryRow(ctx, `SELECT g.task_digest, g.true_label::text, g.label_source, g.labeled_by_device FROM gold_set_members g JOIN gold_sets s ON s.id = g.gold_set_id WHERE g.tenant_id = $1 AND s.agent = 'claudecode' AND s.frozen_at IS NULL`, tenantA).Scan(&digest, &label, &source, &device); err != nil {
		t.Fatal(err)
	}
	root, _ := itTenantRoot(tenantA)
	if want := taskDigest(root, session, task); string(digest) != string(want) {
		t.Fatalf("task_digest must be HMAC(root, session ‖ task): got %x want %x", digest, want)
	}
	if label != "violated" || source != "human" || device == nil || *device != deviceA {
		t.Fatalf("row: label=%s source=%s device=%v", label, source, device)
	}
	// Tenant B: an empty set, and A's task is unknown to it.
	code, out = r.send(http.MethodGet, "/api/v1/verify/labels", tokB, "")
	if code != http.StatusOK {
		t.Fatalf("progress B: %d %s", code, out)
	}
	if p = r.decode("labels.json", out); p["labels"].(float64) != 0 {
		t.Fatalf("tenant B must not see A's labels: %s", out)
	}
	if code, out := r.send(http.MethodPost, "/api/v1/verify/labels", tokB, body("satisfied")); code != http.StatusNotFound {
		t.Fatalf("B labeling A's task: %d %s", code, out)
	}
}
