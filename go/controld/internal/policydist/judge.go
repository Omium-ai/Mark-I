// POST /internal/v1/judge-requests: the cloud half of client-side-first judges
// (ADR-0008, 06 §6.2 step 2, FR-VERIFY-015). adjudicator-svc posts one
// m1p.v1.JudgeRequest; it rides every live stream of the tenant as
// `event: judge_request` (protojson) and the owning device answers with a
// JudgeVote{locus: CLIENT_SIDE}. No evidence, no key and no command cross here
// -- the rubric is prompt DATA. The hub has no replay, so the response says how
// many streams took the request and a caller may repost the same request_id:
// one vote per request_id is enforced where the vote is minted (mark1d's
// persisted seen-set), which is what makes the repost safe.
package policydist

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

const (
	// MaxRubricLen is verify.proto's "rubric ≤ 16 KiB".
	MaxRubricLen = 16 << 10
	// MaxJudgeTokenBudget bounds what an internal caller can charge to a customer key per request.
	MaxJudgeTokenBudget = 1 << 16
	maxJudgeBody        = MaxRubricLen + 4<<10
)

type judgeRequestBody struct {
	TenantID string          `json:"tenant_id"`
	Request  json.RawMessage `json:"request"`
}

// ValidateJudgeRequest is the one shape check both ends run (mark1d re-runs it before acting): protojson decode plus the field bounds verify.proto states.
func ValidateJudgeRequest(raw []byte) (*m1pv1.JudgeRequest, error) {
	var req m1pv1.JudgeRequest
	if err := protojson.Unmarshal(raw, &req); err != nil {
		return nil, reject("M1E-2001", "request is not a protojson JudgeRequest: %v", err)
	}
	if err := ident("request_id", req.GetRequestId()); err != nil {
		return nil, err
	}
	if err := ident("judge_id", req.GetJudgeId()); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(req.GetJudgeId(), "judge:") {
		return nil, reject("M1E-2001", "judge_id %q is not a judge:<name>@<version> registry key", req.GetJudgeId())
	}
	if err := ident("model", req.GetModel()); err != nil {
		return nil, err
	}
	for name, id := range map[string][]byte{"task_id": req.GetTaskId(), "session_id": req.GetSessionId()} {
		if len(id) != 16 || uuid.UUID(id) == uuid.Nil {
			return nil, reject("M1E-2001", "%s must be 16 non-zero bytes", name)
		}
	}
	if n := len(req.GetRubric()); n == 0 || n > MaxRubricLen {
		return nil, reject("M1E-2001", "rubric is %d bytes; want 1..%d", n, MaxRubricLen)
	}
	if b := req.GetTokenBudget(); b == 0 || b > MaxJudgeTokenBudget {
		return nil, reject("M1E-2001", "token_budget %d is outside 1..%d", b, MaxJudgeTokenBudget)
	}
	switch req.GetTier() {
	case m1pv1.EvidenceTier_EVIDENCE_TIER_E0, m1pv1.EvidenceTier_EVIDENCE_TIER_E1, m1pv1.EvidenceTier_EVIDENCE_TIER_E2:
	default:
		return nil, reject("M1E-2001", "tier %v is not E0|E1|E2", req.GetTier())
	}
	if req.GetLocus() != m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE {
		return nil, reject("M1E-2001", "locus %v: only CLIENT_SIDE requests reach the edge (06 §6.5 cloud judging never does)", req.GetLocus())
	}
	return &req, nil
}

func (m *Module) handleJudgeRequest(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		writeError(w, http.StatusForbidden, "M1E-1001", "service credential required")
		return
	}
	cred, err := querychoke.VerifyServiceCredential(m.serviceToken, bearer)
	if err != nil {
		writeError(w, http.StatusForbidden, "M1E-1001", "service credential rejected")
		return
	}
	var body judgeRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJudgeBody)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "M1E-2001", "malformed judge-request body")
		return
	}
	tenantUUID, err := uuid.Parse(body.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "M1E-2001", "tenant_id: not a UUID")
		return
	}
	tenant, err := querychoke.FromServiceJob(cred, tenantUUID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	req, err := ValidateJudgeRequest(body.Request)
	if err != nil {
		writeError(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	data, err := protojson.Marshal(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "M1E-9500", "judge request could not be rendered")
		return
	}
	writeJSON(w, map[string]any{"request_id": req.GetRequestId(), "streams": m.hub.Judge(tenant.UUID(), string(data))})
}
