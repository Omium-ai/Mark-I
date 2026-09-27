package querychoke

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
)

// Viewer is who reads inside a tenant (15-teams §Per-person visibility): Subject is the enrollment principal ("omium:<sub>", "" when the device's enrollment names none); Team marks a tenant with an active member row, and only then is Devices the read filter.
type Viewer struct {
	Subject string
	Team    bool
	Devices []uuid.UUID
}

// Viewers resolves the Viewer behind verified claims; PGViewers is production, tests fake it.
type Viewers interface {
	Viewer(ctx context.Context, tid TenantID, c auth.Claims) (Viewer, error)
}

// SubjectOf is the principal string enrollment stores for a user token's sub (enroll handleApprove: "omium:" + sub).
func SubjectOf(c auth.Claims) string {
	if c.Subject == "" {
		return ""
	}
	return "omium:" + c.Subject
}

const viewerTTL = 30 * time.Second

type viewerMemo struct {
	v   Viewer
	exp time.Time
}

// PGViewers answers from m1_team_members and m1_device_enrollments under the tenant GUC, one statement per miss.
// ponytail: 30 s per-process memo swept whole at 4096 principals; a join, leave or removal shows on the next miss.
type PGViewers struct {
	DB   TenantDB
	mu   sync.Mutex
	memo map[string]viewerMemo
}

func NewPGViewers(db TenantDB) *PGViewers { return &PGViewers{DB: db, memo: map[string]viewerMemo{}} }

// A device's viewer is its latest approved enrollment's subject; the devices are every device that subject enrolled in this tenant, revoked ones kept so a retired laptop's history stays its owner's.
const viewerSQL = `WITH me AS (
  SELECT coalesce($2::text, (SELECT oidc_subject FROM m1_device_enrollments
                              WHERE tenant_id = $1 AND device_id = $3::uuid AND status = 'approved'
                              ORDER BY row_seq DESC LIMIT 1)) AS subject)
SELECT coalesce(me.subject, ''),
       EXISTS (SELECT 1 FROM m1_team_members WHERE tenant_id = $1 AND role = 'member'),
       ARRAY(SELECT DISTINCT e.device_id::text FROM m1_device_enrollments e
              WHERE e.tenant_id = $1 AND e.oidc_subject = me.subject
                AND e.device_id IS NOT NULL AND e.status IN ('approved', 'revoked'))
  FROM me`

func (p *PGViewers) Viewer(ctx context.Context, tid TenantID, c auth.Claims) (Viewer, error) {
	key := tid.String() + "|" + c.Subject + "|" + c.DeviceID.String()
	now := time.Now()
	p.mu.Lock()
	if m, ok := p.memo[key]; ok && now.Before(m.exp) {
		p.mu.Unlock()
		return m.v, nil
	}
	p.mu.Unlock()
	var subject, device any
	if s := SubjectOf(c); s != "" {
		subject = s
	}
	if c.DeviceID != uuid.Nil {
		device = c.DeviceID.String()
	}
	var v Viewer
	var ids []string
	err := p.DB.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, viewerSQL, tid.UUID(), subject, device).Scan(&v.Subject, &v.Team, &ids)
	})
	if err != nil {
		return Viewer{}, err
	}
	v.Devices = make([]uuid.UUID, 0, len(ids)+1)
	for _, s := range ids {
		id, err := uuid.Parse(s)
		if err != nil {
			return Viewer{}, err
		}
		v.Devices = append(v.Devices, id)
	}
	if c.DeviceID != uuid.Nil && !slices.Contains(v.Devices, c.DeviceID) {
		v.Devices = append(v.Devices, c.DeviceID) // a device always reads its own rows
	}
	slices.SortFunc(v.Devices, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	p.mu.Lock()
	if len(p.memo) >= 4096 {
		p.memo = map[string]viewerMemo{}
	}
	p.memo[key] = viewerMemo{v: v, exp: now.Add(viewerTTL)}
	p.mu.Unlock()
	return v, nil
}

type tenantWideKey struct{}

// TenantWide marks a read that answers tenant-wide aggregates on purpose (GET /team's TVO): the viewer filter leaves it alone.
func TenantWide(ctx context.Context) context.Context {
	return context.WithValue(ctx, tenantWideKey{}, true)
}

// ViewerFrom resolves the request's Viewer; no resolver, no verified claims (service and background reads) or a TenantWide context is the zero, unfiltered Viewer.
func ViewerFrom(ctx context.Context, v Viewers) (Viewer, error) {
	if v == nil || ctx.Value(tenantWideKey{}) != nil {
		return Viewer{}, nil
	}
	c, ok := auth.ClaimsFrom(ctx)
	if !ok {
		return Viewer{}, nil
	}
	tid, err := FromClaims(c)
	if err != nil {
		return Viewer{}, err
	}
	return v.Viewer(ctx, tid, c)
}

// Scoped narrows every read a team member drives to the member's devices (15-teams); a non-team tenant's query runs exactly as built.
func Scoped(inner Runner, v Viewers) Runner { return scopedRunner{inner: inner, v: v} }

type scopedRunner struct {
	inner Runner
	v     Viewers
}

func (s scopedRunner) Run(ctx context.Context, q Query) (*Rows, error) {
	vw, err := ViewerFrom(ctx, s.v)
	if err != nil {
		return nil, err
	}
	if vw.Team {
		if q, err = narrow(q, vw.Devices); err != nil {
			return nil, err
		}
	}
	return s.inner.Run(ctx, q)
}

func (s scopedRunner) Ready(ctx context.Context) error {
	if p, ok := s.inner.(interface{ Ready(context.Context) error }); ok {
		return p.Ready(ctx)
	}
	return nil
}
