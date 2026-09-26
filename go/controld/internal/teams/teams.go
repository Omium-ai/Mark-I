// Package teams resolves a subject's effective tenant (docs/design/15-teams.md): the tenant of its active member row, else the tenant its user token names.
package teams

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

type DB interface {
	WithTenant(ctx context.Context, t querychoke.TenantID, fn func(pgx.Tx) error) error
}

// Subject is the principal enrollment and membership record for a user token's sub.
func Subject(sub string) string { return "omium:" + sub }

const ttl = 30 * time.Second

type entry struct {
	team uuid.UUID
	at   time.Time
}

var (
	mu    sync.Mutex
	cache = map[string]entry{}
	now   = time.Now
)

// ponytail: per-pod 30 s cache, so after accept/leave/remove a sibling pod serves the old tenant for up to 30 s; Forget covers this pod only, a shared invalidation (LISTEN/NOTIFY) when that window matters.
func EffectiveTenant(ctx context.Context, db DB, subject string, tokenTenant uuid.UUID) (uuid.UUID, error) {
	t := now()
	mu.Lock()
	e, ok := cache[subject]
	mu.Unlock()
	if !ok || t.Sub(e.at) > ttl {
		team, err := lookup(ctx, db, subject, tokenTenant)
		if err != nil {
			return uuid.Nil, err
		}
		e = entry{team: team, at: t}
		mu.Lock()
		if len(cache) >= 65536 {
			for k, v := range cache {
				if t.Sub(v.at) > ttl {
					delete(cache, k)
				}
			}
		}
		cache[subject] = e
		mu.Unlock()
	}
	if e.team != uuid.Nil {
		return e.team, nil
	}
	return tokenTenant, nil
}

// Forget drops a subject's cached tenant so this pod's next EffectiveTenant reads the member row.
func Forget(subject string) {
	mu.Lock()
	delete(cache, subject)
	mu.Unlock()
}

func lookup(ctx context.Context, db DB, subject string, tokenTenant uuid.UUID) (uuid.UUID, error) {
	tid, err := querychoke.FromClaims(auth.Claims{TenantID: tokenTenant})
	if err != nil {
		return uuid.Nil, err
	}
	var team *uuid.UUID
	err = db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT m1_team_effective_tenant($1)`, subject).Scan(&team)
	})
	if err != nil || team == nil {
		return uuid.Nil, err
	}
	return *team, nil
}
