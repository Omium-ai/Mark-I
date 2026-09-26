package teams

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

type fakeRow struct{ team *uuid.UUID }

func (r fakeRow) Scan(dest ...any) error {
	*(dest[0].(**uuid.UUID)) = r.team
	return nil
}

type fakeTx struct {
	pgx.Tx
	team *uuid.UUID
}

func (f fakeTx) QueryRow(context.Context, string, ...any) pgx.Row { return fakeRow{f.team} }

type fakeDB struct {
	calls int
	team  *uuid.UUID
	err   error
}

func (d *fakeDB) WithTenant(_ context.Context, _ querychoke.TenantID, fn func(pgx.Tx) error) error {
	d.calls++
	if d.err != nil {
		return d.err
	}
	return fn(fakeTx{team: d.team})
}

func TestEffectiveTenantCachesThirtySecondsAndForgets(t *testing.T) {
	clock := time.Now()
	now = func() time.Time { return clock }
	t.Cleanup(func() { now = time.Now })
	ctx, sub, personal, team := context.Background(), "omium:"+uuid.NewString(), uuid.New(), uuid.New()
	db := &fakeDB{}

	if got, err := EffectiveTenant(ctx, db, sub, personal); err != nil || got != personal {
		t.Fatalf("no member row: %s %v", got, err)
	}
	db.team = &team
	if got, _ := EffectiveTenant(ctx, db, sub, personal); got != personal || db.calls != 1 {
		t.Fatalf("inside 30 s the cached answer stands: %s after %d reads", got, db.calls)
	}
	clock = clock.Add(31 * time.Second)
	if got, _ := EffectiveTenant(ctx, db, sub, personal); got != team || db.calls != 2 {
		t.Fatalf("past 30 s the member row wins: %s after %d reads", got, db.calls)
	}
	db.team = nil
	Forget(sub)
	if got, _ := EffectiveTenant(ctx, db, sub, personal); got != personal || db.calls != 3 {
		t.Fatalf("Forget re-reads: %s after %d reads", got, db.calls)
	}
	Forget(sub)
	db.err = errors.New("pg down")
	if _, err := EffectiveTenant(ctx, db, sub, personal); err == nil {
		t.Fatal("a failed read must not fall back to the token tenant")
	}
}
