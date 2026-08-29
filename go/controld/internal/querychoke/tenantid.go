package querychoke

import (
	"errors"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
)

// TenantID is a validated newtype (05 §6.2): constructible ONLY from verified
// claims. There is deliberately no FromString and no exported field — a
// "forgot to set it" bug cannot type-check into a wildcard, and a handler
// cannot assemble one from a path or body value. The zero value is invalid
// and every constructor rejects the nil UUID.
type TenantID struct{ id uuid.UUID }

// ErrNoTenant is returned for a nil tenant UUID — claims that verify but
// carry no tenant are a token-minting bug, refused here rather than allowed
// to become an unset GUC (which the RLS NULLIF policy would match to nothing,
// 05 §7.1 — the second wall; this is the first).
var ErrNoTenant = errors.New("querychoke: claims carry no tenant id")

// FromClaims is the §2 stage-3 stamp: the one path from a request to a
// TenantID. FromOperatorToken joins it with the operator surface (WS-6).
func FromClaims(c auth.Claims) (TenantID, error) {
	if c.TenantID == uuid.Nil {
		return TenantID{}, ErrNoTenant
	}
	return TenantID{id: c.TenantID}, nil
}

func (t TenantID) String() string { return t.id.String() }

// UUID exposes the value for stamping (S3 key derivation, CH rows). Reading
// is safe — only construction is guarded.
func (t TenantID) UUID() uuid.UUID { return t.id }

// IsZero reports the invalid zero value; consumers refuse it.
func (t TenantID) IsZero() bool { return t.id == uuid.Nil }
