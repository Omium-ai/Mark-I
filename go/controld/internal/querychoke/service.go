// service.go — the service-credential seam for the INTERNAL write surface.
// ADR-0010 §2.2: mark1-intel's tvo.rollup_tenant_day job DRIVES the rollup
// write but never holds a ClickHouse credential; it names the tenant as a
// JOB PARAMETER (params = {tenant_id, series, watermark}, 06 §7.3). That is
// the one sanctioned exception to "the tenant comes from the verified
// token": here the verified thing is the CALLING SERVICE, and the TenantID
// type still gates Build — a handler cannot mint one without first holding a
// verified ServiceCred, so the request-parameter path into TenantID stays
// closed for every tenant-facing surface.
package querychoke

import (
	"crypto/subtle"
	"errors"

	"github.com/google/uuid"
)

// ServiceCred proves the caller presented the intel driver's credential.
// Zero value is unverified; the only constructor is VerifyServiceCredential.
type ServiceCred struct{ ok bool }

var errBadServiceCred = errors.New("querychoke: service credential rejected")

// VerifyServiceCredential constant-time-compares the presented bearer
// against the configured secret. An empty configured secret verifies
// NOTHING — the surface is simply absent, never open.
func VerifyServiceCredential(configured, presented string) (ServiceCred, error) {
	if configured == "" || len(presented) == 0 {
		return ServiceCred{}, errBadServiceCred
	}
	if subtle.ConstantTimeCompare([]byte(configured), []byte(presented)) != 1 {
		return ServiceCred{}, errBadServiceCred
	}
	return ServiceCred{ok: true}, nil
}

// FromServiceJob is the third and last TenantID constructor (beside
// FromClaims and the operator path): a verified service caller naming the
// job's tenant. It refuses an unverified cred and the nil UUID, exactly
// like the claims path.
func FromServiceJob(c ServiceCred, tenant uuid.UUID) (TenantID, error) {
	if !c.ok {
		return TenantID{}, errBadServiceCred
	}
	if tenant == uuid.Nil {
		return TenantID{}, ErrNoTenant
	}
	return TenantID{id: tenant}, nil
}
