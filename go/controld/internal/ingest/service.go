package ingest

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// ServiceDevice is the device_id stamped on every service-authored batch (06 §1.2 REVISED seam); fixed, never enrolled, never a token subject.
var ServiceDevice = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://omium.ai/mark1/controld/ingest/service"))

// TenantHeader names the tenant a service batch is filed under; the verified principal is the service (ADR-0010 §2.2 seam, the receipts append.go shape).
const TenantHeader = "M1P-Tenant-Id"

// handleServiceIngest is POST /internal/v1/ingest/service: credential first, tenant from the header only because the caller is a verified service, then the same stages as a device batch under the ServiceDevice stamp.
func (m *Module) handleServiceIngest(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		writeErr(w, apiErr{http.StatusForbidden, "M1E-1001", "service credential required", nil})
		return
	}
	cred, err := querychoke.VerifyServiceCredential(m.serviceToken, bearer)
	if err != nil {
		writeErr(w, apiErr{http.StatusForbidden, "M1E-1001", "service credential rejected", nil})
		return
	}
	tenantUUID, err := uuid.Parse(r.Header.Get(TenantHeader))
	if err != nil {
		writeErr(w, errMalformed(TenantHeader+" must be a UUID"))
		return
	}
	tenant, err := querychoke.FromServiceJob(cred, tenantUUID)
	if err != nil {
		writeErr(w, errMalformed(err.Error()))
		return
	}
	m.ingest(w, r, principal{tenant: tenant, device: ServiceDevice, service: true})
}
