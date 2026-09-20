// The canary decision (05 §4.3; 06 §10.4). Pure functions over an ACK
// coverage snapshot -- no clock, no database, no I/O -- because this is the
// arithmetic that decides whether a policy change reaches a whole customer
// fleet, and the only way to be sure of it is to be able to test every branch
// directly.
//
// ROLLBACK IS A FORWARD PUBLICATION. Halt does not unpublish anything: the
// caller responds by publishing the previous section set again at seq+1 (05
// §4.3). The edge's anti-rollback check is used, never fought. That is why
// Decision has no "revert" member -- there is no such verb in this system.

package policydist

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Decision is what the rollout controller does next.
type Decision string

const (
	DecisionHold  Decision = "hold"  // soak longer; nothing is wrong, nothing is proven
	DecisionWiden Decision = "widen" // advance to the next cohort step
	DecisionHalt  Decision = "halt"  // stop widening; publish the previous sections at seq+1
)

// WidenSteps is 05 §4.3's ladder. 100 is terminal.
var WidenSteps = []int{5, 25, 100}

// CanaryChannel is 05 §4.1's publication target for every compiled draft
const CanaryChannel = "canary"

const (
	// WidenCoverage is the ACK-coverage floor for a widen.
	//
	// DOC CONFLICT, resolved and reported: 06 §10.4 requires >= 95%; 05 §4.3
	// step 2 and m1_042's canary-query comment both say >= 90%. The stricter
	// bound is taken. Widening at 90% when one normative document demands 95%
	// is the error that reaches customers; holding at 94% when 90% would have
	// sufficed costs one soak window.
	WidenCoverage = 0.95
	// SoakWindow is 06 §10.4's default dwell at each step.
	SoakWindow = 60 * time.Minute
	// HaltRejectedRatio / HaltPartialRatio are 05 §4.3(b).
	HaltRejectedRatio = 0.005
	HaltPartialRatio  = 0.20
)

// RolloutState is everything about the rollout that ACK coverage does not
// carry.
type RolloutState struct {
	CohortPercent int           // the step currently serving the canary channel
	SoakElapsed   time.Duration // since the current step began
	// HealthRegressed is 05 §4.3(c): a health signal 2σ above the pre-rollout
	// baseline for two consecutive 5-minute ticks. Computed from the metrics
	// plane, which this package does not read -- it is an input, so the halt
	// arithmetic stays testable without a time series.
	HealthRegressed bool
}

// Decide returns the next action and the reason, always in that order: halt
// conditions first, then the widen gate, then hold. Fail-closed: any
// ambiguity holds, and a halt condition beats a satisfied widen gate.
func Decide(c Coverage, st RolloutState) (Decision, string) {
	// (a) 05 §4.3: "any ACK carrying reject_code M1E-3005 (command string in
	// a section) -- one occurrence is one too many". Not a ratio. A command
	// string in a signed bundle means the publish-side gate was bypassed or
	// broken, and no adoption percentage makes that acceptable.
	if c.CommandString > 0 {
		return DecisionHalt, fmt.Sprintf("%d device(s) rejected the bundle with M1E-3005 (command string in a section); one is too many", c.CommandString)
	}
	if c.ActiveDevices > 0 {
		if r := float64(c.Rejected) / float64(c.ActiveDevices); r > HaltRejectedRatio {
			return DecisionHalt, fmt.Sprintf("rejected %.2f%% of active devices, over the %.1f%% halt line", r*100, HaltRejectedRatio*100)
		}
		if p := float64(c.Partial) / float64(c.ActiveDevices); p > HaltPartialRatio {
			return DecisionHalt, fmt.Sprintf("partial on %.1f%% of active devices, over the %.0f%% halt line", p*100, HaltPartialRatio*100)
		}
	}
	// (c) health non-regression.
	if st.HealthRegressed {
		return DecisionHalt, "health signal regressed 2σ for two consecutive ticks"
	}

	if st.CohortPercent >= 100 {
		return DecisionHold, "already at 100%; nothing left to widen"
	}
	if st.SoakElapsed < SoakWindow {
		return DecisionHold, fmt.Sprintf("soaking: %s of %s elapsed", st.SoakElapsed.Truncate(time.Minute), SoakWindow)
	}
	// Zero active devices reads as zero coverage (Coverage.HeadRatio), so an
	// empty or fully dark fleet holds forever rather than widening on a
	// vacuous truth.
	if c.Rejected > 0 {
		return DecisionHold, fmt.Sprintf("%d device(s) rejected the head; a widen needs zero", c.Rejected)
	}
	if ratio := c.HeadRatio(); ratio < WidenCoverage {
		return DecisionHold, fmt.Sprintf("ACK coverage %.1f%% is under the %.0f%% widen floor", ratio*100, WidenCoverage*100)
	}
	return DecisionWiden, fmt.Sprintf("coverage %.1f%%, zero rejections, %s soak complete", c.HeadRatio()*100, SoakWindow)
}

// NextStep returns the cohort percentage after a widen. 100 is terminal.
func NextStep(current int) int {
	for _, s := range WidenSteps {
		if s > current {
			return s
		}
	}
	return 100
}

// InCohort is 06 §10.4's cohort assignment: HMAC(tenant_salt, device_id) mod
// 100 < percent.
//
// HMAC with a per-tenant salt, not a bare hash, for the reason the doc gives
// it a salt at all: without one, the same device sits in the same percentile
// for every tenant and every rollout forever, so the same unlucky machines
// take every canary. The assignment is stable per (tenant, device) so a
// device does not oscillate in and out of the cohort between polls.
func InCohort(tenantSalt []byte, deviceID uuid.UUID, percent int) bool {
	if percent <= 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	return percentile(tenantSalt, deviceID) < uint64(percent)
}

// percentile is InCohort's HMAC(tenant_salt, device_id) mod 100, shared so the min-one rule agrees with InCohort.
func percentile(tenantSalt []byte, deviceID uuid.UUID) uint64 {
	m := hmac.New(sha256.New, tenantSalt)
	d := deviceID
	m.Write(d[:])
	sum := m.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8]) % 100
}

// lowerPercentile: lower percentile wins, ties break on the lower device id, so every caller picks the same one device.
func lowerPercentile(salt []byte, a, b uuid.UUID) bool {
	pa, pb := percentile(salt, a), percentile(salt, b)
	if pa != pb {
		return pa < pb
	}
	return bytes.Compare(a[:], b[:]) < 0
}

// CohortOf is InCohort over every active device plus the min-one rule: the lowest-percentile device is always in once percent > 0, so a one-device fleet never sits at an empty cohort.
func CohortOf(tenantSalt []byte, activeDevices []uuid.UUID, percent int) []uuid.UUID {
	if percent <= 0 || len(activeDevices) == 0 {
		return nil
	}
	in := make([]uuid.UUID, 0, len(activeDevices))
	lowest := activeDevices[0]
	for _, id := range activeDevices {
		if InCohort(tenantSalt, id, percent) {
			in = append(in, id)
		}
		if lowerPercentile(tenantSalt, id, lowest) {
			lowest = id
		}
	}
	for _, id := range in {
		if id == lowest {
			return in
		}
	}
	return append(in, lowest)
}

// InCohortOf is CohortOf's membership test for one device, so the steering path (which only ever needs a yes/no for the device that just polled) need not build the whole slice.
func InCohortOf(tenantSalt []byte, activeDevices []uuid.UUID, percent int, deviceID uuid.UUID) bool {
	if InCohort(tenantSalt, deviceID, percent) {
		return true
	}
	if percent <= 0 {
		return false
	}
	for _, id := range activeDevices {
		if id != deviceID && lowerPercentile(tenantSalt, id, deviceID) {
			return false
		}
	}
	return true
}
