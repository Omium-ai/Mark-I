// Package selfupdate is the one door a self-update may pass (08 §10.1, FR-POLICY-009); no updater exists yet, and when one lands Allowed is its only entry.
package selfupdate

import "os"

// ProfileEnv is the fleet profile mark1d already reads (anchors E2 gating); "managed" is what an MDM-provisioned install sets.
const ProfileEnv = "MARK1_PROFILE"

// Allowed reports whether a self-update may proceed and, when not, why.
func Allowed() (bool, string) {
	if os.Getenv(ProfileEnv) == "managed" {
		return false, "self-update is off on managed fleets (MARK1_PROFILE=managed, 08 §10.1)"
	}
	return true, ""
}
