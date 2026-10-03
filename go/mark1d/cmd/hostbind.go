package main

import (
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/admit"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
)

// sessionBinding is the sealer's ADR-0017 session lookup: the admit door's
// Session (bound at an ext: Hello or manifest; Default and unbound for a
// native session) as the receipt payload attests it.
func sessionBinding(door *admit.Path) func([16]byte) identity.SessionBinding {
	return func(sid [16]byte) identity.SessionBinding {
		s := door.SessionFor(sid)
		return identity.SessionBinding{
			Transport: s.Transport, HostID: s.Profile.HostID, HostVersion: s.Profile.HostVersion,
			HostCorrelationID: s.HostCorrelationID, ProfileHash: identity.ProfileHash(s.Profile),
			SuppliesIdentity: s.Profile.SuppliesIdentity, Bound: s.Ext,
		}
	}
}
