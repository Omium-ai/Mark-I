package hostprofile

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// The host registry (ADR-0013 §5): known hosts and the manifest each is
// expected to declare. Checked-in data beside its consumer, the same
// convention as the hookshim's maps/<agent>.json defaults that agent_maps
// bundle data overrides. INFORMATIONAL: the handshake logs known/unknown and
// enforces nothing — an unlisted host integrates exactly as a listed one.

//go:embed hosts.json
var hostsJSON []byte

// Host is one registry entry.
type Host struct {
	HostID      string  `json:"host_id"`
	DisplayName string  `json:"display_name"`
	Expected    Profile `json:"expected_manifest"`
}

// hosts is the parsed registry, loaded once; a malformed file is a build
// defect and panics at init so it can never ship.
var hosts = func() map[string]Host {
	var raw struct {
		Hosts []struct {
			HostID      string `json:"host_id"`
			DisplayName string `json:"display_name"`
			Expected    struct {
				HostVersion       string     `json:"host_version"`
				OwnsExecution     bool       `json:"owns_execution"`
				OwnsConfigSurface bool       `json:"owns_config_surface"`
				OwnsMemory        bool       `json:"owns_memory"`
				ArrestMode        ArrestMode `json:"arrest_mode"`
				SuppliesIdentity  bool       `json:"supplies_identity"`
				SchemaVersion     string     `json:"schema_version"`
			} `json:"expected_manifest"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(hostsJSON, &raw); err != nil {
		panic(fmt.Sprintf("hostprofile: hosts.json is not valid: %v", err))
	}
	out := make(map[string]Host, len(raw.Hosts))
	for _, h := range raw.Hosts {
		if h.HostID == "" || (h.Expected.ArrestMode != Act && h.Expected.ArrestMode != Recommend) {
			panic(fmt.Sprintf("hostprofile: hosts.json entry %q is incomplete", h.HostID))
		}
		out[h.HostID] = Host{HostID: h.HostID, DisplayName: h.DisplayName, Expected: Profile{
			HostID: h.HostID, HostVersion: h.Expected.HostVersion,
			OwnsExecution: h.Expected.OwnsExecution, OwnsConfigSurface: h.Expected.OwnsConfigSurface, OwnsMemory: h.Expected.OwnsMemory,
			ArrestMode: h.Expected.ArrestMode, SuppliesIdentity: h.Expected.SuppliesIdentity, SchemaVersion: h.Expected.SchemaVersion,
		}}
	}
	return out
}()

// Lookup returns the registry entry for hostID and whether it is known.
func Lookup(hostID string) (Host, bool) {
	h, ok := hosts[hostID]
	return h, ok
}
