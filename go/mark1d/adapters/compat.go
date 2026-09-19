package adapters

// Compat is a tailer's admission verdict for an installed agent version (D-EE).
type Compat int

const (
	// Incompatible: the newest artifact of this version fails the structural probe; the surface is refused.
	Incompatible Compat = iota
	// Unprobed: nothing of this version on disk yet, so no verdict; refused until a session exists.
	Unprobed
	// Pinned: a recorded conformance corpus covers this version.
	Pinned
	// CompatibleUnpinned: the probe passed with no corpus; capture proceeds under a receipted unsupported_agent_version window.
	CompatibleUnpinned
)

func (c Compat) String() string {
	switch c {
	case Pinned:
		return "pinned"
	case CompatibleUnpinned:
		return "compatible_unpinned"
	case Unprobed:
		return "unprobed"
	}
	return "incompatible"
}

// Admits is the tail gate: only a pinned or probe-passed version is parsed.
func (c Compat) Admits() bool { return c == Pinned || c == CompatibleUnpinned }
