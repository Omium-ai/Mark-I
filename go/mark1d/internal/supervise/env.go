package supervise

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// childEnvNames is everything a supervised child (mark1-proxy, cortexd, llama-server) reads from its environment or needs to load at all: the search path and loader paths, home and temp, locale, the runtime and kill-switch knobs the Rust children read (XDG_RUNTIME_DIR for the fabric socket, RUST_LOG, MARK1_DISABLE), GPU selection for the reward model, and the names a Win32 process cannot start without. Nothing else crosses: the daemon's ANTHROPIC_API_KEY, cloud credentials and any other secret stay in the daemon.
var childEnvNames = []string{
	"PATH", "HOME", "USERPROFILE", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ",
	"XDG_RUNTIME_DIR", "RUST_LOG", "RUST_BACKTRACE", "MARK1_DISABLE",
	"LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "CUDA_VISIBLE_DEVICES", "HIP_VISIBLE_DEVICES",
	"SystemRoot", "SystemDrive", "windir", "PATHEXT", "LOCALAPPDATA", "APPDATA", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
}

// ChildEnv is a supervised child's whole environment: the daemon's values for childEnvNames only, then set (K=V pairs) replacing any same-named entry. A test binary also passes its *_TEST_* re-exec switches, the seam every child test here uses.
func ChildEnv(set ...string) []string {
	name := func(kv string) string { k, _, _ := strings.Cut(kv, "="); return k }
	var out []string
	for _, kv := range os.Environ() {
		k := name(kv)
		keep := slices.ContainsFunc(childEnvNames, func(n string) bool { return strings.EqualFold(n, k) }) || (testing.Testing() && strings.Contains(k, "_TEST_"))
		overridden := slices.ContainsFunc(set, func(s string) bool { return strings.EqualFold(name(s), k) })
		if keep && !overridden {
			out = append(out, kv)
		}
	}
	return append(out, set...)
}
