//go:build linux

package apparmor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Host paths and the parser, test seams.
var (
	RestrictPath = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
	Dir          = "/etc/apparmor.d"
	LoadedPath   = "/sys/kernel/security/apparmor/profiles"
	Parser       = func(args ...string) ([]byte, error) {
		return exec.Command("apparmor_parser", args...).CombinedOutput() //nolint:gosec // G204: fixed flags and our own profile path
	}
	uidOf = func(fi os.FileInfo) uint32 {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			return st.Uid
		}
		return 1
	}
	euid = os.Geteuid
)

// ProfilePath is where the profile lives.
func ProfilePath() string { return filepath.Join(Dir, Name) }

// Restricted reports kernel.apparmor_restrict_unprivileged_userns=1: absent (older kernels, WSL, non-Ubuntu) reads as unrestricted.
func Restricted() bool {
	b, err := os.ReadFile(RestrictPath)
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// RootOwned refuses a path any non-root user could replace: the binary and every directory above it must be owned by root and writable by nobody else, or the profile would hand user namespaces to whatever lands there.
func RootOwned(p string) error {
	for d := p; ; d = filepath.Dir(d) {
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		if uidOf(fi) != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is not owned by root or is writable by others", d)
		}
		if d == filepath.Dir(d) {
			return nil
		}
	}
}

// Install writes and loads the profile for daemon when the kernel restricts user namespaces; it refuses a user-writable daemon path and anything short of root. installed=false with no error means there was nothing to do.
func Install(daemon string) (installed bool, err error) {
	if !Restricted() {
		return false, nil
	}
	resolved, err := filepath.EvalSymlinks(daemon)
	if err != nil {
		return false, err
	}
	if err := RootOwned(resolved); err != nil {
		return false, fmt.Errorf("refusing a profile for %s: %w (install the .deb, or move the Mark 1 binaries under a root-owned directory)", resolved, err)
	}
	text, err := Profile(resolved)
	if err != nil {
		return false, err
	}
	if euid() != 0 {
		return false, errors.New("loading an AppArmor profile needs root: run this command with sudo")
	}
	tmp := ProfilePath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil { //nolint:gosec // G306: /etc/apparmor.d profiles are world-readable by convention
		return false, err
	}
	if err := os.Rename(tmp, ProfilePath()); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if out, err := Parser("-r", "-W", "-T", ProfilePath()); err != nil {
		_ = os.Remove(ProfilePath())
		return false, fmt.Errorf("apparmor_parser -r: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return true, nil
}

// Uninstall unloads and removes the profile; absent is success.
func Uninstall() error {
	if _, err := os.Stat(ProfilePath()); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if euid() != 0 {
		return errors.New("unloading an AppArmor profile needs root: run this command with sudo")
	}
	_, _ = Parser("-R", ProfilePath()) // not loaded is fine; the file goes either way
	return os.Remove(ProfilePath())
}

// Check is `mark1 doctor`'s apparmor_userns row for the mark1d at daemon; self names this CLI in the fix it prints.
func Check(daemon, self string) (ok bool, detail string) {
	if !Restricted() {
		return true, "unprivileged user namespaces are not restricted here"
	}
	resolved, err := filepath.EvalSymlinks(daemon)
	if err != nil {
		return false, "mark1d not found at " + daemon
	}
	fix := "run `sudo " + self + " apparmor install`"
	if err := RootOwned(resolved); err != nil {
		fix = "mark1d at " + resolved + " is in a user-writable location (" + err.Error() + "): install the .deb, or move the Mark 1 binaries under a root-owned directory and " + fix
	}
	b, err := os.ReadFile(ProfilePath())
	switch {
	case err != nil:
		return false, "kernel.apparmor_restrict_unprivileged_userns=1 and no " + Name + " profile: the anchor sandbox cannot start; " + fix
	case !strings.Contains(string(b), "\""+resolved+"\""):
		return false, ProfilePath() + " names another mark1d, not " + resolved + "; " + fix
	}
	loaded, err := os.ReadFile(LoadedPath)
	switch {
	case err != nil:
		return true, "profile installed for " + resolved + " (the loaded set is readable by root only)"
	case !strings.Contains(string(loaded), Name+" ("):
		return false, "profile installed for " + resolved + " but not loaded; " + fix
	}
	return true, "profile installed and loaded for " + resolved
}
