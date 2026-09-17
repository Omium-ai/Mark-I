package supervise

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
)

const shimBinary = "mark1-hookshim"

// ShimPath is where 08 §8.1's fragment command resolves: <state>/bin/mark1-hookshim.
func ShimPath(stateDir string) string { return filepath.Join(stateDir, "bin", shimBinary) }

// InstallShim copies the packaged shim sitting beside this executable into ShimPath when it is absent or its bytes differ, so a fragment the app provisioned has a shim to run. mark1-proxy and cortexd need no copy: findBinary execs them in place.
func InstallShim(stateDir string, log *slog.Logger) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	return installShim(filepath.Dir(self), stateDir, log)
}

func installShim(srcDir, stateDir string, log *slog.Logger) error {
	name := shimBinary
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	src := filepath.Join(srcDir, name)
	want, err := os.ReadFile(src)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	dst := filepath.Join(stateDir, "bin", name)
	have, err := os.ReadFile(dst)
	switch {
	case err == nil && bytes.Equal(have, want):
		return nil
	case err == nil:
		// A shim the user put there after this package was built is theirs; say so instead of clobbering it.
		si, serr := os.Stat(src)
		di, derr := os.Stat(dst)
		if serr == nil && derr == nil && di.ModTime().After(si.ModTime()) {
			log.Warn("mark1d: keeping a user-installed mark1-hookshim newer than the packaged one", "path", dst, "packaged", src)
			return nil
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, want, 0o755); err != nil { //nolint:gosec // G306: an executable
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	log.Info("mark1d: installed the packaged mark1-hookshim", "path", dst, "from", src)
	return nil
}
