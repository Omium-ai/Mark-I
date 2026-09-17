package harden

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows has no rlimit and no dumpable flag; crash dumps are Windows Error
// Reporting's. 04 §11.6's arm is the same one rust/mark1-harden takes for the
// edge processes: WerAddExcludedApplication for this exe, per-user
// (bAllUsers = FALSE — HKLM needs admin, and a daemon that needs admin to
// start is a bigger hole than the one it closes). The exe is passed by file
// name: WER matches on the name, and MAX_PATH would otherwise bound where the
// binary may live. CEILING (10 §4.2): the exclusion stops WER's user-mode dump;
// a kernel/complete-memory dump or an administrator's debugger can still image
// the process, and there is no read-back API short of the registry, so the
// HRESULT is the only signal.
var (
	wer                       = windows.NewLazySystemDLL("wer.dll")
	werAddExcludedApplication = wer.NewProc("WerAddExcludedApplication")
)

// ErrUnsupported is kept for callers that name the old refusal; Apply no longer returns it.
var ErrUnsupported = errors.New("harden: no core-dump suppression on windows (dumps are WER; 04 §11.6)")

func Apply() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("harden: os.Executable: %w", err)
	}
	name, err := windows.UTF16PtrFromString(filepath.Base(exe))
	if err != nil {
		return fmt.Errorf("harden: exe name: %w", err)
	}
	if err := werAddExcludedApplication.Find(); err != nil {
		return fmt.Errorf("harden: %w", err)
	}
	hr, _, _ := werAddExcludedApplication.Call(uintptr(unsafe.Pointer(name)), 0)
	if int32(hr) < 0 {
		return fmt.Errorf("harden: WerAddExcludedApplication failed: HRESULT %#010x", uint32(hr))
	}
	// No fault dialog either: a hung "mark1d.exe has stopped working" box is a supervisor stall.
	windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX)
	return nil
}
