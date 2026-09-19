//go:build windows

package anchors

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// appContainerName is the one per-user profile every anchor runs under: zero capabilities, so its LowBox token reaches no network at all (loopback included) and no file or pipe whose DACL carries no package ACE.
const appContainerName = "Omium.Mark1.Anchors"

const (
	procThreadAttributeSecurityCapabilities = 0x00020009
	procThreadAttributeJobList              = 0x0002000D
	hresultAlreadyExists                    = 0x800700B7 // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
	killExit                                = 0xC000013A // STATUS_CONTROL_C_EXIT: the code TerminateJobObject stamps on a run mark1d killed
	cpuCapExit                              = 1816       // ERROR_NOT_ENOUGH_QUOTA: the job's user-time limit fired
	activeProcessCap                        = 256        // the pids.max twin
	modifyMask                              = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.FILE_GENERIC_EXECUTE | windows.DELETE
	readExecMask                            = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE
)

var (
	userenv                                   = windows.NewLazySystemDLL("userenv.dll")
	createAppContainerProfile                 = userenv.NewProc("CreateAppContainerProfile")
	deriveAppContainerSidFromAppContainerName = userenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

// securityCapabilities is SECURITY_CAPABILITIES (winnt.h); capabilityCount 0 IS the network denial.
type securityCapabilities struct {
	appContainerSid *windows.SID
	capabilities    *windows.SIDAndAttributes
	capabilityCount uint32
	reserved        uint32
}

// WindowsSandbox implements Sandbox with an AppContainer (network denied, reads AND writes confined to the ACL allow-list below) and a job object (caps, kill). See doc.go.
type WindowsSandbox struct {
	scratchRoot string
	sid         *windows.SID
	reason      string // non-empty ⇒ every run is refused with it
}

// NewSandbox creates or derives the per-user profile and grants the package its roots once; scratchRoot is where per-run scratch dirs live ("" uses the OS temp dir) and they inherit its ACE.
func NewSandbox(scratchRoot string) *WindowsSandbox {
	if scratchRoot == "" {
		scratchRoot = os.TempDir()
	}
	s := &WindowsSandbox{scratchRoot: scratchRoot}
	sid, err := appContainerSID()
	if err != nil {
		s.reason = "AppContainer profile refused: " + err.Error()
		return s
	}
	s.sid = sid
	if err := s.grant(scratchRoot, modifyMask); err != nil {
		s.reason = "scratch root grant refused: " + err.Error()
		return s
	}
	for _, root := range toolchainRoots() {
		_ = s.grant(root, readExecMask) // best effort: the per-run binary-dir grant is the load-bearing one
	}
	return s
}

// appContainerSID creates the profile (per user, HKCU + %LOCALAPPDATA%\Packages, no elevation) or derives the SID of the one already there.
func appContainerSID() (*windows.SID, error) {
	name, err := windows.UTF16PtrFromString(appContainerName)
	if err != nil {
		return nil, err
	}
	if err := createAppContainerProfile.Find(); err != nil {
		return nil, err
	}
	if err := deriveAppContainerSidFromAppContainerName.Find(); err != nil {
		return nil, err
	}
	var raw *windows.SID
	//nolint:gosec // G103: syscall arguments; name and raw outlive the calls
	hr, _, _ := createAppContainerProfile.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), 0, 0, uintptr(unsafe.Pointer(&raw)))
	if uint32(hr) == hresultAlreadyExists {
		hr, _, _ = deriveAppContainerSidFromAppContainerName.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&raw))) //nolint:gosec // G103: as above
	}
	if int32(hr) < 0 {
		return nil, fmt.Errorf("HRESULT %#010x", uint32(hr))
	}
	defer func() { _ = windows.FreeSid(raw) }()
	return raw.Copy()
}

// FSConfined is true whenever runs are admitted at all: the ACL allow-list is the token, not an optional regime as Landlock is on Linux.
func (s *WindowsSandbox) FSConfined() bool { return s.reason == "" }

func (s *WindowsSandbox) Status() SandboxStatus {
	return SandboxStatus{Available: s.reason == "", Reason: s.reason}
}

// Run executes spec per the doc.go contract: package grants on the worktree and the binary's root, then CreateProcessW with the security-capabilities and job-list attributes (os/exec cannot carry an attribute list).
func (s *WindowsSandbox) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	if s.reason != "" {
		return RunResult{}, fmt.Errorf("%w: %s", ErrSandboxUnavailable, s.reason)
	}
	scratch, env, lim, err := prepare(s.scratchRoot, spec)
	if err != nil {
		return RunResult{}, err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	env = windowsEnv(env, scratch)
	if err := s.grant(spec.WorktreeRO, modifyMask); err != nil {
		return RunResult{}, fmt.Errorf("%w: worktree grant refused: %v", ErrSandboxUnavailable, err)
	}
	if err := s.grant(toolRoot(spec.Argv[0]), readExecMask); err != nil {
		return RunResult{}, fmt.Errorf("%w: toolchain grant refused: %v", ErrSandboxUnavailable, err)
	}

	job, err := newJob(lim)
	if err != nil {
		return RunResult{}, fmt.Errorf("%w: job object: %v", ErrSandboxUnavailable, err)
	}
	defer func() { _ = windows.CloseHandle(job) }() // KILL_ON_JOB_CLOSE: nothing outlives this frame

	budget := &outputBudget{remaining: lim.OutputCap}
	var stdout, stderr capWriter
	stdout.budget, stderr.budget = budget, budget
	std, closeParentEnds, wait, err := stdHandles(&stdout, &stderr)
	if err != nil {
		return RunResult{}, err
	}
	defer closeParentEnds()

	al, err := windows.NewProcThreadAttributeList(3)
	if err != nil {
		return RunResult{}, fmt.Errorf("%w: attribute list: %v", ErrSandboxUnavailable, err)
	}
	defer al.Delete()
	caps := securityCapabilities{appContainerSid: s.sid}
	jobs := []windows.Handle{job}
	//nolint:gosec // G103: the attribute list stores these pointers until Delete, past CreateProcess
	for _, a := range []struct {
		attr uintptr
		p    unsafe.Pointer
		n    uintptr
	}{
		{procThreadAttributeSecurityCapabilities, unsafe.Pointer(&caps), unsafe.Sizeof(caps)},
		{procThreadAttributeJobList, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0])},
		{windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&std[0]), uintptr(len(std)) * unsafe.Sizeof(std[0])},
	} {
		if err := al.Update(a.attr, a.p, a.n); err != nil {
			return RunResult{}, fmt.Errorf("%w: process attribute %#x: %v", ErrSandboxUnavailable, a.attr, err)
		}
	}
	si := windows.StartupInfoEx{ProcThreadAttributeList: al.List()}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	si.StdInput, si.StdOutput, si.StdErr = std[0], std[1], std[2]

	exe, err := windows.UTF16PtrFromString(spec.Argv[0])
	if err != nil {
		return RunResult{}, err
	}
	cmdline, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(spec.Argv))
	if err != nil {
		return RunResult{}, err
	}
	cwd, err := windows.UTF16PtrFromString(spec.WorktreeRO)
	if err != nil {
		return RunResult{}, err
	}
	block, err := envBlock(env)
	if err != nil {
		return RunResult{}, err
	}
	var pi windows.ProcessInformation
	began := time.Now()
	err = windows.CreateProcess(exe, cmdline, nil, nil, true,
		windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT,
		&block[0], cwd, &si.StartupInfo, &pi)
	closeParentEnds() // the child holds its own copies now; EOF on the pipes means every job process is gone
	if err != nil {
		// ERROR_ACCESS_DENIED here is an exe or DLL outside the granted roots: the path is what `mark1 doctor` needs.
		return RunResult{}, fmt.Errorf("%w: createprocess(appcontainer) %s: %v", ErrSandboxUnavailable, spec.Argv[0], err)
	}
	_ = windows.CloseHandle(pi.Thread)
	defer func() { _ = windows.CloseHandle(pi.Process) }()

	gk := &groupKill{sig: func() { _ = windows.TerminateJobObject(job, killExit) }}
	budget.onExceed(func() { gk.kill(false) }) // output cap breach kills the whole job
	watchDone := make(chan struct{})
	go func() {
		t := time.NewTimer(lim.Wall)
		defer t.Stop()
		select {
		case <-ctx.Done(): // the kill switch: `mark1 off` cancels all anchors
		case <-t.C:
		case <-watchDone:
			return
		}
		gk.kill(true)
	}()

	_, _ = windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	var code uint32
	_ = windows.GetExitCodeProcess(pi.Process, &code)
	wait() // pipe EOF: a straggler in the job holding stdout is reaped by the wall clock above, as on linux
	timedOut := gk.markReaped()
	close(watchDone)

	res := RunResult{
		Stdout:       stdout.buf,
		Stderr:       stderr.buf,
		TimedOut:     timedOut,
		Truncated:    budget.exceeded(),
		EffectiveEnv: env,
		Duration:     time.Since(began),
	}
	res.ExitCode, res.Signal = windowsExit(code)
	if res.Truncated {
		return res, ErrOutputCap
	}
	return res, nil
}

// windowsExit maps the process exit code to (ExitCode, Signal): 0 clean; the kill and CPU-cap codes and any NTSTATUS error-severity code (a fault, not an exit()) read as signal-killed with -1, exactly as a signaled unix child does.
func windowsExit(code uint32) (int, string) {
	switch {
	case code == 0:
		return 0, ""
	case code == killExit:
		return -1, "killed"
	case code == cpuCapExit:
		return -1, "CPU time limit exceeded"
	case code >= 0xC0000000:
		return -1, fmt.Sprintf("exception 0x%08X", code)
	default:
		return int(code), ""
	}
}

// stdHandles builds the child's std triple: NUL for stdin and one pipe each for stdout/stderr, the child ends inheritable (the HANDLE_LIST attribute requires it), the parent ends drained into the capWriters by wait.
func stdHandles(stdout, stderr *capWriter) (std [3]windows.Handle, closeChild func(), wait func(), err error) {
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	nulName, _ := windows.UTF16PtrFromString(os.DevNull)
	nul, err := windows.CreateFile(nulName, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &sa, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return std, nil, nil, err
	}
	var wg sync.WaitGroup
	var files []*os.File
	closeChild = func() { // idempotent: called right after CreateProcess and again by the deferred cleanup
		if nul != 0 {
			_ = windows.CloseHandle(nul)
		}
		for _, f := range files {
			_ = f.Close()
		}
		nul, files = 0, nil
	}
	std[0] = nul
	for i, w := range []*capWriter{stdout, stderr} {
		r, wf, perr := os.Pipe()
		if perr != nil {
			closeChild()
			return std, nil, nil, perr
		}
		if perr := windows.SetHandleInformation(windows.Handle(wf.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); perr != nil {
			_ = r.Close()
			_ = wf.Close()
			closeChild()
			return std, nil, nil, perr
		}
		files = append(files, wf)
		std[i+1] = windows.Handle(wf.Fd())
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = io.Copy(w, r)
			_ = r.Close()
		}()
	}
	return std, closeChild, wg.Wait, nil
}

// newJob is the caps half: user-CPU time (RLIMIT_CPU twin, job-wide), committed memory (RLIMIT_DATA twin, job-wide), a process count, kill-on-close (Pdeathsig twin), no fault dialogs, and every UI restriction.
func newJob(lim Limits) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	x := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{JobMemoryLimit: uintptr(lim.MemoryBytes)} //nolint:gosec // G115: SIZE_T on the 64-bit targets mark1d ships for
	x.BasicLimitInformation.PerJobUserTimeLimit = int64(lim.CPUSeconds) * 10_000_000            //nolint:gosec // G115: seconds → 100 ns ticks; the cap is at most 600
	x.BasicLimitInformation.ActiveProcessLimit = activeProcessCap
	x.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_JOB_TIME | windows.JOB_OBJECT_LIMIT_JOB_MEMORY |
		windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	//nolint:gosec // G103: SetInformationJobObject takes the struct by pointer
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&x)), uint32(unsafe.Sizeof(x))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("extended limits: %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_DESKTOP | windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
		windows.JOB_OBJECT_UILIMIT_EXITWINDOWS | windows.JOB_OBJECT_UILIMIT_GLOBALATOMS | windows.JOB_OBJECT_UILIMIT_HANDLES |
		windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD}
	//nolint:gosec // G103: as above
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("ui restrictions: %w", err)
	}
	return job, nil
}

// windowsEnv is the platform half of the allow-list: SystemRoot/PATHEXT/COMSPEC pass through (a Win32 process cannot load without the first, cmd.exe needs the others), and every profile-shaped var points at the per-run scratch so caches land where the package can write. Attested in EffectiveEnv like the rest.
func windowsEnv(env []string, scratch string) []string {
	for _, k := range []string{"SystemRoot", "PATHEXT", "COMSPEC"} {
		if v := os.Getenv(k); v != "" {
			env = withDefault(env, k, v)
		}
	}
	for _, k := range []string{"USERPROFILE", "TEMP", "TMP", "APPDATA", "LOCALAPPDATA"} {
		env = withDefault(env, k, scratch)
	}
	return env
}

// envBlock is the CREATE_UNICODE_ENVIRONMENT block: K=V\0 … \0.
func envBlock(env []string) ([]uint16, error) {
	var b []uint16
	for _, kv := range env {
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			return nil, err
		}
		b = append(b, u...)
	}
	return append(b, 0), nil
}

// toolRoot is the read-execute grant a binary needs: its own dir, or its parent when the dir is a `bin`/`Scripts` leaf (GOROOT\bin\go.exe needs GOROOT\pkg, a venv's Scripts\pytest.exe needs its python.exe and Lib). ponytail: two leaf names cover go/cargo/python layouts; any other layout surfaces as ERROR_ACCESS_DENIED naming the path.
func toolRoot(exe string) string {
	dir := filepath.Dir(exe)
	if b := filepath.Base(dir); b == "bin" || b == "Scripts" {
		return filepath.Dir(dir)
	}
	return dir
}

// toolchainRoots is the fixed read-execute table: the user-profile homes toolchains install into (machine roots like Program Files already carry ALL APPLICATION PACKAGES read by default, so hasPackageACE skips them) plus the module caches, readable never network (founder ruling 2026-09-19).
func toolchainRoots() []string {
	sub := func(base string, elems ...string) string {
		if base == "" {
			return ""
		}
		return filepath.Join(append([]string{base}, elems...)...)
	}
	home, local, roaming := os.Getenv("USERPROFILE"), os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA")
	var out []string
	for _, r := range []string{
		os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"),
		sub(local, "Programs"), sub(roaming, "npm"), sub(local, "Microsoft", "WindowsApps"),
		sub(home, ".cargo"), sub(home, "go"), sub(home, ".local", "bin"),
		os.Getenv("GOMODCACHE"), os.Getenv("CARGO_HOME"),
	} {
		if st, err := os.Stat(r); r != "" && err == nil && st.IsDir() {
			out = append(out, r)
		}
	}
	return out
}

// grant adds an inheritable allow ACE for the package SID on dir unless one is already there (or, for read grants, the ALL APPLICATION PACKAGES ACE machine roots carry by default), so the tree walk SetNamedSecurityInfo does on propagation happens once per root, never per run. Non-NTFS volumes have no ACLs to grant on: refused by name.
func (s *WindowsSandbox) grant(dir string, mask uint32) error {
	fsName, err := volumeFS(dir)
	if err != nil {
		return fmt.Errorf("volume of %s: %w", dir, err)
	}
	if fsName != "NTFS" && fsName != "ReFS" {
		return fmt.Errorf("%s is on %s, not NTFS: AppContainer confinement needs ACLs", dir, fsName)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("DACL of %s: %w", dir, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return fmt.Errorf("DACL of %s: %w", dir, err)
	}
	if dacl == nil || hasPackageACE(dacl, s.sid, mask) {
		return nil // a NULL DACL already admits everyone; otherwise the ACE is in place
	}
	ea := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(mask),
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(s.sid)},
	}}
	merged, err := windows.ACLFromEntries(ea, dacl)
	if err != nil {
		return fmt.Errorf("merge DACL of %s: %w", dir, err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, merged, nil); err != nil {
		return fmt.Errorf("grant on %s: %w", dir, err)
	}
	return nil
}

// hasPackageACE reports an effective (not inherit-only) allow ACE on dir itself that covers mask for the package, or any ALL APPLICATION PACKAGES allow ACE when only read-execute is wanted.
func hasPackageACE(dacl *windows.ACL, sid *windows.SID, mask uint32) bool {
	anyPackage, _ := windows.CreateWellKnownSid(windows.WinBuiltinAnyPackageSid)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		got := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // G103: the SID is stored inline after the ACE header
		if got.Equals(sid) && uint32(ace.Mask)&mask == mask {
			return true
		}
		if mask == readExecMask && anyPackage != nil && got.Equals(anyPackage) {
			return true
		}
	}
	return false
}

// volumeFS names the filesystem holding path ("NTFS", "ReFS", "FAT32", "exFAT", …); a UNC or unmounted path errors.
func volumeFS(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var root, fs [windows.MAX_PATH + 1]uint16
	if err := windows.GetVolumePathName(p, &root[0], uint32(len(root))); err != nil {
		return "", err
	}
	if err := windows.GetVolumeInformation(&root[0], nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))); err != nil {
		return "", err
	}
	return windows.UTF16ToString(fs[:]), nil
}

// MaybeRunHelper is linux/darwin re-exec plumbing; on windows everything is parent-applied at CreateProcess, so there is no helper and no exec gadget to refuse.
func MaybeRunHelper() {}
