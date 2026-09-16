//go:build chaos && linux

package spool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	diskFullChildEnv = "M1_CHAOS_DISKFULL_CHILD"
	diskFullDirEnv   = "M1_CHAOS_DISKFULL_DIR"
	diskFullResult   = "M1RESULT "
)

type diskFullReport struct {
	MountBytes    uint64    `json:"mount_bytes"`
	Appended      int       `json:"appended"`
	Shed          uint64    `json:"shed"`
	Parked        bool      `json:"parked"`
	Edges         []bool    `json:"edges"`
	LiveDrops     []Dropped `json:"live_drops"`
	Recovered     int       `json:"recovered"`
	RecoveryDrops []Dropped `json:"recovery_drops"`
}

// TestChaosDiskHardStopTmpfs runs the real statfs sampler against a real full
// filesystem: a 1 MiB tmpfs mounted in an unprivileged user+mount namespace,
// filled past 95 % by a ballast file the child then deletes.
func TestChaosDiskHardStopTmpfs(t *testing.T) {
	if os.Getenv(diskFullChildEnv) == "1" {
		diskFullChild()
		return
	}
	dir := t.TempDir()
	child := exec.Command("unshare", "-Urm", "sh", "-c",
		`mount -t tmpfs -o size=1m tmpfs "$0" && exec "$1" -test.run='^TestChaosDiskHardStopTmpfs$'`, dir, os.Args[0])
	child.Env = append(os.Environ(), diskFullChildEnv+"=1", diskFullDirEnv+"="+dir)
	var stderr bytes.Buffer
	child.Stderr = &stderr
	out, err := child.Output()
	if err != nil {
		msg := stderr.String()
		if errors.Is(err, exec.ErrNotFound) || strings.Contains(msg, "unshare:") || strings.Contains(msg, "mount:") {
			// Not a pass: TestChaosDiskHardStopUnderLoad gates the row through the seam; this leg adds the real statfs.
			t.Skipf("this host cannot mount a tmpfs in an unprivileged user namespace (%v): %s", err, msg)
		}
		t.Fatalf("child failed: %v\n%s\n%s", err, out, msg)
	}
	var rep diskFullReport
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, diskFullResult) {
			if err := json.Unmarshal([]byte(line[len(diskFullResult):]), &rep); err != nil {
				t.Fatal(err)
			}
		}
	}
	if rep.MountBytes == 0 || rep.MountBytes > 2<<20 {
		t.Fatalf("mount_bytes = %d: the child did not run on the 1 MiB tmpfs", rep.MountBytes)
	}
	if !rep.Parked || rep.Shed == 0 {
		t.Fatalf("parked=%v shed=%d: the real statfs never tripped the hard stop", rep.Parked, rep.Shed)
	}
	if len(rep.Edges) != 2 || !rep.Edges[0] || rep.Edges[1] {
		t.Fatalf("hard-stop edges = %v, want [true false]", rep.Edges)
	}
	if len(rep.LiveDrops) != 1 || rep.LiveDrops[0] != (Dropped{DropSpoolShed, ClassDiagnostic, rep.Shed}) {
		t.Fatalf("live drops = %v, want exactly Dropped{SPOOL_SHED,DIAGNOSTIC,%d}", rep.LiveDrops, rep.Shed)
	}
	if rep.Recovered != rep.Appended || len(rep.RecoveryDrops) != 0 {
		t.Fatalf("recovered %d of %d records with drops %v: the hard stop corrupted or lost a segment", rep.Recovered, rep.Appended, rep.RecoveryDrops)
	}
	t.Logf("chaos_disk_hardstop (tmpfs %d bytes): %d billing records, %d diagnostics shed, billing parked and released by deleting the ballast; recovery exact",
		rep.MountBytes, rep.Appended, rep.Shed)
}

func diskFullChild() {
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "chaos child: "+format+"\n", args...)
		os.Exit(1)
	}
	dir := os.Getenv(diskFullDirEnv)
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		fail("statfs: %v", err)
	}
	rep := diskFullReport{MountBytes: uint64(st.Blocks) * uint64(st.Bsize)} // #nosec G115 -- statfs fields are non-negative
	cfg := Config{Dir: filepath.Join(dir, "spool"), SegmentSize: 32 << 10, SpoolCap: 64 << 20}
	s, err := Open(cfg)
	if err != nil {
		fail("open: %v", err)
	}
	var edgesMu sync.Mutex
	s.SetHardStopHook(func(entered bool) {
		edgesMu.Lock()
		defer edgesMu.Unlock()
		rep.Edges = append(rep.Edges, entered)
	})
	edges := func() int {
		edgesMu.Lock()
		defer edgesMu.Unlock()
		return len(rep.Edges)
	}
	payload := bytes.Repeat([]byte{0xB1}, 200)
	ctx := context.Background()
	for i := 1; i <= 200; i++ {
		if err := s.Append(ctx, eid(i), ClassBilling, payload); err != nil {
			fail("append %d: %v", i, err)
		}
		rep.Appended++
	}

	ballast := filepath.Join(dir, "ballast")
	f, err := os.Create(ballast)
	if err != nil {
		fail("ballast: %v", err)
	}
	chunk := make([]byte, 4096)
	for used, _ := diskUsedRatio(dir); used < 0.97; used, _ = diskUsedRatio(dir) {
		if _, err := f.Write(chunk); err != nil {
			fail("ballast write at %.3f: %v", used, err)
		}
	}
	if err := f.Close(); err != nil {
		fail("ballast close: %v", err)
	}
	for deadline := time.Now().Add(3 * time.Second); edges() != 1; {
		if time.Now().After(deadline) {
			fail("the sampler never saw the full tmpfs")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		if err := s.Append(ctx, eid(1000+i), ClassDiagnostic, payload); !errors.Is(err, ErrDiagnosticShed) {
			fail("diagnostic under the hard stop: %v, want shed", err)
		}
		rep.Shed++
	}
	probe, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	err = s.Append(probe, eid(2000), ClassBilling, payload)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		fail("billing under the hard stop: %v, want to block", err)
	}
	rep.Parked = true

	if err := os.Remove(ballast); err != nil {
		fail("remove ballast: %v", err)
	}
	for deadline := time.Now().Add(3 * time.Second); ; {
		probe, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		err := s.Append(probe, eid(3000), ClassBilling, payload)
		cancel()
		if err == nil {
			rep.Appended++
			break
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			fail("billing after the ballast was removed: %v", err)
		}
		if time.Now().After(deadline) {
			fail("billing still parked 3 s after space returned")
		}
	}
	for deadline := time.Now().Add(3 * time.Second); edges() != 2; {
		if time.Now().After(deadline) {
			fail("the hard-stop hook never reported the exit edge")
		}
		time.Sleep(10 * time.Millisecond)
	}
	rep.LiveDrops = s.DrainDropped()
	if err := s.Close(); err != nil {
		fail("close: %v", err)
	}

	s2, err := Open(cfg)
	if err != nil {
		fail("recovery open: %v", err)
	}
	rep.RecoveryDrops = s2.DrainDropped()
	ack, _ := s2.Cursors()
	recs, _, err := s2.Records(ack)
	if err != nil {
		fail("records: %v", err)
	}
	rep.Recovered = len(recs)
	_ = s2.Close()
	out, err := json.Marshal(rep)
	if err != nil {
		fail("marshal: %v", err)
	}
	fmt.Println(diskFullResult + string(out))
}
