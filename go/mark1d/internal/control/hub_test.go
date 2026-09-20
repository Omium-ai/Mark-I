package control

import (
	"os"
	"path/filepath"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// The home directory, / and a drive root are never offered as the project to watch.
func TestTooBroadRoots(t *testing.T) {
	home, _ := os.UserHomeDir()
	for p, want := range map[string]bool{home: true, filepath.Join(home, "work", "repo"): false, string(filepath.Separator): true} {
		if got := tooBroad(p); got != want {
			t.Errorf("tooBroad(%q) = %v, want %v", p, got, want)
		}
	}
}

// A Windows path into a WSL distro is refused as a project: the WSL lane exists for it.
func TestWSLSharesAreNotProjects(t *testing.T) {
	for p, want := range map[string]bool{
		`\\wsl.localhost\Ubuntu\home\u\repo`: true,
		`\\wsl$\Ubuntu\home\u\repo`:          true,
		`//wsl.localhost/Ubuntu/home/u/repo`: true,
		`C:\Users\u\repo`:                    false,
		`/home/u/repo`:                       false,
	} {
		if got := isWSLShare(p); got != want {
			t.Errorf("isWSLShare(%q) = %v, want %v", p, got, want)
		}
	}
}

// A live session's token count survives a daemon restart: the count the last run flushed seeds the session when its next event arrives.
func TestLiveTokensSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-tokens.json")
	sid := [16]byte{7}
	usage := func(n uint64) *m1pv1.Event {
		return &m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{InputTokens: n}}}
	}
	h := NewHub()
	h.SetTokensFile(path)
	h.Publish(usage(100))
	h.Publish(usage(50))
	h.FlushTokens()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("nothing flushed")
	}
	h2 := NewHub()
	h2.SetTokensFile(path)
	h2.Publish(usage(1))
	live := h2.live(nil)
	if len(live) != 1 || live[0].Tokens != 151 {
		t.Fatalf("after a restart the session should hold 151 tokens, got %+v", live)
	}
}
