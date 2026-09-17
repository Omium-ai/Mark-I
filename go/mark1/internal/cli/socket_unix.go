//go:build unix

// 07 §5's transport endpoint on unix, restated because mark1d/internal is module-private: the string, not the code, is the contract.
package cli

import (
	"net"
	"os"
	"path/filepath"
	"time"
)

func SocketPath() (string, error) {
	if rd := os.Getenv("XDG_RUNTIME_DIR"); rd != "" {
		return filepath.Join(rd, "omium-mark1", "m1p.sock"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".omium", "mark1", "m1p.sock"), nil
}

// DaemonReachable: a dial, not a handshake — connect then close distinguishes running from gone.
func DaemonReachable(socket string) bool {
	conn, err := net.DialTimeout("unix", socket, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
