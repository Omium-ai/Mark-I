// 07 §5's transport endpoint on Windows: the per-user pipe mark1d's fabric binds, derived from the same token call.
package cli

import (
	"io"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func SocketPath() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return `\\.\pipe\omium-mark1-` + u.User.Sid.String(), nil
}

// DaemonReachable dials by shape: a pipe name via the pipe, anything else as an AF_UNIX path (an explicit --socket, or a test's fake).
func DaemonReachable(socket string) bool {
	d := 300 * time.Millisecond
	var conn io.Closer
	var err error
	if strings.HasPrefix(socket, `\\.\pipe\`) {
		conn, err = winio.DialPipe(socket, &d)
	} else {
		conn, err = net.DialTimeout("unix", socket, d)
	}
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
