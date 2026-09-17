// 07 §5's transport endpoint on Windows: the per-user pipe mark1d's fabric binds, derived from the same token call.
package cli

import (
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

func DaemonReachable(socket string) bool {
	d := 300 * time.Millisecond
	conn, err := winio.DialPipe(socket, &d)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
