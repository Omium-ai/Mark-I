// 07 §5 / 04 §11.1 on Windows: named pipe \\.\pipe\omium-mark1-<user-SID>, DACL owner-SID-only, byte mode.
package fabric

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const pipePrefix = `\\.\pipe\omium-mark1-`

// SocketPath is the per-user pipe name; rust/mark1-harden derives the same string from the same token call.
func SocketPath() (string, error) {
	sid, err := userSID()
	if err != nil {
		return "", err
	}
	return pipePrefix + sid, nil
}

func userSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("fabric: token user: %w", err)
	}
	return u.User.Sid.String(), nil
}

// sddl is the whole boundary: one allow ACE, generic-all, the owner's SID, no inheritance.
func sddl(sid string) string { return "D:P(A;;GA;;;" + sid + ")" }

// Listen binds the pipe; go-winio takes FILE_FLAG_FIRST_PIPE_INSTANCE, so a held name is a refusal, never a shared endpoint.
func Listen(path string) (net.Listener, error) {
	sid, err := userSID()
	if err != nil {
		return nil, err
	}
	l, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl(sid), MessageMode: false})
	if err != nil {
		return nil, fmt.Errorf("fabric: listen %s: %w", path, err)
	}
	return l, nil
}
