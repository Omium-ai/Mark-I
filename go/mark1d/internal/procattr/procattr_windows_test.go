package procattr

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHideSetsNoConsole(t *testing.T) {
	cmd := exec.Command("cmd")
	Hide(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.HideWindow || cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("attrs %+v", cmd.SysProcAttr)
	}
}
