//go:build !windows

package procattr

import (
	"os/exec"
	"testing"
)

func TestHideIsANoOpElsewhere(t *testing.T) {
	cmd := exec.Command("true")
	Hide(cmd)
	if cmd.SysProcAttr != nil {
		t.Fatal("no attrs outside Windows")
	}
}
