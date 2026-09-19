// Package procattr: the daemon has no console; on Windows every child it spawns would get a fresh one (v0.1.2 showed a black
// terminal per cortexd). Hide marks a command so no console window is created; elsewhere it is a no-op.
package procattr

import "os/exec"

func Hide(cmd *exec.Cmd) { hide(cmd) }
