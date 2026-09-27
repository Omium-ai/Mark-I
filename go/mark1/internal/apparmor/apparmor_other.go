//go:build !linux

package apparmor

import "errors"

var errLinuxOnly = errors.New("AppArmor is Linux-only")

func Install(string) (bool, error) { return false, errLinuxOnly }

func Uninstall() error { return errLinuxOnly }

func Check(string, string) (bool, string) { return true, "not applicable on this OS" }
