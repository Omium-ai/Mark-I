// Package apparmor installs the one AppArmor profile Mark 1 needs on Ubuntu ≥ 23.10, where kernel.apparmor_restrict_unprivileged_userns=1 refuses the unprivileged user namespace the anchor sandbox is built on (10 §7.4, 09 §Linux install). The profile grants `userns,` to mark1d at its root-owned install path and nothing else.
package apparmor

import (
	"errors"
	"strings"
)

// Name is the profile's name and its file name under /etc/apparmor.d.
const Name = "omium-mark1d"

// Profile is the whole policy: unconfined apart from being allowed to create user namespaces, attached to daemon's exact path.
func Profile(daemon string) (string, error) {
	if daemon == "" || !strings.HasPrefix(daemon, "/") || strings.ContainsAny(daemon, "*?[]{}^\"\\\x00\n\r\t#") {
		return "", errors.New("mark1d path " + daemon + " is not an absolute path AppArmor can name literally")
	}
	return "# Omium Mark 1: lets mark1d create the anchor sandbox's user namespace. Written by `mark1 apparmor install`; removed by `mark1 apparmor uninstall`.\n" +
		"abi <abi/4.0>,\ninclude <tunables/global>\n\n" +
		"profile " + Name + " \"" + daemon + "\" flags=(unconfined) {\n  userns,\n\n  include if exists <local/" + Name + ">\n}\n", nil
}
