package anchors

import "strings"

// grantRefused is the AppContainer grant rule, pure so it tests on every OS: a directory equal to or above a protected root (the user profile, AppData, Program Files, the Windows dir), a drive or UNC share root, a relative path, or one at or below a poisoned root never carries the package ACE; "" admits dir. Paths compare as Windows does, case-insensitive with either slash.
func grantRefused(dir string, protected, poisoned []string) string {
	d := winPath(dir)
	switch {
	case d == "":
		return "refusing a grant on an empty path"
	case len(d) == 2 && d[1] == ':':
		return "refusing a grant on the drive root " + dir
	case strings.HasPrefix(d, `\\`):
		if len(strings.FieldsFunc(d, func(r rune) bool { return r == '\\' })) <= 2 {
			return "refusing a grant on the share root " + dir
		}
	case len(d) < 3 || d[1] != ':' || d[2] != '\\':
		return "refusing a grant on the relative path " + dir
	}
	for _, p := range protected {
		if q := winPath(p); q != "" && (q == d || strings.HasPrefix(q, d+`\`)) {
			return "refusing a grant on " + dir + ": it is or contains " + p
		}
	}
	for _, p := range poisoned {
		if q := winPath(p); q != "" && (q == d || strings.HasPrefix(d, q+`\`)) {
			return "refusing a grant on " + dir + ": it is under " + p + ", where a package ACE breaks installed apps"
		}
	}
	return ""
}

// winPath lower-cases p, turns / into \, drops the \\?\ prefix (\\?\UNC\ back to \\) and any trailing separator.
func winPath(p string) string {
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "/", `\`))
	if rest, ok := strings.CutPrefix(p, `\\?\`); ok {
		p = rest
		if unc, ok := strings.CutPrefix(rest, `unc\`); ok {
			p = `\\` + unc
		}
	}
	for strings.HasSuffix(p, `\`) && len(p) > 2 && p != `\\` {
		p = strings.TrimSuffix(p, `\`)
	}
	return p
}
