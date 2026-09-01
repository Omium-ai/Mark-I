// .mark1ignore — the second half of the 04 §0.3 invariant-3 oracle. The
// enabled roots say which trees may be read at all; this file says which
// parts of an enabled tree the customer took back (01 §2, 04 §2.1, 08 §5.1
// "tailers ... honor .mark1ignore"). `mark1 enable` only honors the
// whole-repo opt-out and explicitly defers the rest here
// (go/mark1/internal/enable/enable.go:173).
//
// # Supported gitignore subset
//
//	# comment          comment lines and blank lines are skipped
//	build/             trailing '/' — directories only
//	/dist              leading '/' — anchored at the workspace root
//	src/gen            any embedded '/' — also anchored (git's rule)
//	*.pem  secrets     no '/' — matches that BASENAME at any depth
//	*  ?               segment globs (never cross a '/')
//	**                 crosses whole segments: a/**/c, **/vendor
//	*   or   **        alone on a line: the whole workspace is out — the same
//	                   opt-out `mark1 enable` refuses to enroll
//
// An ignored directory takes its whole subtree with it, as git does.
//
// # Explicitly REFUSED (never silently mis-matched)
//
//	!pattern           negation / un-ignore
//	[a-z] [abc]        character classes
//	\#  \!  \          backslash escapes
//
// A file containing any of these does not parse, and an unparseable (or
// unreadable) .mark1ignore excludes its ENTIRE workspace — see ignoreCache.
// The alternative, treating an unsupported line as "matches nothing", is the
// silent-widening failure CON-012 exists to prevent: the customer writes
// `[Pp]rivate/` believing it is excluded and the tailer reads it anyway.
//
// ponytail: this is a port of cortexd's matcher (rust/cortexd/src/l0_merkle),
// deliberately duplicated rather than shared — the two planes are different
// languages and neither may take a new dependency. It diverges in exactly one
// direction: cortexd DROPS `!` lines silently, this refuses the file. Both
// read strictly less than git would; only this one says so out loud. Nested
// per-directory ignore files and `.git/info/exclude` are unread in both.
package tailers

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// IgnoreFileName is the per-workspace exclusion file (01 §2).
const IgnoreFileName = ".mark1ignore"

type ignoreRule struct {
	anchored bool // matched from the workspace root, not by basename
	dirOnly  bool // trailing '/'
	segs     []string
}

// ignoreSet is one workspace root's parsed .mark1ignore.
type ignoreSet struct {
	rules []ignoreRule
	all   bool // bare `*` / `**`: the whole root is out
}

// parseIgnore parses the supported subset. Any refused construct fails the
// WHOLE file — a partially-honored exclusion list is a privacy control that
// lies about its own coverage.
func parseIgnore(text string) (*ignoreSet, error) {
	set := &ignoreSet{}
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// '!' is only special leading; 'foo!bar' is a literal name in git.
		if strings.HasPrefix(line, "!") {
			return nil, fmt.Errorf("line %d %q: `!` negation is unsupported — remove it or narrow the ignore instead", n+1, line)
		}
		if strings.ContainsAny(line, `[\`) {
			return nil, fmt.Errorf("line %d %q: character classes and backslash escapes are unsupported", n+1, line)
		}
		if line == "*" || line == "**" {
			set.all = true // same whole-repo opt-out `mark1 enable` refuses
			continue
		}
		pat := line
		dirOnly := strings.HasSuffix(pat, "/")
		pat = strings.TrimSuffix(pat, "/")
		anchored := strings.Contains(pat, "/")
		var segs []string
		for _, s := range strings.Split(pat, "/") {
			if s != "" {
				segs = append(segs, s)
			}
		}
		if len(segs) == 0 {
			return nil, fmt.Errorf("line %d %q: empty pattern", n+1, line)
		}
		set.rules = append(set.rules, ignoreRule{anchored: anchored, dirOnly: dirOnly, segs: segs})
	}
	return set, nil
}

// match reports whether rel (slash-separated, relative to the workspace root,
// "." for the root itself) is excluded.
func (ig *ignoreSet) match(rel string, isDir bool) bool {
	if ig.all {
		return true
	}
	var segs []string
	for _, s := range strings.Split(rel, "/") {
		if s != "" && s != "." {
			segs = append(segs, s)
		}
	}
	// git semantics: an ignored directory's contents are unconditionally out,
	// so every ancestor prefix is tested as a directory.
	for end := 1; end <= len(segs); end++ {
		prefixIsDir := end < len(segs) || isDir
		for i := range ig.rules {
			if ig.rules[i].match(segs[:end], prefixIsDir) {
				return true
			}
		}
	}
	return false
}

func (r *ignoreRule) match(path []string, isDir bool) bool {
	if r.dirOnly && !isDir {
		return false
	}
	if r.anchored {
		return segsMatch(r.segs, path)
	}
	// Unanchored: the pattern matches the basename at any depth.
	return segsMatch(r.segs, path[len(path)-1:])
}

// segsMatch: `**` spans whole segments, `*`/`?` glob within one.
func segsMatch(pat []string, path []string) bool {
	switch {
	case len(pat) == 0:
		return len(path) == 0
	case pat[0] == "**":
		// zero or more whole segments
		return segsMatch(pat[1:], path) || (len(path) > 0 && segsMatch(pat, path[1:]))
	case len(path) == 0:
		return false
	default:
		return globMatch(pat[0], path[0]) && segsMatch(pat[1:], path[1:])
	}
}

func globMatch(pat, s string) bool {
	switch {
	case pat == "":
		return s == ""
	case pat[0] == '*':
		return globMatch(pat[1:], s) || (s != "" && globMatch(pat, s[1:]))
	case s == "":
		return false
	case pat[0] == '?':
		return globMatch(pat[1:], s[1:])
	default:
		return pat[0] == s[0] && globMatch(pat[1:], s[1:])
	}
}

// ignoreCache holds one root's parsed .mark1ignore and re-stats it on every
// consult, so a file the customer writes mid-session takes effect on the next
// discovery rather than the next daemon restart. Re-parsed only when
// (mtime, size) moves.
//
// FAIL-CLOSED (02 CON-007: fail-closed for legality and secrets). A
// .mark1ignore that exists but cannot be read or parsed returns an error, and
// Allowed turns that into "nothing under this root may be read". Degrading to
// "ignore nothing" would silently widen the read surface at exactly the moment
// the customer's consent record became unreadable.
//
// ponytail: (mtime, size) invalidation, so an in-place edit that preserves
// both within the filesystem's timestamp granularity is missed until the next
// change; a content hash if that ever matters.
type ignoreCache struct {
	dir string

	mu     sync.Mutex
	loaded bool
	mod    time.Time
	size   int64
	set    *ignoreSet // nil = no .mark1ignore at this root
	err    error
}

func (c *ignoreCache) current() (*ignoreSet, error) {
	path := filepath.Join(c.dir, IgnoreFileName)
	var mod time.Time
	var size int64
	fi, serr := os.Stat(path)
	switch {
	case serr == nil:
		mod, size = fi.ModTime(), fi.Size()
	case errors.Is(serr, fs.ErrNotExist):
		// No exclusion file: the roots are the whole oracle for this root.
	default:
		// Cannot even tell whether the customer wrote one.
		return nil, fmt.Errorf("stat %s: %w", path, serr)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// A failed load is never cached: repairing a .mark1ignore's permissions or
	// syntax changes neither mtime nor size, so a latched error would leave the
	// workspace dark until the daemon restarted.
	if c.loaded && c.err == nil && c.mod.Equal(mod) && c.size == size {
		return c.set, nil
	}
	c.loaded, c.mod, c.size, c.set, c.err = true, mod, size, nil, nil
	if serr == nil {
		switch data, rerr := os.ReadFile(path); {
		case rerr != nil:
			c.err = rerr
		default:
			set, perr := parseIgnore(string(data))
			if perr != nil {
				c.err = fmt.Errorf("%s: %w", path, perr)
			} else {
				c.set = set
			}
		}
	}
	if c.err != nil {
		// The refusal must be visible: Allowed is a bool, so this is the only
		// place that can say WHY the workspace went dark.
		slog.Warn("tailers: .mark1ignore unreadable — excluding the whole workspace until it parses (fail-closed, 02 CON-007)",
			"root", c.dir, "err", c.err)
	}
	return c.set, c.err
}
