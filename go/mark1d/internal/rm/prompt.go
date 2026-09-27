package rm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// The rm-input/v1 contract, ported line for line from training_jobs/rm/prompt.py so train and serve render the same bytes.
const (
	TemplateVersion  = "rm-input/v1"
	Suffix           = "\n<|end|>\nIs this change a correct and complete solution to the task? Answer:"
	maxTaskChars     = 2700
	taskHead         = 1800
	MaxDiffChars     = 9000
	MaxSeqLen        = 4096
	oversizeSrcFrac  = 0.5
	AbstainNoChange  = "NO_CHANGE"
	AbstainOversize  = "OVERSIZE"
	AbstainNoTask    = "NO_TASK"
	AbstainNoRuntime = "NO_RUNTIME"
)

// TemplateSHA is what a manifest's template_sha must equal: sha256(TemplateVersion ‖ Suffix), hex.
func TemplateSHA() string {
	h := sha256.Sum256([]byte(TemplateVersion + Suffix))
	return hex.EncodeToString(h[:])
}

var (
	lockfiles = set("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "poetry.lock",
		"pipfile.lock", "go.sum", "composer.lock", "gemfile.lock", "uv.lock", "npm-shrinkwrap.json")
	vendorDirs = set("vendor", "node_modules", "third_party", "dist", "build", "__pycache__", ".git")
	binaryExt  = set("png", "jpg", "jpeg", "gif", "ico", "bmp", "pdf", "zip", "gz", "tgz", "bz2", "xz", "so",
		"dll", "exe", "dylib", "woff", "woff2", "ttf", "otf", "eot", "jar", "class", "pyc", "whl",
		"mp4", "mp3", "wav", "bin", "npy", "npz", "pkl", "parquet", "db", "sqlite")
	configExt   = set("json", "yaml", "yml", "toml", "ini", "cfg", "conf", "xml", "gradle", "properties", "lock")
	configNames = set("dockerfile", "makefile", "cmakelists.txt", ".gitignore", "setup.py", "setup.cfg", "tox.ini")
	docExt      = set("md", "rst", "txt", "adoc")
	testDirs    = set("test", "tests", "__tests__", "spec", "specs", "testing")
	langs       = map[string]string{
		"py": "python", "js": "javascript", "jsx": "javascript", "mjs": "javascript", "ts": "typescript",
		"tsx": "typescript", "java": "java", "kt": "kotlin", "go": "go", "rs": "rust", "c": "c", "h": "c",
		"cc": "cpp", "cpp": "cpp", "cxx": "cpp", "hpp": "cpp", "cs": "csharp", "rb": "ruby", "php": "php",
		"scala": "scala", "swift": "swift", "sh": "shell", "sql": "sql", "hs": "haskell", "ml": "ocaml",
	}
	narrativeRe = regexp.MustCompile(`(SUMMARY|NOTES|REPORT|CHANGES_|FIX_|IMPLEMENTATION|SOLUTION|VERIFICATION)`)
	testFileRe  = regexp.MustCompile(`(^test_.*\.py$|_test\.(py|go|rs|rb|cc|cpp)$|\.(test|spec)\.[jt]sx?$|Tests?\.(java|kt|cs)$|_spec\.rb$)`)
	// claimRe and suppressRe are Python's str patterns: \b, \s and (?i) rewritten to Python's Unicode meaning (Go's are ASCII, and Python's (?i) also folds ı/İ to i).
	claimRe = regexp.MustCompile(`(?i)` + strings.NewReplacer("i", `[iı\x{130}]`, `\b`, pyWordEnd).Replace(
		`(all (the )?tests? (now )?pass|tests? (now )?pass(es|ed)?\b|`+
			`(this|the) (fix|change|patch|implementation) (is|has been) (verified|confirmed|correct|tested)|`+
			`issue (is|has been) (now )?(fixed|resolved)|successfully (fixed|resolved|implemented)|`+
			`reviewer note|verified (correct|working)|fix verified)`))
	suppressRe = regexp.MustCompile(`(noqa|type:[\t\n\v\f\r\x1c-\x1f\x85\p{Z}]*ignore|@ts-ignore|@ts-expect-error|eslint-disable|#\[allow\(|@SuppressWarnings|` +
		`pytest\.mark\.(skip|xfail)|unittest\.skip|@Disabled|@Ignore` + pyWordEnd + `|(?:^|[^\p{L}\p{N}_])xit\(|\.skip\()`)
	pyUpper = strings.NewReplacer("ß", "SS", "ﬀ", "FF", "ﬁ", "FI", "ﬂ", "FL", "ﬃ", "FFI", "ﬄ", "FFL", "ﬅ", "ST", "ﬆ", "ST",
		"ŉ", "ʼN", "ǰ", "J\u030c", "ẖ", "H\u0331", "ẗ", "T\u0308", "ẘ", "W\u030a", "ẙ", "Y\u030a", "ẚ", "Aʾ")
	pyLower = strings.NewReplacer("İ", "i\u0307")
)

// pyWordEnd is Python's Unicode \b after a word character, outside any (?i) so no case fold widens the class.
const pyWordEnd = `(?-i:[^\p{L}\p{N}_]|$)`

// upper and lower are Python's str.upper/str.lower where they can change an ASCII match: the SpecialCasing entries Go's simple mapping lacks.
func upper(s string) string { return strings.ToUpper(pyUpper.Replace(s)) }
func lower(s string) string { return strings.ToLower(pyLower.Replace(s)) }

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

type fileDiff struct {
	path   string
	hunks  [][]string
	isNew  bool
	binary bool
}

// Rendered is the one model input: Text is all the runtime ever sees.
type Rendered struct {
	Prefix  string
	Abstain string
}

func (r Rendered) Text() string { return r.Prefix + Suffix }

func neutralize(s string) string { return strings.ReplaceAll(s, "<|", "< |") }

func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f })
}

func cleanPath(p string) string {
	p, _, _ = strings.Cut(p, "\t")
	p = pyStrip(p)
	if strings.HasPrefix(p, "a/") || strings.HasPrefix(p, "b/") {
		return p[2:]
	}
	return p
}

// splitLines is Python's str.splitlines: every boundary it honours, no trailing empty line.
func splitLines(s string) []string {
	var out []string
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch r := rs[i]; r {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, b.String())
			b.Reset()
		case '\r':
			out = append(out, b.String())
			b.Reset()
			if i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func splitFiles(diff string) []*fileDiff {
	var files []*fileDiff
	var cur *fileDiff
	lines := splitLines(diff)
	for i, line := range lines {
		nxt := ""
		if i+1 < len(lines) {
			nxt = lines[i+1]
		}
		switch {
		case strings.HasPrefix(line, "diff --git "):
			cur = &fileDiff{path: "?"}
			if j := strings.LastIndex(line, " b/"); j >= 0 {
				cur.path = cleanPath(line[j+3:])
			}
			files = append(files, cur)
		case strings.HasPrefix(line, "--- ") && strings.HasPrefix(nxt, "+++ "):
			if cur == nil || len(cur.hunks) > 0 {
				cur = &fileDiff{path: "?"}
				files = append(files, cur)
			}
			if pyStrip(line[4:]) == "/dev/null" {
				cur.isNew = true
			}
		case strings.HasPrefix(line, "+++ ") && cur != nil && len(cur.hunks) == 0:
			if pyStrip(line[4:]) != "/dev/null" {
				cur.path = cleanPath(line[4:])
			}
		case strings.HasPrefix(line, "@@"):
			if cur == nil {
				cur = &fileDiff{path: "?"}
				files = append(files, cur)
			}
			cur.hunks = append(cur.hunks, []string{line})
		case cur != nil && len(cur.hunks) > 0 && (line == "" || strings.ContainsRune(" +-\\", rune(line[0]))):
			cur.hunks[len(cur.hunks)-1] = append(cur.hunks[len(cur.hunks)-1], line)
		case cur != nil:
			if strings.HasPrefix(line, "new file mode") {
				cur.isNew = true
			}
			if strings.HasPrefix(line, "Binary files") || strings.HasPrefix(line, "GIT binary patch") {
				cur.binary = true
			}
		}
	}
	return files
}

func lastAfter(s, sep string) string {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[i+len(sep):]
	}
	return s
}

func pathRole(p string, isNew bool) string {
	var parts []string
	for _, x := range strings.Split(lower(p), "/") {
		if x != "" {
			parts = append(parts, x)
		}
	}
	base, dirs := "", []string(nil)
	if len(parts) > 0 {
		base, dirs = parts[len(parts)-1], parts[:len(parts)-1]
	}
	ext := ""
	if strings.Contains(base, ".") {
		ext = lastAfter(base, ".")
	}
	anyIn := func(m map[string]bool) bool { return slices.ContainsFunc(dirs, func(d string) bool { return m[d] }) }
	name := lastAfter(p, "/")
	switch {
	case lockfiles[base] || anyIn(vendorDirs) || binaryExt[ext] || strings.HasSuffix(base, ".min.js"):
		return "drop"
	case isNew && docExt[ext] && narrativeRe.MatchString(upper(name)):
		return "narrative"
	case testFileRe.MatchString(name) || anyIn(testDirs) || base == "conftest.py":
		return "test"
	case docExt[ext]:
		return "doc"
	case configExt[ext] || configNames[base]:
		return "config"
	}
	return "src"
}

func shortPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, "/")
}

func runeLen(s string) int { return len([]rune(s)) }

func truncateTask(task string) (string, bool) {
	task = pyStrip(neutralize(task))
	rs := []rune(task)
	if len(rs) <= maxTaskChars {
		return task, false
	}
	return string(rs[:taskHead]) + "\n[...]\n" + string(rs[len(rs)-(maxTaskChars-taskHead):]), true
}

func fileText(f *fileDiff, role string, hunks [][]string) string {
	p := shortPath(f.path)
	lines := []string{"--- a/" + p + " [role=" + role + "]", "+++ b/" + p}
	for _, h := range hunks {
		lines = append(lines, h...)
	}
	return strings.Join(lines, "\n")
}

type keptFile struct {
	idx   int
	f     *fileDiff
	role  string
	hunks [][]string
}

// Render is prompt.render(task, diff, maxDiffChars): nothing but these two strings can reach the model.
func Render(task, diff string, maxDiffChars int) Rendered {
	taskText, taskTrunc := truncateTask(task)
	var kept []keptFile
	adds, dels, supp := 0, 0, 0
	roles := map[string]int{}
	langCount := map[string]int{}
	var langOrder []string
	for idx, f := range splitFiles(neutralize(diff)) {
		role := pathRole(f.path, f.isNew)
		if role == "drop" || role == "narrative" || f.binary || len(f.hunks) == 0 {
			continue
		}
		var hunks [][]string
		for _, h := range f.hunks {
			body := []string{h[0]}
			for _, ln := range h[1:] {
				if strings.HasPrefix(ln, "+") && claimRe.MatchString(ln) {
					continue
				}
				if strings.HasPrefix(ln, "+") {
					adds++
					if suppressRe.MatchString(ln) {
						supp++
					}
				} else if strings.HasPrefix(ln, "-") {
					dels++
					if suppressRe.MatchString(ln) {
						supp--
					}
				}
				body = append(body, ln)
			}
			hunks = append(hunks, body)
		}
		roles[role]++
		if role == "src" {
			ext := ""
			if strings.Contains(f.path, ".") {
				ext = lower(lastAfter(f.path, "."))
			}
			l, ok := langs[ext]
			if !ok {
				l = "other"
			}
			if langCount[l] == 0 {
				langOrder = append(langOrder, l)
			}
			langCount[l]++
		}
		kept = append(kept, keptFile{idx, f, role, hunks})
	}
	if len(kept) == 0 || adds+dels == 0 {
		return Rendered{Abstain: AbstainNoChange}
	}

	order := map[string]int{"src": 0, "test": 1, "config": 2, "doc": 3}
	sorted := slices.Clone(kept)
	slices.SortStableFunc(sorted, func(a, b keptFile) int {
		if order[a.role] != order[b.role] {
			return order[a.role] - order[b.role]
		}
		return a.idx - b.idx
	})
	budget := maxDiffChars
	chosen := map[int]string{}
	srcTotal, srcKept := 0, 0
	truncated := false
	for _, k := range sorted {
		full := fileText(k.f, k.role, k.hunks)
		n := runeLen(full)
		if k.role == "src" {
			srcTotal += n
		}
		if n <= budget {
			chosen[k.idx] = full
			budget -= n + 1
			if k.role == "src" {
				srcKept += n
			}
			continue
		}
		truncated = true
		var part [][]string
		for _, h := range k.hunks {
			if runeLen(fileText(k.f, k.role, append(slices.Clone(part), h))) > budget {
				break
			}
			part = append(part, h)
		}
		if len(part) > 0 {
			txt := fileText(k.f, k.role, part)
			chosen[k.idx] = txt
			budget -= runeLen(txt) + 1
			if k.role == "src" {
				srcKept += runeLen(txt)
			}
		}
	}
	if srcTotal > 0 && float64(srcTotal-srcKept)/float64(srcTotal) > oversizeSrcFrac {
		return Rendered{Abstain: AbstainOversize}
	}

	lang := "none"
	best := 0
	for _, l := range langOrder {
		if langCount[l] > best {
			lang, best = l, langCount[l]
		}
	}
	tr := 0
	if truncated || taskTrunc {
		tr = 1
	}
	tt := 0
	if roles["test"] > 0 {
		tt = 1
	}
	meta := fmt.Sprintf("lang=%s files=%d add=%d del=%d src_files=%d test_files=%d config_files=%d test_touched=%d suppression_delta=%d truncated=%d",
		lang, len(kept), adds, dels, roles["src"], roles["test"], roles["config"]+roles["doc"], tt, supp, tr)
	idxs := make([]int, 0, len(chosen))
	for i := range chosen {
		idxs = append(idxs, i)
	}
	slices.Sort(idxs)
	body := make([]string, len(idxs))
	for i, idx := range idxs {
		body[i] = chosen[idx]
	}
	return Rendered{Prefix: "<|task|>\n" + taskText + "\n<|meta|> " + meta + "\n<|diff|>\n" + strings.Join(body, "\n")}
}
