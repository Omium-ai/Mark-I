package contrib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
)

// TestFilterDiffReadsHostilePathNamesExactly: the path axis reads the path git printed, never a suffix a crafted name makes look like one — a name holding " b/" is not the path after it, a quoted name is decoded, both sides of a rename are held to the rules, a hunk line shaped like a header names nothing, and a header it cannot split unambiguously drops the section.
func TestFilterDiffReadsHostilePathNamesExactly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mark1ignore"), []byte("secrets b/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hunk := "@@ -1 +1 @@\n-old\n+new line here\n"
	for _, c := range []struct {
		name, sec string
		keep      bool
	}{
		{"plain", "diff --git a/app.go b/app.go\n--- a/app.go\n+++ b/app.go\n" + hunk, true},
		{"ignored dir whose name holds ' b/'", "diff --git a/secrets b/app/x b/secrets b/app/x\n--- a/secrets b/app/x\t\n+++ b/secrets b/app/x\t\n" + hunk, false},
		{"new file in the ignored dir", "diff --git a/secrets b/app/x b/secrets b/app/x\nnew file mode 100644\n--- /dev/null\n+++ b/secrets b/app/x\t\n@@ -0,0 +1 @@\n+k\n", false},
		{"allowed name holding ' b/'", "diff --git a/docs b/readme.md b/docs b/readme.md\n--- a/docs b/readme.md\t\n+++ b/docs b/readme.md\t\n" + hunk, true},
		{"quoted non-ASCII name", "diff --git \"a/caf\\303\\251.go\" \"b/caf\\303\\251.go\"\n--- \"a/caf\\303\\251.go\"\n+++ \"b/caf\\303\\251.go\"\n" + hunk, true},
		{"quoted secret name", "diff --git \"a/\\303\\251/.env\" \"b/\\303\\251/.env\"\n--- \"a/\\303\\251/.env\"\n+++ \"b/\\303\\251/.env\"\n" + hunk, false},
		{"quoted name with an escaped quote", "diff --git \"a/x\\\" b/.env\" \"b/x\\\" b/.env\"\n--- \"a/x\\\" b/.env\"\n+++ \"b/x\\\" b/.env\"\n" + hunk, false},
		{"rename out of a secret", "diff --git a/.env b/notes.txt\nsimilarity index 90%\nrename from .env\nrename to notes.txt\n--- a/.env\n+++ b/notes.txt\n" + hunk, false},
		{"pure rename into a secret", "diff --git a/notes.txt b/.env\nsimilarity index 100%\nrename from notes.txt\nrename to .env\n", false},
		{"hunk line shaped like a header", "diff --git a/app.go b/app.go\n--- a/app.go\n+++ b/app.go\n@@ -1 +1,2 @@\n-old\n+++ b/.env\n+-- a/.env\n", true},
		{"unsplittable header, no path lines", "diff --git a/x b/y\nold mode 100644\nnew mode 100755\n", false},
		{"unterminated quote", "diff --git \"a/x b/x\n--- \"a/x\n+++ \"b/x\n" + hunk, false},
	} {
		got := FilterDiff([]byte(c.sec), root, root)
		if (len(got) > 0) != c.keep {
			t.Errorf("%s: kept=%v, want %v", c.name, len(got) > 0, c.keep)
		}
	}
	mixed := "diff --git a/secrets b/app/x b/secrets b/app/x\n--- a/secrets b/app/x\t\n+++ b/secrets b/app/x\t\n" + hunk + "diff --git a/app.go b/app.go\n--- a/app.go\n+++ b/app.go\n" + hunk
	if got := string(FilterDiff([]byte(mixed), root, root)); strings.Contains(got, "secrets") || !strings.Contains(got, "a/app.go") {
		t.Fatalf("mixed diff filtered to %q", got)
	}
}

// TestAddedLinesTakesTheFileFromTheHeaderOnly: a hunk line that reads like `+++ b/other` is content, so its lines stay attributed to the section's own file.
func TestAddedLinesTakesTheFileFromTheHeaderOnly(t *testing.T) {
	got := addedLines([]byte("diff --git \"a/caf\\303\\251.go\" \"b/caf\\303\\251.go\"\n--- \"a/caf\\303\\251.go\"\n+++ \"b/caf\\303\\251.go\"\n@@ -1 +1,2 @@\n-old\n+++ b/other.go\n+return total\n"))
	if len(got) != 1 || len(got["café.go"]) != 2 {
		t.Fatalf("added = %v", got)
	}
}

// TestReconcileTenantNeverCarriesContributionAcrossTenants (M2/M3): contribute_outcomes set under one tenant — by the person or by a staff default — is off, undecided and purged once the device is enrolled in another; one set before any enrollment is adopted by the first.
func TestReconcileTenantNeverCarriesContributionAcrossTenants(t *testing.T) {
	dir := t.TempDir()
	on := func() {
		t.Helper()
		if err := consents.Write(dir, consents.Consents{E1: true, ContributeOutcomes: true}); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(Dir(dir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(Dir(dir), "task.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reset := func(want bool, tenant string) {
		t.Helper()
		got, err := ReconcileTenant(dir, tenant)
		if err != nil || got != want {
			t.Fatalf("ReconcileTenant(%q) = %v, %v; want %v", tenant, got, err, want)
		}
	}
	gone := func() {
		t.Helper()
		c := consents.Read(dir)
		_, derr := os.Stat(defaultPath(dir))
		_, perr := os.Stat(Dir(dir))
		if c.ContributeOutcomes || !c.E1 || Decided(dir) || !os.IsNotExist(derr) || !os.IsNotExist(perr) {
			t.Fatalf("after a switch: consents %+v decided %v default %v pending %v", c, Decided(dir), derr, perr)
		}
	}

	on()
	if err := MarkDefault(dir, "staff"); err != nil {
		t.Fatal(err)
	}
	if Decided(dir) {
		t.Fatal("a staff default recorded as the person's decision")
	}
	reset(false, "")
	reset(false, "staff")
	reset(true, "personal")
	gone()

	on()
	if err := MarkDecided(dir, ""); err != nil {
		t.Fatal(err)
	}
	reset(false, "first")
	if tn, ok := stampedTenant(dir); !ok || tn != "first" || !consents.Read(dir).ContributeOutcomes {
		t.Fatalf("a choice made before enrollment is adopted by the first tenant: %q %v", tn, ok)
	}
	reset(true, "second")
	gone()

	on()
	if err := os.WriteFile(decidedPath(dir), []byte("2026-09-01T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reset(false, "first")
	reset(true, "second")
	gone()
}
