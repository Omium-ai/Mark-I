package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const childEnv = "M1_BOOT_REFUSAL_CHILD"

// 05 §1.2's boot refusals are only worth their name if they TERMINATE. Every
// Must* in main() is documented as un-caught "so a broken deploy crashloops
// instead of quietly degrading", and config_test.go proves each required key
// makes Load() return an error — but Load is not the boot path. MustLoad is,
// and it routes through `var fatalf = log.Fatalf` (config.go:20), a seam no
// test had ever touched. Which is the problem: MustLoad returns `c` after
// calling fatalf, so a fatalf that does not exit hands main() a ZERO Config
// and boot continues with an empty Postgres user, an empty ClickHouse
// password and a nil signing seed. That is the exact "quietly degraded"
// outcome §1.2 forbids, and no in-process test can see it, because an
// in-process test has to replace the very function whose exiting is the
// property.
//
// So this runs the real main() in a real child process and asserts the
// process died. Nothing is stubbed; the only thing injected is one blank
// environment variable.
func TestBootRefusalCrashloopsRatherThanDegrading(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		main()
		// Reached only if the refusal did not terminate. Returning lets the
		// child exit 0, which is precisely what the parent fails on.
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBootRefusalCrashloopsRatherThanDegrading$")
	// Every required key gets a well-formed value except the one under test, so
	// the refusal is unambiguously about POSTGRES_HOST and not about whichever
	// key config.Load happens to check first. Inherited on top of os.Environ so
	// a developer's own POSTGRES_HOST cannot rescue the child.
	cmd.Env = append(os.Environ(),
		childEnv+"=1",
		"POSTGRES_HOST=",
		"POSTGRES_DB=mark1",
		"POSTGRES_APP_USER=controld_app",
		"POSTGRES_APP_PASSWORD=pw",
		"CLICKHOUSE_ADDR=ch:8123",
		"CLICKHOUSE_INGEST_PASSWORD=chp",
		"CLICKHOUSE_QUERY_PASSWORD=chq",
		"S3_INGEST_BUCKET=mark1-ingest",
		"AUTH_TOKEN_ED25519_SEED="+strings.Repeat("ab", 32),
		"SERVER_CHAIN_ED25519_SEED="+strings.Repeat("cd", 32),
	)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out

	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("controld did not exit within the deadline: a boot refusal that blocks is not a "+
			"crashloop, it is a pod that never becomes ready and never restarts. Output:\n%s", out.String())
	}
	if err == nil {
		t.Fatalf("controld booted to completion with POSTGRES_HOST unset and exited 0. R1 refused "+
			"in config.Load, so MustLoad's fatalf did not terminate and main() ran on the zero "+
			"Config that MustLoad returns after it. Output:\n%s", out.String())
	}
	// Exit status alone is NOT the property, and asserting it was decoration: with
	// fatalf swapped for log.Printf the refusal still prints, boot step 2 still runs
	// on the zero Config MustLoad returns, pg.MustOpenApp fails to dial, and the
	// process still exits 1 — indistinguishable from a correct crashloop by exit
	// code and by a substring search for the key. What separates them is that the
	// degraded run keeps GOING: it emitted a second line, dialling Postgres as the
	// local developer with `user=anurag database=`. So the assertion is that the
	// refusal is the LAST thing controld ever says.
	lines := []string{}
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 || !strings.Contains(lines[len(lines)-1], "POSTGRES_HOST") {
		t.Fatalf("controld died, but the R1 refusal was not its last word — it carried on past "+
			"boot step 1 on the zero Config that MustLoad returns after a non-terminating fatalf, "+
			"and died later for some other reason. Output:\n%s", out.String())
	}
}
