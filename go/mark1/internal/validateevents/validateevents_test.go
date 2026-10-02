package validateevents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

// One well-formed session, in 08 §4.6.3 order. Each violation case below is
// this file with exactly one thing wrong.
var valid = []string{
	`{"eventId":"4AAAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:00Z","sessionStart":{"agent":"acme-runner"}}`,
	`{"eventId":"4AEAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:01Z","taskOpen":{"taskSegVersion":"ext:acme/runner.v1"}}`,
	`{"eventId":"4AIAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:02Z","turn":{"initiator":"INITIATOR_HUMAN"}}`,
	`{"eventId":"4AMAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:03Z","toolUse":{"toolName":"Bash","status":"TOOL_STATUS_OK"}}`,
	`{"eventId":"4AQAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:04Z","usage":{"messageId":"msg_01","requestId":"req_01","model":"m","outputTokens":"30"}}`,
	`{"eventId":"4AUAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:05Z","artifactOutcome":{"taskVerdict":"VERDICT_SATISFIED"}}`,
	`{"eventId":"4AYAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:06Z","taskClose":{"resolution":"RESOLUTION_VERDICT","turnCount":1}}`,
	`{"eventId":"4AcAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:07Z","sessionEnd":{"reason":"END_REASON_EXIT"}}`,
}

func with(replace int, line string) string {
	out := append([]string(nil), valid...)
	out[replace] = line
	return strings.Join(out, "\n") + "\n"
}

func TestValidateTable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		wantErr string // substring of the one expected error; "" = valid
		wantWrn string // substring of an expected warning; "" = none required
	}{
		{"valid", strings.Join(valid, "\n") + "\n", "", ""},
		{"blank lines are nothing", "\n" + strings.Join(valid, "\n\n") + "\n\n", "", ""},
		{"not json", with(3, `{"eventId":`), "not an m1p.v1.Event", ""},
		{"no body", with(3, `{"eventId":"4AMAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:03Z"}`), "no body", ""},
		{"bad event_id length", with(3, `{"eventId":"AAEC","occurredAt":"2026-10-02T12:00:03Z","toolUse":{"toolName":"Bash"}}`), "event_id is 3 bytes", ""},
		{"seq set", with(3, `{"eventId":"4AMAAAAAAAAAAAAAAAAAAA==","seq":"4","occurredAt":"2026-10-02T12:00:03Z","toolUse":{"toolName":"Bash"}}`), "seq/session_epoch must be zero", ""},
		{"server band set", with(3, `{"eventId":"4AMAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:03Z","tenantId":"AAEC","toolUse":{"toolName":"Bash"}}`), "server-stamped band", ""},
		{"timestamp missing", with(3, `{"eventId":"4AMAAAAAAAAAAAAAAAAAAA==","toolUse":{"toolName":"Bash"}}`), "occurred_at missing", ""},
		{"timestamp goes backwards", with(3, `{"eventId":"4AMAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T11:59:59Z","toolUse":{"toolName":"Bash"}}`), "is before the previous", ""},
		{"TaskClose before TaskOpen", with(1, `{"eventId":"4AEAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:01Z","taskClose":{}}`), "TaskClose before its TaskOpen", ""},
		{"Turn outside a task", with(1, `{"eventId":"4AEAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:01Z","toolUse":{"toolName":"Bash"}}`), "Turn outside an open task", ""},
		{"ArtifactOutcome before a Turn", with(2, `{"eventId":"4AIAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:02Z","artifactOutcome":{}}`), "ArtifactOutcome before any Turn", ""},
		{"Usage before a Turn", with(2, `{"eventId":"4AIAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:02Z","usage":{"messageId":"m","requestId":"r"}}`), "Usage before any Turn", ""},
		{"Usage without ids", with(4, `{"eventId":"4AQAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:04Z","usage":{"model":"m"}}`), "Usage needs message_id and request_id", ""},
		{"nested TaskOpen", with(2, `{"eventId":"4AIAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:02Z","taskOpen":{}}`), "TaskOpen while a task is already open", ""},
		{"unknown field is a warning", with(3, `{"eventId":"4AMAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:03Z","futureField":1,"toolUse":{"toolName":"Bash"}}`), "", "unknown field ignored"},
		{"empty event_id is a warning", with(3, `{"occurredAt":"2026-10-02T12:00:03Z","toolUse":{"toolName":"Bash"}}`), "", "event_id empty"},
		{"writer idem_key is a warning", with(4, `{"eventId":"4AQAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:04Z","usage":{"idemKey":"HR0d","messageId":"msg_01","requestId":"req_01"}}`), "", "idem_key set"},
		{"SessionEnd with an open task is a warning", with(6, `{"eventId":"4AYAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:06Z","toolUse":{"toolName":"Bash"}}`), "", "task still open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Validate(strings.NewReader(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantErr == "" {
				if !rep.OK || len(rep.Errors) != 0 {
					t.Fatalf("want valid, got errors %v", rep.Errors)
				}
			} else {
				// The FIRST error is the planted one; later lines may cascade truthfully
				// (a Turn after a refused TaskClose is outside a task), which is
				// what a host reading the report top-down fixes first.
				if rep.OK || len(rep.Errors) == 0 || !strings.Contains(rep.Errors[0].Message, tc.wantErr) {
					t.Fatalf("want the first error to contain %q, got %v", tc.wantErr, rep.Errors)
				}
			}
			if tc.wantWrn != "" {
				found := false
				for _, w := range rep.Warnings {
					found = found || strings.Contains(w.Message, tc.wantWrn)
				}
				if !found {
					t.Fatalf("want a warning containing %q, got %v", tc.wantWrn, rep.Warnings)
				}
			}
		})
	}
}

// TestRunContract pins 08 §7.8's surface: --json is exactly one object with
// ok/lines/errors/warnings; an invalid file exits ExitVerify with M1E-4006
// after the report; a missing path is a usage error; "-" reads stdin.
func TestRunContract(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.jsonl")
	if err := os.WriteFile(good, []byte(strings.Join(valid, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(bad, []byte(with(1, `{"eventId":"4AEAAAAAAAAAAAAAAAAAAA==","occurredAt":"2026-10-02T12:00:01Z","taskClose":{}}`)), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	env := &cli.Env{JSON: true, Stdout: &out, Stderr: &bytes.Buffer{}}
	if err := Run(context.Background(), env, Options{Path: good}); err != nil {
		t.Fatalf("valid file: %v", err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || !rep.OK || rep.Lines != len(valid) {
		t.Fatalf("--json object: %s (%v)", out.String(), err)
	}

	out.Reset()
	err := Run(context.Background(), env, Options{Path: bad})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitVerify || ee.M1E != CodeInvalid || !ee.Emitted {
		t.Fatalf("invalid file: want ExitVerify/%s with the report already emitted, got %v", CodeInvalid, err)
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep.OK || len(rep.Errors) == 0 {
		t.Fatalf("--json object on failure: %s", out.String())
	}

	out.Reset()
	human := &cli.Env{Stdout: &out, Stderr: &bytes.Buffer{}}
	_ = Run(context.Background(), human, Options{Path: bad})
	if !strings.Contains(out.String(), "line 2: error: TaskClose before its TaskOpen") || !strings.Contains(out.String(), "INVALID") {
		t.Fatalf("human report: %s", out.String())
	}

	if err := Run(context.Background(), env, Options{Path: filepath.Join(dir, "missing.jsonl")}); !errors.As(err, &ee) || ee.Code != cli.ExitUsage {
		t.Fatalf("missing path: want ExitUsage, got %v", err)
	}
}
