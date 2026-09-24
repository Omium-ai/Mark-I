// Package verifyreceipts is 08 §7.7: fetch + orchestrate + honest exit
// codes. It wraps the standalone open-source verifier (rust/verifier —
// same code, same verdicts) rather than growing a fourth crypto
// implementation: the default network path is GET /api/v1/receipts/export +
// /api/v1/receipts/keys (§7.7 as amended — the export is DEFINED as
// byte-loadable by the verifier, no translation layer; the paginated §3.4
// rows serve dashboards, not auditors), landed as local files and handed to
// `mark1-verifier` (PATH, or MARK1_VERIFIER to point elsewhere), whose exit
// code IS the verdict (0 valid, 5 defect, 1 input) and whose --json stdout
// IS §7.7's shape.
package verifyreceipts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

type Options struct {
	From           string // export.jsonl or a dir of *.jsonl; empty = fetch from the server
	AgainstWitness bool
	Offline        bool
	Keys           string // local key-manifest snapshot; required with --offline
	Witness        string // local witness snapshot; required with --against-witness
}

func Run(ctx context.Context, env *cli.Env, opts Options) error {
	verifier := os.Getenv("MARK1_VERIFIER")
	if verifier == "" {
		var err error
		verifier, err = exec.LookPath("mark1-verifier")
		if err != nil {
			return cli.Failf(cli.ExitRuntime, "",
				"mark1-verifier not on PATH — install it (rust/verifier) or set MARK1_VERIFIER")
		}
	}

	// --offline touches no network by contract: "Omium's servers are
	// unreachable", executable. Both inputs must therefore be local files.
	if opts.Offline {
		if opts.From == "" || opts.Keys == "" {
			return cli.Failf(cli.ExitUsage, "", "--offline requires --from and --keys (local snapshots; no network by design)")
		}
	}
	if opts.AgainstWitness && opts.Witness == "" {
		// The witness snapshot format is the verifier's contract; fetching
		// tlog heads into it is a later row — a local snapshot is required.
		return cli.Failf(cli.ExitUsage, "", "--against-witness requires --witness <snapshot>")
	}

	tmpDir, err := os.MkdirTemp("", "mark1-verify-*")
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// One enrollment read serves both network fetches; local-only invocations
	// (--from + --keys) never require it, so verify works fully offline.
	var doc *cli.Enrollment
	if opts.From == "" || opts.Keys == "" {
		doc, err = env.LoadEnrollment()
		if err != nil {
			if errors.Is(err, cli.ErrNotEnrolled) {
				return cli.Failf(cli.ExitNotEnrolled, "M1E-1002", "not enrolled — use --from and --keys for offline verification")
			}
			return cli.Failf(cli.ExitRuntime, "", "reading enrollment: %v", err)
		}
	}

	chainPath, err := resolveChain(ctx, env, opts, doc, tmpDir)
	if err != nil {
		return err
	}
	keysPath := opts.Keys
	if keysPath == "" {
		keysPath, err = fetchKeys(ctx, env, doc, tmpDir)
		if err != nil {
			return err
		}
	}

	args := []string{"verify", "--chain", chainPath, "--keys", keysPath}
	if opts.Witness != "" {
		args = append(args, "--witness", opts.Witness)
	}
	if env.JSON {
		args = append(args, "--json")
	}

	//nolint:gosec // G204: MARK1_VERIFIER or LookPath — the operator's own PATH, args passed as a slice, no shell
	cmd := exec.CommandContext(ctx, verifier, args...)
	cmd.Stdout = env.Stdout // the verifier's report IS our output, verbatim
	cmd.Stderr = env.Stderr
	err = cmd.Run()
	if err == nil {
		return nil
	}
	var xe *exec.ExitError
	if errors.As(err, &xe) {
		// Exit-code passthrough for the verdict; anything else the verifier
		// says (its 1 = input, its 2 = usage of OUR making) is our runtime
		// failure — the operator typed nothing wrong.
		if xe.ExitCode() == 5 {
			ee := cli.Failf(cli.ExitVerify, "", "chain defect(s) found — see report")
			ee.Emitted = true
			return ee
		}
		return cli.Failf(cli.ExitRuntime, "", "mark1-verifier failed (exit %d)", xe.ExitCode())
	}
	return cli.Failf(cli.ExitRuntime, "", "running mark1-verifier: %v", err)
}

// resolveChain lands the chain export as one local JSONL file: --from file
// verbatim, --from dir as its *.jsonl concatenated in name order, otherwise
// fetched from GET /api/v1/receipts/export (08 §7.7's default network path).
func resolveChain(ctx context.Context, env *cli.Env, opts Options, doc *cli.Enrollment, tmpDir string) (string, error) {
	if opts.From == "" {
		return fetchChain(ctx, env, doc, tmpDir)
	}
	fi, err := os.Stat(opts.From)
	if err != nil {
		return "", cli.Failf(cli.ExitUsage, "", "--from %s: %v", opts.From, err)
	}
	if !fi.IsDir() {
		return opts.From, nil
	}
	matches, err := filepath.Glob(filepath.Join(opts.From, "*.jsonl"))
	if err != nil || len(matches) == 0 {
		return "", cli.Failf(cli.ExitUsage, "", "--from %s: no *.jsonl export files found", opts.From)
	}
	sort.Strings(matches)
	out := filepath.Join(tmpDir, "chain.jsonl")
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", cli.Failf(cli.ExitRuntime, "", "temp chain file: %v", err)
	}
	defer func() { _ = f.Close() }()
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			return "", cli.Failf(cli.ExitRuntime, "", "reading %s: %v", m, err)
		}
		if _, err := f.Write(data); err != nil {
			return "", cli.Failf(cli.ExitRuntime, "", "writing chain: %v", err)
		}
		if len(data) > 0 && data[len(data)-1] != '\n' {
			if _, err := f.Write([]byte("\n")); err != nil {
				return "", cli.Failf(cli.ExitRuntime, "", "writing chain: %v", err)
			}
		}
	}
	// Closed here, not by the defer: the close is where a buffered write finally fails,
	// and the deferred one reports that only after the verifier has already read a
	// truncated chain and returned a verdict on it.
	if err := f.Close(); err != nil {
		return "", cli.Failf(cli.ExitRuntime, "", "writing chain: %v", err)
	}
	return out, nil
}

// exportPage is the server's page bound on /api/v1/receipts/export
// (receipts/module.go pageParams caps limit at 5000): a page carrying
// exactly this many rows means more may follow; fewer means the chain end.
const exportPage = 5000

// fetchChain pages GET /api/v1/receipts/export (08 §7.7 as amended — the
// D-O ruling: the export IS the default network path) with the device token
// and lands the body verbatim. Each line already is one rust/verifier
// ExportRow — byte-loadable, the round-trip the receipts integration e2e
// proves — so this function copies bytes and never re-marshals a row: a
// re-encode could perturb the exact payload text the signatures cover.
func fetchChain(ctx context.Context, env *cli.Env, doc *cli.Enrollment, tmpDir string) (path string, err error) {
	out := filepath.Join(tmpDir, "chain.jsonl")
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", cli.Failf(cli.ExitRuntime, "", "temp chain file: %v", err)
	}
	// The close is where a buffered page finally fails to reach disk, and this file is then
	// handed to the verifier — which would read the truncation as a gap in the chain and name
	// a receipt defect. Discarding the close error turns a local disk error into the CLI
	// accusing the operator's own receipts of tampering, so it is promoted to the return.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			path, err = "", cli.Failf(cli.ExitRuntime, "", "writing chain: %v", cerr)
		}
	}()

	// since_seq is EXCLUSIVE (08 §3.4 cursor semantics, shared by the export
	// route), so the full-chain fetch starts at 0; starting at 1 silently
	// dropped receipt #1 and the verifier then failed the export as
	// gapped-at-genesis.
	sinceSeq := uint64(0)
	for {
		body, err := deviceGET(ctx, env, doc,
			fmt.Sprintf("%s/api/v1/receipts/export?since_seq=%d&limit=%d", env.BaseURL(), sinceSeq, exportPage))
		if err != nil {
			return "", err
		}
		lines := splitLines(body)
		if len(lines) == 0 {
			break
		}
		if _, err := f.Write(body); err != nil {
			return "", cli.Failf(cli.ExitRuntime, "", "writing chain: %v", err)
		}
		if body[len(body)-1] != '\n' {
			// Keep the file valid JSONL across page boundaries.
			if _, err := f.Write([]byte{'\n'}); err != nil {
				return "", cli.Failf(cli.ExitRuntime, "", "writing chain: %v", err)
			}
		}
		if len(lines) < exportPage {
			break
		}
		last, ok := seqOfLine(lines[len(lines)-1])
		if !ok || last <= sinceSeq {
			// No parseable forward progress: a hostile/broken page must not
			// loop us forever.
			return "", cli.Failf(cli.ExitRuntime, "", "export page made no seq progress (since_seq=%d)", sinceSeq)
		}
		// The page's last seq IS the next exclusive cursor; +1 here would
		// skip one receipt per page boundary.
		sinceSeq = last
	}
	return out, nil
}

// splitLines returns the non-empty lines of an NDJSON body.
func splitLines(body []byte) [][]byte {
	var out [][]byte
	for _, l := range bytes.Split(body, []byte{'\n'}) {
		if len(bytes.TrimSpace(l)) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// seqOfLine reads the paging cursor from one export row.
func seqOfLine(line []byte) (uint64, bool) {
	var row struct {
		Seq json.RawMessage `json:"seq"`
	}
	if json.Unmarshal(line, &row) != nil || row.Seq == nil {
		return 0, false
	}
	var n uint64
	if json.Unmarshal(row.Seq, &n) == nil {
		return n, true
	}
	// proto3 JSON projects uint64 as a string (08 §3.2 divergence table).
	var s string
	if json.Unmarshal(row.Seq, &s) == nil {
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
			return n, true
		}
	}
	return 0, false
}

// fetchKeys snapshots GET /api/v1/receipts/keys — the rust/verifier
// KeysFile the server emits natively (pubkey_hex, role split by list), so
// the body lands verbatim. Authenticated like the export: device keys are
// tenant-scoped (m1_001) and 08 §7.7 (amended) severs the old
// /.well-known/mark1-keys dependency — that public surface belongs to
// policydist's key ceremony, not this path.
func fetchKeys(ctx context.Context, env *cli.Env, doc *cli.Enrollment, tmpDir string) (string, error) {
	body, err := deviceGET(ctx, env, doc, env.BaseURL()+"/api/v1/receipts/keys")
	if err != nil {
		return "", err
	}
	out := filepath.Join(tmpDir, "keys.json")
	if err := os.WriteFile(out, body, 0o600); err != nil {
		return "", cli.Failf(cli.ExitRuntime, "", "writing key manifest: %v", err)
	}
	return out, nil
}

// deviceGET is the one authenticated fetch both export surfaces ride:
// Bearer device token, 64 MiB read bound (a full-chain export page), and the
// 401/403 path stamps what the server said about this enrollment
// (cli.NoteAuthRefusal: M1E-1003 ⇒ revoked, plain 401 ⇒ expired) so
// status/enroll surface the recovery instead of claiming ACTIVE forever.
func deviceGET(ctx context.Context, env *cli.Env, doc *cli.Enrollment, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, cli.Failf(cli.ExitRuntime, "", "building request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+doc.DeviceToken)
	resp, err := env.Client().Do(req)
	if err != nil {
		return nil, cli.Failf(cli.ExitRuntime, "", "fetching %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		code, msg := cli.APIError(resp)
		env.NoteAuthRefusal(resp.StatusCode, code)
		return nil, cli.Failf(cli.ExitNotEnrolled, code, "authentication refused: %s", msg)
	default:
		code, msg := cli.APIError(resp)
		return nil, cli.Failf(cli.ExitRuntime, code, "receipts endpoint returned HTTP %d: %s", resp.StatusCode, msg)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, cli.Failf(cli.ExitRuntime, "", "reading response: %v", err)
	}
	return body, nil
}
