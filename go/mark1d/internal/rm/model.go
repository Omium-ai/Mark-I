package rm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"lukechampine.com/blake3"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/procattr"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/supervise"
)

var ErrHashMismatch = errors.New("rm: model sha256 does not match the catalog pin")

func ModelPath(stateDir string, m Manifest) string {
	return filepath.Join(stateDir, "rm", "models", m.Ref(), "model.gguf")
}

func hashFile(path string, h hash.Hash) (int64, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a path under the daemon state dir or the resolved runtime
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	return io.Copy(h, f)
}

func sha256File(path string) (string, error) {
	h := sha256.New()
	if _, err := hashFile(path, h); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ensureModel returns the verified model path, downloading it once; a file that fails the pin is deleted, never served.
func ensureModel(ctx context.Context, client *http.Client, baseURL, stateDir string, m Manifest) (string, error) {
	path := ModelPath(stateDir, m)
	if got, err := sha256File(path); err == nil {
		if got == m.SHA256 {
			return path, nil
		}
		_ = os.Remove(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	url := strings.TrimRight(baseURL, "/") + "/" + m.Ref() + "/model.gguf"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("rm: download %s: transport error", url)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rm: download %s: HTTP %d", url, resp.StatusCode)
	}
	part := path + ".part"
	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: under the state dir
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, m.SizeBytes+1))
	err = errors.Join(err, f.Close())
	switch {
	case err != nil:
	case n != m.SizeBytes:
		err = fmt.Errorf("rm: download %s: %d bytes, manifest says %d", url, n, m.SizeBytes)
	case hex.EncodeToString(h.Sum(nil)) != m.SHA256:
		err = ErrHashMismatch
	}
	if err != nil {
		_ = os.Remove(part)
		return "", err
	}
	return path, os.Rename(part, path)
}

// ExecutionHash is rm-exec/v1, the manifest's execution_hash and RmScore.execution_hash: BLAKE3-256(GGUF bytes ‖ 0x00 ‖ runtime ‖ 0x00 ‖ template_sha hex).
func ExecutionHash(gguf, runtime string) ([]byte, error) {
	f, err := os.Open(gguf) //nolint:gosec // G304: a path under the daemon state dir
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return executionHash(f, runtime)
}

func executionHash(gguf io.Reader, runtime string) ([]byte, error) {
	h := blake3.New(32, nil)
	if _, err := io.Copy(h, gguf); err != nil {
		return nil, err
	}
	_, _ = h.Write([]byte("\x00" + runtime + "\x00" + TemplateSHA()))
	return h.Sum(nil), nil
}

var reBuild = regexp.MustCompile(`\(build ([0-9]+),`)

// RuntimeID is the runtime half of the execution hash, "llama.cpp b<build>" as the binary itself reports it (`--version`, the same on every platform's build of one tag).
func RuntimeID(ctx context.Context, bin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version") //nolint:gosec // G204: bin is FindRM() or an operator-set MARK1_RM
	procattr.Hide(cmd)
	cmd.Env = supervise.ChildEnv()
	out, _ := cmd.CombinedOutput()
	m := reBuild.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("rm: %s --version names no llama.cpp build", filepath.Base(bin))
	}
	return "llama.cpp b" + string(m[1]), nil
}
