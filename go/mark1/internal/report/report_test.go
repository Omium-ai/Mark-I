// A stub httptest server proves the client's §3.3 contract. The guarantee-grade
// case serves controld's own fixture (querychoke/testdata/tvo_report_guarantee_body.json,
// asserted there against the real handler's output), so the CLI renders exactly
// what controld emits — one fixture, two asserters.
package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

func enrolledEnv(t *testing.T, server string) (*cli.Env, *bytes.Buffer) {
	t.Helper()
	t.Setenv("MARK1_OPERATOR_TOKEN", "") // a real operator token must not sway these tests
	out := &bytes.Buffer{}
	env := &cli.Env{StateDir: t.TempDir(), Server: server, JSON: true, Stdout: out, Stderr: os.Stderr}
	if err := env.SaveEnrollment(&cli.Enrollment{
		Version: 1, State: "active", DeviceToken: "tok-1",
		TokenExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return env, out
}

func tvoStub(t *testing.T, guaranteeGrade bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/reports/tvo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":{"code":"M1E-1001","message":"caller lacks operator role"}}`)
			return
		}
		if r.URL.Query().Get("window") != "30d" || r.URL.Query().Get("cost_basis") != "auto" {
			t.Errorf("query %s", r.URL.RawQuery)
		}
		body := map[string]any{
			"tvo": 4.2, "trend": []float64{1, 2},
			"coverage_band": map[string]float64{"observed_fraction": 0.94, "floor": 0.85},
			"cost_basis":    "usd", "task_seg_version": "task_seg.v1",
			"waste":           map[string]int{"retry_loop_tokens": 100, "re_exploration_tokens": 50, "over_model_tokens": 25},
			"guarantee_grade": guaranteeGrade,
		}
		if !guaranteeGrade {
			body["refusal"] = "M1E-5004 coverage below floor"
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestReportHappyPath(t *testing.T) {
	srv := tvoStub(t, true)
	env, out := enrolledEnv(t, srv.URL)
	if err := Run(context.Background(), env, Options{Window: "30d"}); err != nil {
		t.Fatal(err)
	}
	var res struct {
		OK     bool           `json:"ok"`
		Report map[string]any `json:"report"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout not one JSON object: %v", err)
	}
	// §7.5: the coverage band and cost basis are ALWAYS in the output.
	if !res.OK || res.Report["coverage_band"] == nil || res.Report["cost_basis"] != "usd" {
		t.Fatalf("result %+v", res)
	}
}

// TestReportGuaranteeGradeRefusal: §7.5 — the numbers print WITH the
// refusal, and --guarantee-grade turns the refusal into exit 4 (M1E-5004).
func TestReportGuaranteeGradeRefusal(t *testing.T) {
	srv := tvoStub(t, false)
	env, out := enrolledEnv(t, srv.URL)
	err := Run(context.Background(), env, Options{Window: "30d", GuaranteeGrade: true})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRefused || ee.M1E != "M1E-5004" || !ee.Emitted {
		t.Fatalf("got %v, want emitted exit 4 M1E-5004", err)
	}
	var res struct {
		OK     bool           `json:"ok"`
		Report map[string]any `json:"report"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Report["tvo"] == nil {
		t.Fatal("refusal suppressed the numbers; §7.5 prints them WITH the notice")
	}
}

func TestReportWithoutGuaranteeFlagStillExitsZero(t *testing.T) {
	srv := tvoStub(t, false)
	env, _ := enrolledEnv(t, srv.URL)
	if err := Run(context.Background(), env, Options{Window: "30d"}); err != nil {
		t.Fatalf("non-guarantee report below floor must exit 0, got %v", err)
	}
}

func TestReportAuthRefused(t *testing.T) {
	srv := tvoStub(t, true)
	env, _ := enrolledEnv(t, srv.URL)
	doc, _ := env.LoadEnrollment()
	doc.DeviceToken = "wrong"
	if err := env.SaveEnrollment(doc); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), env, Options{Window: "30d"})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitNotEnrolled || ee.M1E != "M1E-1001" {
		t.Fatalf("got %v, want exit 3 M1E-1001", err)
	}
}

func TestReportNotEnrolled(t *testing.T) {
	t.Setenv("MARK1_OPERATOR_TOKEN", "")
	env := &cli.Env{StateDir: t.TempDir(), Stdout: os.Stderr, Stderr: os.Stderr}
	err := Run(context.Background(), env, Options{Window: "30d"})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitNotEnrolled {
		t.Fatalf("got %v, want exit 3", err)
	}
}

// TestReportGuaranteeGradeEndToEnd: FR-CLI-005's positive control — the body
// controld's handler emits for a covered, shed-free day under a usd regime
// pinned to the price table (querychoke TestTVOReportGuaranteeGradeFromRegime
// locks the fixture to the handler) renders as a guarantee-grade report with
// its band, basis and price-table pin, and --guarantee-grade exits 0.
func TestReportGuaranteeGradeEndToEnd(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "controld", "internal", "querychoke", "testdata", "tvo_report_guarantee_body.json"))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["guarantee_grade"] != true || !strings.HasPrefix(body["price_table_version"].(string), "model_prices.v1@sha256:") {
		t.Fatalf("fixture is not a guarantee-grade usd body: %s", raw)
	}
	body["trend"] = []map[string]any{{"day": "2026-09-16", "tvo": body["tvo"]}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/reports/tvo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	for _, jsonOut := range []bool{true, false} {
		env, out := enrolledEnv(t, srv.URL)
		env.JSON = jsonOut
		if err := Run(context.Background(), env, Options{Window: "30d", GuaranteeGrade: true}); err != nil {
			t.Fatalf("json=%v: guarantee-grade report refused: %v", jsonOut, err)
		}
		if jsonOut {
			var res struct {
				OK     bool           `json:"ok"`
				Report map[string]any `json:"report"`
			}
			if err := json.Unmarshal(out.Bytes(), &res); err != nil {
				t.Fatal(err)
			}
			if !res.OK || res.Report["guarantee_grade"] != true || res.Report["price_table_version"] != body["price_table_version"] ||
				res.Report["cost_basis"] != "usd" || res.Report["coverage_band"] == nil {
				t.Fatalf("json passthrough narrowed the report: %s", out.String())
			}
			continue
		}
		for _, line := range []string{
			"tvo           100 (usd basis)",
			"prices        " + body["price_table_version"].(string),
			"coverage      0.98 observed (floor 0.95)",
			"waste         retry_loop=10 re_exploration=20 over_model=30",
			"guarantee     GRADE OK",
		} {
			if !strings.Contains(out.String(), line+"\n") {
				t.Fatalf("human render lacks %q:\n%s", line, out.String())
			}
		}
	}
}
