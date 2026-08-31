// Package report is 08 §7.5: GET /api/v1/reports/tvo (§3.3) with the
// identity available (device token; an operator OIDC token can be supplied
// via MARK1_OPERATOR_TOKEN), printing TVO always WITH its coverage band and
// cost basis. Below the coverage floor with --guarantee-grade the numbers
// still print but the guarantee is refused outright (M1E-5004, exit 4) —
// refused, never caveated.
package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

type Options struct {
	Window         string // e.g. 30d
	Cohort         string
	GuaranteeGrade bool
}

// TVO mirrors §3.3's response body; unknown fields pass through Raw so the
// CLI never narrows what the server said.
type TVO struct {
	TVO          json.Number `json:"tvo"`
	CoverageBand struct {
		ObservedFraction float64 `json:"observed_fraction"`
		Floor            float64 `json:"floor"`
	} `json:"coverage_band"`
	CostBasis string `json:"cost_basis"`
	Waste     struct {
		RetryLoopTokens     json.Number `json:"retry_loop_tokens"`
		ReExplorationTokens json.Number `json:"re_exploration_tokens"`
		OverModelTokens     json.Number `json:"over_model_tokens"`
	} `json:"waste"`
	GuaranteeGrade bool   `json:"guarantee_grade"`
	Refusal        string `json:"refusal,omitempty"`
}

func Run(ctx context.Context, env *cli.Env, opts Options) error {
	token := os.Getenv("MARK1_OPERATOR_TOKEN")
	if token == "" {
		doc, err := env.LoadEnrollment()
		if err != nil {
			if errors.Is(err, cli.ErrNotEnrolled) {
				return cli.Failf(cli.ExitNotEnrolled, "M1E-1002", "not enrolled and no MARK1_OPERATOR_TOKEN set")
			}
			return cli.Failf(cli.ExitRuntime, "", "reading enrollment: %v", err)
		}
		token = doc.DeviceToken
	}

	q := url.Values{}
	if opts.Window != "" {
		q.Set("window", opts.Window)
	}
	if opts.Cohort != "" {
		q.Set("cohort", opts.Cohort)
	}
	q.Set("cost_basis", "auto")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		env.BaseURL()+"/api/v1/reports/tvo?"+q.Encode(), nil)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "building request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := env.Client().Do(req)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "fetching report: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		code, msg := cli.APIError(resp)
		// Persist what the server just said about the device identity (401 ⇒
		// expired, M1E-1003 ⇒ revoked) so status/enroll surface the recovery
		// path — but only when the device token was the credential presented;
		// an operator token's refusal says nothing about this enrollment.
		if os.Getenv("MARK1_OPERATOR_TOKEN") == "" {
			env.NoteAuthRefusal(resp.StatusCode, code)
		}
		return cli.Failf(cli.ExitNotEnrolled, code, "authentication refused: %s", msg)
	default:
		code, msg := cli.APIError(resp)
		return cli.Failf(cli.ExitRuntime, code, "report endpoint returned HTTP %d: %s", resp.StatusCode, msg)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "reading response: %v", err)
	}
	var tvo TVO
	if err := json.Unmarshal(body, &tvo); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "malformed report body: %v", err)
	}

	// --json passes the server's object through under the global contract's
	// ok envelope — the CLI adds nothing and hides nothing.
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "malformed report body: %v", err)
	}
	out := map[string]any{"ok": true, "report": raw}

	if err := env.Emit(out, func(w io.Writer) { renderHuman(w, &tvo) }); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "emit: %v", err)
	}

	// §7.5: the numbers print WITH the refusal notice; exit 4 only when
	// guarantee grade was explicitly requested and refused.
	if opts.GuaranteeGrade && !tvo.GuaranteeGrade {
		ee := cli.Failf(cli.ExitRefused, "M1E-5004", "guarantee-grade refused: %s", tvo.Refusal)
		ee.Emitted = true
		return ee
	}
	return nil
}

func renderHuman(w io.Writer, t *TVO) {
	_, _ = fmt.Fprintf(w, "tvo           %s (%s basis)\n", t.TVO, t.CostBasis)
	_, _ = fmt.Fprintf(w, "coverage      %.2f observed (floor %.2f)\n",
		t.CoverageBand.ObservedFraction, t.CoverageBand.Floor)
	_, _ = fmt.Fprintf(w, "waste         retry_loop=%s re_exploration=%s over_model=%s\n",
		t.Waste.RetryLoopTokens, t.Waste.ReExplorationTokens, t.Waste.OverModelTokens)
	if t.GuaranteeGrade {
		_, _ = fmt.Fprintln(w, "guarantee     GRADE OK")
	} else if t.Refusal != "" {
		_, _ = fmt.Fprintf(w, "guarantee     REFUSED: %s\n", t.Refusal)
	} else {
		_, _ = fmt.Fprintln(w, "guarantee     not guarantee-grade")
	}
}
