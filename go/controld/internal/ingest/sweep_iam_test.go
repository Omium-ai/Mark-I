package ingest

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
)

// controldDeletable is every ingest-bucket object pattern controld's IRSA role may s3:DeleteObject, read from the prod Terraform.
func controldDeletable(t *testing.T) []*regexp.Regexp {
	t.Helper()
	tf, err := os.ReadFile("../../../../deploy/terraform/envs/prod/irsa.tf")
	if err != nil {
		t.Fatal(err)
	}
	doc := regexp.MustCompile(`(?s)data "aws_iam_policy_document" "controld" \{(.*?)\n\}`).FindSubmatch(tf)
	if doc == nil {
		t.Fatal("irsa.tf has no controld policy document")
	}
	var out []*regexp.Regexp
	for _, st := range regexp.MustCompile(`(?s)statement \{(.*?)\n  \}`).FindAllSubmatch(doc[1], -1) {
		if !regexp.MustCompile(`actions\s*=\s*\[[^\]]*"s3:DeleteObject"`).Match(st[1]) {
			continue
		}
		res := regexp.MustCompile(`(?s)resources\s*=\s*\[(.*?)\]`).FindSubmatch(st[1])
		if res == nil {
			t.Fatal("a DeleteObject statement without resources")
		}
		for _, q := range regexp.MustCompile(`"\$\{local\.bucket_arns\.ingest\}/([^"]+)"`).FindAllSubmatch(res[1], -1) {
			glob := strings.NewReplacer(`\*`, `.*`, `\?`, `.`).Replace(regexp.QuoteMeta(string(q[1])))
			out = append(out, regexp.MustCompile(`^`+glob+`$`))
		}
	}
	return out
}

// H1: every prefix the daily sweep deletes (quarantine twins, contributions, E1 parts) is deletable by controld's role, the keys built by the same functions that land them; the replay log stays undeletable.
func TestControldRoleMayDeleteEverySweptPrefix(t *testing.T) {
	allowed := controldDeletable(t)
	deletable := func(key string) bool {
		for _, re := range allowed {
			if re.MatchString(key) {
				return true
			}
		}
		return false
	}
	tenant, batch, task := uuid.New(), mustV7(t), uuid.New()
	for sweep, key := range map[string]string{
		"SweepTenant/batch":        s3land.QuarantineKey(tenant, batch),
		"SweepTenant/e1":           s3land.EvidenceQuarantineKey(tenant, task, time.Now()),
		"SweepContributions":       s3land.ContributionKey(tenant, batch),
		"SweepEvidence/withdrawal": s3land.EvidenceKey(tenant, task),
	} {
		if !deletable(key) {
			t.Errorf("%s deletes %s, which controld's IRSA policy does not allow (AccessDenied, retried forever)", sweep, key)
		}
	}
	if deletable(s3land.IngestKey(tenant, batch)) {
		t.Error("controld may delete the replay log (t/<tenant>/ingest/v1/)")
	}
}
