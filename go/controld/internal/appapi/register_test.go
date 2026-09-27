package appapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every consent key the routes can write has a register row with the same subprocessor, region and tier; the contribution and email rows match the bucket lifecycle and the chart that set them; the app's copy (Mark1-GUI settings/register.ts, held to register.json by its own test) and doc 10's table are held to Register here.
func TestRegisterCoversEveryConsentAndMatchesItsCopies(t *testing.T) {
	byKey := map[string]RegisterEntry{}
	for _, e := range Register {
		byKey[e.Key] = e
	}
	for _, k := range []consentKey{cloudJudgeConsent, cloudRMConsent, memoryExtractConsent} {
		e, ok := byKey[k.id]
		if !ok || e.Subprocessor != k.subprocessor || e.Region != k.region || e.MaxTier != k.maxTier {
			t.Fatalf("consent key %s has no matching register row: %+v", k.id, e)
		}
	}

	email := byKey["email"]
	tf, err := os.ReadFile("../../../../deploy/terraform/envs/prod/buckets.tf")
	if err != nil {
		t.Fatal(err)
	}
	for key, rule := range map[string]string{"contribute_outcomes": "contribution-ttl", "training": "corpus-default-ttl"} {
		e := byKey[key]
		ttl := regexp.MustCompile(`id\s+= "` + rule + `"[\s\S]*?days = (\d+)`).FindSubmatch(tf)
		if ttl == nil || e.RetentionDays == nil || string(ttl[1]) != strconv.Itoa(*e.RetentionDays) {
			t.Errorf("%s retention %v is not the bucket lifecycle %s %q", key, e.RetentionDays, rule, ttl)
		}
	}
	for _, key := range []string{"training", "contribute_outcomes"} {
		data, compute := byKey[key], byKey[key+":compute"]
		if compute.Subprocessor != "nebius-ai-cloud" || compute.MaxTier != data.MaxTier || compute.RetentionDays == nil || *compute.RetentionDays != 0 {
			t.Errorf("%s: the training-compute row must name Nebius AI Cloud at the data row's tier, kept only for the run: %+v", key, compute)
		}
	}
	values, err := os.ReadFile("../../../../deploy/helm/omium-mark1/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	region := regexp.MustCompile(`(?m)^\s+customerioRegion:\s*(\w+)`).FindSubmatch(values)
	if region == nil || string(region[1]) != email.Region || email.Subprocessor != "customer.io" {
		t.Errorf("email row %+v is not the chart's email.customerioRegion %q", email, region)
	}

	file := filepath.Join(goldenDir, "register.json")
	if *update {
		b, _ := json.MarshalIndent(Register, "", "  ")
		if err := os.WriteFile(file, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	var golden []RegisterEntry
	if err := json.Unmarshal(raw, &golden); err != nil || !reflect.DeepEqual(golden, Register) {
		t.Fatalf("register.json diverges from Register (run with -update): %v", err)
	}

	doc, err := os.ReadFile("../../../../docs/design/10-security-threat-model.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range Register {
		kept := "—"
		if e.RetentionDays != nil {
			kept = strconv.Itoa(*e.RetentionDays)
		}
		row := regexp.MustCompile(`(?m)^\| ` + "`" + regexp.QuoteMeta(e.Key) + "`" + ` \| [^|]+ \| ` + regexp.QuoteMeta(e.Subprocessor) + ` \| ` + regexp.QuoteMeta(e.Region) + ` \| ` + e.MaxTier + ` \| ` + kept + ` \|`)
		if !row.Match(doc) {
			t.Errorf("doc 10's register table has no row `| %s | … | %s | %s | %s | %s |`", e.Key, e.Subprocessor, e.Region, e.MaxTier, kept)
		}
	}
	if strings.Count(string(doc), "| `") == 0 {
		t.Fatal("doc 10 lost its tables")
	}
}
