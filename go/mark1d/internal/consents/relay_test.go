package consents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type fixed string

func (f fixed) Token(context.Context) (string, error) { return string(f), nil }

// TestRelaySendsTheWholeRecordAndStaysPendingUntilAcknowledged: nothing to
// relay before a consent exists; a recorded consent is pending until controld
// answers 2xx to the whole triple under the device token; a refusal or an
// outage leaves it pending; a later change (a revocation) is pending again.
func TestRelaySendsTheWholeRecordAndStaysPendingUntilAcknowledged(t *testing.T) {
	dir := t.TempDir()
	if Pending(dir) {
		t.Fatal("no record: nothing to relay")
	}
	if err := Write(dir, Consents{E1: true, CloudJudge: true, Training: true, Team: true}); err != nil {
		t.Fatal(err)
	}
	if !Pending(dir) {
		t.Fatal("a fresh record is pending")
	}
	var got []map[string]any
	var auth []string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/consents" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected %s %s %s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		auth = append(auth, r.Header.Get("Authorization"))
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Error(err)
		}
		got = append(got, m)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	ctx := context.Background()
	status = http.StatusServiceUnavailable
	if err := Relay(ctx, dir, srv.URL, fixed("tok")); err == nil || !Pending(dir) {
		t.Fatalf("a refused relay must stay pending: err=%v pending=%v", err, Pending(dir))
	}
	status = http.StatusOK
	if err := Relay(ctx, dir, srv.URL, fixed("tok")); err != nil || Pending(dir) {
		t.Fatalf("acknowledged relay: err=%v pending=%v", err, Pending(dir))
	}
	if len(got) != 2 || got[1]["e1"] != true || got[1]["cloud_judge"] != true || got[1]["training"] != true || got[1]["team"] != true || got[1]["contribute_outcomes"] != false || len(got[1]) != 7 || auth[1] != "Bearer tok" {
		t.Fatalf("relayed %v under %v", got, auth)
	}
	if err := Write(dir, Consents{E1: true, CloudJudge: true, Training: false, Team: false}); err != nil {
		t.Fatal(err)
	}
	if !Pending(dir) {
		t.Fatal("a revocation is pending until acknowledged")
	}
	if err := Relay(ctx, dir, srv.URL, fixed("tok")); err != nil || got[2]["team"] != false || got[2]["training"] != false || len(got[2]) != 7 {
		t.Fatalf("a team revocation relays team:false: err=%v %v", err, got)
	}
	if err := Write(dir, Consents{E1: true}); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if err := Relay(ctx, dir, srv.URL, fixed("tok")); err == nil || !Pending(dir) {
		t.Fatalf("controld down: err=%v pending=%v", err, Pending(dir))
	}
	if err := os.WriteFile(Path(dir), []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Relay(ctx, dir, srv.URL, fixed("tok")); err == nil {
		t.Fatal("a corrupt local record is never relayed as consent")
	}
}

// f85bff9Body is prod controld's consentsBody at f85bff9 (go/controld/internal/ingest/consents.go): three required fields, DisallowUnknownFields.
type f85bff9Body struct {
	E1         *bool `json:"e1"`
	CloudJudge *bool `json:"cloud_judge"`
	Training   *bool `json:"training"`
}

// currentBody is today's controld consentsBody: the later four optional, absent reads as off.
type currentBody struct {
	E1                 *bool `json:"e1"`
	CloudJudge         *bool `json:"cloud_judge"`
	Training           *bool `json:"training"`
	Team               bool  `json:"team"`
	ContributeOutcomes bool  `json:"contribute_outcomes"`
	LocalRM            bool  `json:"local_rm"`
	CloudRM            bool  `json:"cloud_rm"`
}

func strictServer(t *testing.T, into func() any, rows *[]map[string]any) *httptest.Server {
	t.Helper()
	return strictServerCounting(t, into, rows, new(int))
}

func strictServerCounting(t *testing.T, into func() any, rows *[]map[string]any, tries *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*tries++
		raw, _ := io.ReadAll(r.Body)
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		body := into()
		if err := dec.Decode(body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		*rows = append(*rows, m)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRelayWithdrawalLandsOnTheF85bff9Decoder: a new edge against prod controld f85bff9, whose strict decoder knows e1/cloud_judge/training only. A record with every later consent off is accepted as is; one with a later consent on is refused, and the retry with the three known fields carries the e1 withdrawal, which the cloud then acknowledges, while the record stays pending for the later fields.
func TestRelayWithdrawalLandsOnTheF85bff9Decoder(t *testing.T) {
	ctx := context.Background()
	var rows []map[string]any
	tries := 0
	srv := strictServerCounting(t, func() any { return &f85bff9Body{} }, &rows, &tries)

	dir := t.TempDir()
	if err := Write(dir, Consents{E1: true, CloudJudge: true}); err != nil {
		t.Fatal(err)
	}
	if err := Relay(ctx, dir, srv.URL, fixed("tok")); !errors.Is(err, ErrLegacyCloud) || tries != 2 || len(rows) != 1 || len(rows[0]) != 3 || !Acknowledged(dir).E1 || !Pending(dir) {
		t.Fatalf("explicit later fields refused, three landed: err=%v tries=%d rows=%v pending=%v", err, tries, rows, Pending(dir))
	}

	if err := Write(dir, Consents{E1: false, CloudJudge: true, LocalRM: true, ContributeOutcomes: true}); err != nil {
		t.Fatal(err)
	}
	err := Relay(ctx, dir, srv.URL, fixed("tok"))
	if !errors.Is(err, ErrLegacyCloud) || tries != 4 || len(rows) != 2 || rows[1]["e1"] != false || rows[1]["cloud_judge"] != true || len(rows[1]) != 3 {
		t.Fatalf("e1 withdrawal on the old decoder, full body tried first: err=%v tries=%d rows=%v", err, tries, rows)
	}
	if ack := Acknowledged(dir); ack.E1 || !ack.CloudJudge || ack.ContributeOutcomes || ack.LocalRM {
		t.Fatalf("acknowledged = %+v, want the three fields the old cloud took", ack)
	}
	if !Pending(dir) {
		t.Fatal("the later consents the old cloud could not take stay pending")
	}

	var upgraded []map[string]any
	srv2 := strictServer(t, func() any { return &currentBody{} }, &upgraded)
	if err := Relay(ctx, dir, srv2.URL, fixed("tok")); err != nil || Pending(dir) || len(upgraded) != 1 || upgraded[0]["contribute_outcomes"] != true || upgraded[0]["team"] != false {
		t.Fatalf("an upgraded cloud takes the full body on the next relay: err=%v rows=%v pending=%v", err, upgraded, Pending(dir))
	}
}

// TestRelaySendsEveryFieldExplicitlyToTheCurrentDecoder: today's controld reads an absent later field as unchanged, so every field goes out as true or false.
func TestRelaySendsEveryFieldExplicitlyToTheCurrentDecoder(t *testing.T) {
	var rows []map[string]any
	srv := strictServer(t, func() any { return &currentBody{} }, &rows)
	dir := t.TempDir()
	if err := Write(dir, Consents{E1: true, CloudRM: true}); err != nil {
		t.Fatal(err)
	}
	if err := Relay(context.Background(), dir, srv.URL, fixed("tok")); err != nil || Pending(dir) {
		t.Fatalf("err=%v pending=%v", err, Pending(dir))
	}
	want := map[string]any{"e1": true, "cloud_judge": false, "training": false, "team": false, "local_rm": false, "cloud_rm": true, "contribute_outcomes": false}
	if len(rows) != 1 || len(rows[0]) != len(want) {
		t.Fatalf("rows = %v", rows)
	}
	for k, v := range want {
		if rows[0][k] != v {
			t.Fatalf("%s = %v, want explicit %v: %v", k, rows[0][k], v, rows[0])
		}
	}
	if ack := Acknowledged(dir); !ack.CloudRM || !ack.E1 {
		t.Fatalf("acknowledged = %+v", ack)
	}
}

// TestRelayContributionWithdrawalIsAnExplicitFalse: withdrawing contribute_outcomes sends contribute_outcomes:false, never an absent field the cloud would read as unchanged.
func TestRelayContributionWithdrawalIsAnExplicitFalse(t *testing.T) {
	var rows []map[string]any
	srv := strictServer(t, func() any { return &currentBody{} }, &rows)
	dir := t.TempDir()
	for _, on := range []bool{true, false} {
		if err := Write(dir, Consents{E1: true, ContributeOutcomes: on}); err != nil {
			t.Fatal(err)
		}
		if err := Relay(context.Background(), dir, srv.URL, fixed("tok")); err != nil {
			t.Fatal(err)
		}
	}
	if len(rows) != 2 || rows[0]["contribute_outcomes"] != true {
		t.Fatalf("rows = %v", rows)
	}
	if v, ok := rows[1]["contribute_outcomes"]; !ok || v != false {
		t.Fatalf("withdrawal sent contribute_outcomes=%v (present %v), want explicit false", v, ok)
	}
	if Pending(dir) || Acknowledged(dir).ContributeOutcomes {
		t.Fatal("the withdrawal is acknowledged once controld took it")
	}
}

// TestSyncReadsTheEffectiveRow (review HIGH-2): the 2xx body's "consents" is the cloud's effective row, a field it does not name reading as on; a body without it and a refusal are no row at all. An omitted key leaves the body and reads false in sent.
func TestSyncReadsTheEffectiveRow(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, Consents{E1: true, Team: true}); err != nil {
		t.Fatal(err)
	}
	body, status := "", http.StatusOK
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = nil
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	for _, c := range []struct {
		body   string
		status int
		want   *Consents
	}{
		{`{"recorded_at":"x"}`, http.StatusOK, nil},
		{`{"consents":null}`, http.StatusOK, nil},
		{`{"consents":{"e1":"no"}}`, http.StatusOK, nil},
		{`{"consents":{"e1":false,"team":false}}`, http.StatusServiceUnavailable, nil},
		{`{"consents":{"e1":false,"team":false}}`, http.StatusOK, &Consents{CloudJudge: true, Training: true, LocalRM: true, CloudRM: true, ContributeOutcomes: true}},
	} {
		body, status = c.body, c.status
		sent, cloud, _ := Sync(context.Background(), dir, srv.URL, fixed("tok"))
		if (cloud == nil) != (c.want == nil) || (cloud != nil && *cloud != *c.want) || !sent.E1 || !sent.Team || len(got) != 7 {
			t.Errorf("%d %s: cloud %+v sent %+v body %v", c.status, c.body, cloud, sent, got)
		}
	}
	body, status = `{}`, http.StatusOK
	if sent, _, _ := Sync(context.Background(), dir, srv.URL, fixed("tok"), "team"); sent.Team || len(got) != 6 || got["team"] != nil {
		t.Fatalf("an omitted key is sent absent: sent %+v body %v", sent, got)
	}
}
