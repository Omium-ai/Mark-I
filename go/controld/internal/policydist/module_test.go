package policydist

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

func testTenant(t *testing.T, id string) querychoke.TenantID {
	t.Helper()
	tid, err := querychoke.FromClaims(auth.Claims{TenantID: uuid.MustParse(id)})
	if err != nil {
		t.Fatal(err)
	}
	return tid
}

// ---------------------------------------------------------------------------
// ACK parsing (08 §3.2)
// ---------------------------------------------------------------------------

func TestParseAckAccepts(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	raw := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name string
		body string
		want Ack
	}{
		{
			name: "applied, unquoted seq, bare hex hash",
			body: `{"channel":"stable","seq":483,"bundle_hash":"` + hash + `","result":"applied"}`,
			want: Ack{Channel: "stable", Seq: 483, Result: "applied"},
		},
		{
			// proto3 JSON renders uint64 as a string; 08's own examples differ
			// between the SSE frame and the ACK body, and an edge is not going
			// to be refused over which side of that the doc meant.
			name: "applied, quoted seq",
			body: `{"channel":"stable","seq":"483","bundle_hash":"` + hash + `","result":"applied"}`,
			want: Ack{Channel: "stable", Seq: 483, Result: "applied"},
		},
		{
			name: "the retired blake3: label an older edge still sends (08 §3.2 row 3 closed)",
			body: `{"channel":"canary","seq":1,"bundle_hash":"blake3:` + hash + `","result":"applied"}`,
			want: Ack{Channel: "canary", Seq: 1, Result: "applied"},
		},
		{
			name: "base64 hash, as a generated proto3 client emits",
			body: `{"channel":"stable","seq":2,"bundle_hash":"` + raw + `","result":"applied"}`,
			want: Ack{Channel: "stable", Seq: 2, Result: "applied"},
		},
		{
			name: "rejected carries a reject_code",
			body: `{"channel":"stable","seq":9,"bundle_hash":"` + hash + `","result":"rejected","reject_code":"M1E-3002"}`,
			want: Ack{Channel: "stable", Seq: 9, Result: "rejected"},
		},
		{
			name: "partial names the skipped sections",
			body: `{"channel":"stable","seq":9,"bundle_hash":"` + hash + `","result":"partial","sections_skipped":["cortex","memory"]}`,
			want: Ack{Channel: "stable", Seq: 9, Result: "partial"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAck([]byte(tc.body), "mark1d/0.1.0")
			if err != nil {
				t.Fatalf("rejected a valid ACK: %v", err)
			}
			if got.Channel != tc.want.Channel || got.Seq != tc.want.Seq || got.Result != tc.want.Result {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			if got.EdgeVersion != "mark1d/0.1.0" {
				t.Fatal("edge_version must come from the header, never the body")
			}
		})
	}
}

func TestParseAckRejects(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	ran := 0
	for _, tc := range []struct {
		name, body string
	}{
		{"tenant_id in the body", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"applied","tenant_id":"6f1c8b2e-6a5f-4e70-9f1a-2b6c9d3e4f50"}`},
		{"device_id in the body", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"applied","device_id":"x"}`},
		{"unknown field", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"applied","extra":1}`},
		{"result outside the vocabulary", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"ok"}`},
		{"seq zero", `{"channel":"stable","seq":0,"bundle_hash":"` + hash + `","result":"applied"}`},
		{"seq negative", `{"channel":"stable","seq":-1,"bundle_hash":"` + hash + `","result":"applied"}`},
		{"channel is a command string", `{"channel":"stable; drop","seq":1,"bundle_hash":"` + hash + `","result":"applied"}`},
		{"hash is not 32 bytes", `{"channel":"stable","seq":1,"bundle_hash":"abcd","result":"applied"}`},
		{"applied with a reject_code", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"applied","reject_code":"M1E-3002"}`},
		{"applied with skipped sections", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"applied","sections_skipped":["cortex"]}`},
		{"rejected with no reject_code", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"rejected"}`},
		{"rejected naming skipped sections", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"rejected","reject_code":"M1E-3002","sections_skipped":["cortex"]}`},
		{"partial with no skipped sections", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"partial"}`},
		{"partial with a reject_code", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"partial","sections_skipped":["cortex"],"reject_code":"M1E-3002"}`},
		// An attacker-chosen section name would otherwise perturb the >20%
		// partial halt denominator, which is a way to stall a rollout.
		{"skipped section outside the six", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"partial","sections_skipped":["exec"]}`},
		{"reject_code is a command string", `{"channel":"stable","seq":1,"bundle_hash":"` + hash + `","result":"rejected","reject_code":"$(id)"}`},
		{"not json", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ran++
			if _, err := parseAck([]byte(tc.body), "mark1d/0.1.0"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if ran < 15 {
		t.Fatalf("ACK rejection table executed only %d cases", ran)
	}
}

func TestParseBundleHash(t *testing.T) {
	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(i)
	}
	for _, form := range []string{
		hex.EncodeToString(want),
		"blake3:" + hex.EncodeToString(want),
		"sha256:" + hex.EncodeToString(want),
		base64.StdEncoding.EncodeToString(want),
		base64.RawURLEncoding.EncodeToString(want),
	} {
		got, err := parseBundleHash(form)
		if err != nil {
			t.Fatalf("%q: %v", form, err)
		}
		if string(got[:]) != string(want) {
			t.Fatalf("%q decoded to different bytes", form)
		}
	}
	for _, bad := range []string{"", "zz", hex.EncodeToString(want[:31]), hex.EncodeToString(append(want, 0))} {
		if _, err := parseBundleHash(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// ETag
// ---------------------------------------------------------------------------

func TestETagIsStablePerTenantAndCarriesNoTenantID(t *testing.T) {
	a := testTenant(t, "6f1c8b2e-6a5f-4e70-9f1a-2b6c9d3e4f50")
	b := testTenant(t, "6f1c8b2e-6a5f-4e70-9f1a-2b6c9d3e4f51")

	got := ETag(a, "stable", 483)
	if got != ETag(a, "stable", 483) {
		t.Fatal("ETag is not deterministic; every poll would be a 200")
	}
	if !strings.HasPrefix(got, `"t`) || !strings.HasSuffix(got, `-000483"`) {
		t.Fatalf(`ETag %s is not the 05 §4.2 "t<n>-<channel>-<seq06>" shape`, got)
	}
	if strings.Contains(got, a.UUID().String()) {
		t.Fatal("the tenant UUID leaks into a header that rides in proxy logs (08 §3.5)")
	}
	for _, other := range []string{ETag(b, "stable", 483), ETag(a, "canary", 483), ETag(a, "stable", 484)} {
		if other == got {
			t.Fatalf("ETag collides across tenant/channel/seq: %s", other)
		}
	}
}

func TestMatchesETag(t *testing.T) {
	e := `"tdeadbeef-stable-000483"`
	for _, h := range []string{e, `W/` + e, `"other", ` + e, e + `, "other"`} {
		if !matchesETag(h, e) {
			t.Fatalf("If-None-Match %q did not match", h)
		}
	}
	for _, h := range []string{"", "*", `"tdeadbeef-stable-000484"`, `tdeadbeef-stable-000483`} {
		if matchesETag(h, e) {
			// `*` deliberately does NOT match: a wildcard revalidation on the
			// validator that gates a policy change is not a place to be
			// generous, and a 304 the edge did not earn is a stale bundle.
			t.Fatalf("If-None-Match %q matched", h)
		}
	}
}

// ---------------------------------------------------------------------------
// Rate limits (05 §8.2)
// ---------------------------------------------------------------------------

func TestLimiterIsPerRoutePerDevice(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter()
	l.now = func() time.Time { return now }
	d1, d2 := uuid.New(), uuid.New()

	for i := 0; i < pollPerMinute; i++ {
		if !l.allow("poll", d1, pollPerMinute) {
			t.Fatalf("poll %d of %d denied", i+1, pollPerMinute)
		}
	}
	if l.allow("poll", d1, pollPerMinute) {
		t.Fatal("the 5th poll in a minute was allowed; 05 §8.2 caps it at 4")
	}
	if !l.allow("ack", d1, ackPerMinute) {
		t.Fatal("an exhausted poll budget also blocked the ACK route")
	}
	if !l.allow("poll", d2, pollPerMinute) {
		t.Fatal("one device's budget blocked another device")
	}

	now = now.Add(30 * time.Second)
	if !l.allow("poll", d1, pollPerMinute) {
		t.Fatal("no refill after 30s (2 tokens at 4/min)")
	}
	now = now.Add(time.Hour)
	for i := 0; i < pollPerMinute; i++ {
		if !l.allow("poll", d1, pollPerMinute) {
			t.Fatalf("bucket did not refill to capacity after an hour (token %d)", i+1)
		}
	}
	if l.allow("poll", d1, pollPerMinute) {
		t.Fatal("the bucket refilled past its capacity")
	}
}

func TestLimiterBoundsItsMemory(t *testing.T) {
	l := newLimiter()
	for i := 0; i < maxBucketKeys+10; i++ {
		l.allow("poll", uuid.New(), pollPerMinute)
	}
	if len(l.buckets) > maxBucketKeys {
		t.Fatalf("limiter holds %d keys, over the %d bound", len(l.buckets), maxBucketKeys)
	}
}

// ---------------------------------------------------------------------------
// SSE hub
// ---------------------------------------------------------------------------

func drainOne(t *testing.T, s *stream) (Event, bool) {
	t.Helper()
	select {
	case ev, open := <-s.out:
		return ev, open
	case <-time.After(2 * time.Second):
		t.Fatal("no event and no close within 2s")
		return Event{}, false
	}
}

func TestHubRoutesByTenantAndChannel(t *testing.T) {
	h := NewHub()
	tenantA, tenantB := uuid.New(), uuid.New()

	stable, err := h.subscribe(tenantA, "stable")
	if err != nil {
		t.Fatal(err)
	}
	canary, err := h.subscribe(tenantA, "canary")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := h.subscribe(tenantB, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if h.Live() != 3 {
		t.Fatalf("Live() = %d, want 3", h.Live())
	}

	h.Publish(tenantA, "stable", 483, `"tdeadbeef-stable-000483"`)
	ev, open := drainOne(t, stable)
	if !open || ev.Name != "bundle" || ev.Data != `{"seq":483,"etag":"tdeadbeef-stable-000483"}` {
		t.Fatalf("bundle hint = %+v", ev)
	}
	select {
	case ev := <-canary.out:
		t.Fatalf("a stable publication reached the canary stream: %+v", ev)
	case ev := <-foreign.out:
		t.Fatalf("tenant A's publication reached tenant B: %+v", ev)
	default:
	}

	// A revocation is not channel-scoped (05 §3.4).
	h.Revoke(tenantA, 7)
	for _, s := range []*stream{stable, canary} {
		ev, open := drainOne(t, s)
		if !open || ev.Name != "revocation" || ev.Data != `{"revocation_epoch":7}` {
			t.Fatalf("revocation frame = %+v", ev)
		}
	}
	select {
	case ev := <-foreign.out:
		t.Fatalf("tenant A's revocation reached tenant B: %+v", ev)
	default:
	}
}

func TestHubBoundsConnections(t *testing.T) {
	h := NewHub()
	h.maxTotal, h.maxTenant = 4, 2
	a, b := uuid.New(), uuid.New()

	for i := 0; i < 2; i++ {
		if _, err := h.subscribe(a, "stable"); err != nil {
			t.Fatalf("tenant A stream %d: %v", i+1, err)
		}
	}
	if _, err := h.subscribe(a, "stable"); !errors.Is(err, ErrHubFull) {
		t.Fatal("one tenant consumed more than its per-tenant budget")
	}
	for i := 0; i < 2; i++ {
		if _, err := h.subscribe(b, "stable"); err != nil {
			t.Fatalf("tenant B must still be able to connect: %v", err)
		}
	}
	if _, err := h.subscribe(uuid.New(), "stable"); !errors.Is(err, ErrHubFull) {
		t.Fatal("the pod budget was exceeded")
	}
}

func TestHubClosesSlowConsumers(t *testing.T) {
	h := NewHub()
	tenant := uuid.New()
	s, err := h.subscribe(tenant, "stable")
	if err != nil {
		t.Fatal(err)
	}
	// streamBuffer deep; the one past it must close the stream rather than
	// block the publication path.
	for i := 0; i < streamBuffer+1; i++ {
		h.Publish(tenant, "stable", int64(i), `"e"`)
	}
	if h.Live() != 0 {
		t.Fatalf("a stream that stopped reading is still holding a slot (Live=%d)", h.Live())
	}
	for {
		if _, open := drainOne(t, s); !open {
			break
		}
	}
	// unsubscribe is idempotent: the writer goroutine also defers it, and a
	// double close would panic the pod.
	h.unsubscribe(s)
}

func TestHubDrainEndsEveryStreamWithAPing(t *testing.T) {
	h := NewHub()
	tenant := uuid.New()
	s, err := h.subscribe(tenant, "stable")
	if err != nil {
		t.Fatal(err)
	}
	h.Drain()

	ev, open := drainOne(t, s)
	if !open || ev.Name != "ping" {
		t.Fatalf("drain must end a stream with a final ping, got %+v (open=%v)", ev, open)
	}
	if _, open := drainOne(t, s); open {
		t.Fatal("drain did not close the stream after the ping")
	}
	if h.Live() != 0 {
		t.Fatalf("Live() = %d after drain", h.Live())
	}
	// A draining pod must not accept new streams: /readyz is already 503 and a
	// new subscriber would just be dropped a moment later.
	if _, err := h.subscribe(tenant, "stable"); !errors.Is(err, ErrHubFull) {
		t.Fatal("a draining hub accepted a new stream")
	}
}

// ---------------------------------------------------------------------------
// Canary arithmetic (05 §4.3, 06 §10.4)
// ---------------------------------------------------------------------------

func TestDecide(t *testing.T) {
	soaked := RolloutState{CohortPercent: 5, SoakElapsed: SoakWindow}
	healthy := Coverage{HeadSeq: 7, ActiveDevices: 100, OnHead: 96}

	cases := []struct {
		name  string
		cov   Coverage
		state RolloutState
		want  Decision
	}{
		{"widen at 96% coverage after a full soak", healthy, soaked, DecisionWiden},
		{"halt on a single M1E-3005", Coverage{ActiveDevices: 100, OnHead: 99, Rejected: 1, CommandString: 1}, soaked, DecisionHalt},
		// One command string outranks a perfect rollout: it means the
		// publish-side gate was bypassed or broken.
		{"halt on M1E-3005 even at full coverage", Coverage{ActiveDevices: 100, OnHead: 100, CommandString: 1}, soaked, DecisionHalt},
		{"halt over the 0.5% rejected line", Coverage{ActiveDevices: 1000, OnHead: 990, Rejected: 6}, soaked, DecisionHalt},
		{"hold at exactly the 0.5% rejected line", Coverage{ActiveDevices: 1000, OnHead: 990, Rejected: 5}, soaked, DecisionHold},
		{"halt over the 20% partial line", Coverage{ActiveDevices: 100, OnHead: 79, Partial: 21}, soaked, DecisionHalt},
		{"halt on a health regression", healthy, RolloutState{CohortPercent: 5, SoakElapsed: SoakWindow, HealthRegressed: true}, DecisionHalt},
		{"hold mid-soak even when everything is green", healthy, RolloutState{CohortPercent: 5, SoakElapsed: 59 * time.Minute}, DecisionHold},
		{"hold under the coverage floor", Coverage{ActiveDevices: 100, OnHead: 94}, soaked, DecisionHold},
		{"widen exactly at the floor", Coverage{ActiveDevices: 100, OnHead: 95}, soaked, DecisionWiden},
		// A partial ACK is a successful verify but counts as NON-adoption
		// (05 §4.3b), so it must never push coverage over the floor.
		{"partials do not count towards coverage", Coverage{ActiveDevices: 100, OnHead: 80, Partial: 19}, soaked, DecisionHold},
		{"hold with any rejection at all", Coverage{ActiveDevices: 1000, OnHead: 998, Rejected: 1}, soaked, DecisionHold},
		// An empty or fully dark fleet must not widen on a vacuous truth.
		{"hold on an empty fleet", Coverage{}, soaked, DecisionHold},
		{"terminal at 100%", healthy, RolloutState{CohortPercent: 100, SoakElapsed: 24 * time.Hour}, DecisionHold},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, why := Decide(tc.cov, tc.state)
			if got != tc.want {
				t.Fatalf("Decide = %s (%s), want %s", got, why, tc.want)
			}
			if why == "" {
				t.Fatal("a rollout decision with no stated reason is unauditable")
			}
		})
	}
	if len(cases) < 12 {
		t.Fatalf("the canary decision table shrank to %d cases", len(cases))
	}
}

func TestCoverageHeadRatioNeverDividesByNothing(t *testing.T) {
	if r := (Coverage{ActiveDevices: 0, OnHead: 0}).HeadRatio(); r != 0 {
		t.Fatalf("an empty fleet reported %v adoption; 0/0 must read as 0, never 1", r)
	}
	if r := (Coverage{ActiveDevices: 4, OnHead: 3}).HeadRatio(); r != 0.75 {
		t.Fatalf("HeadRatio = %v, want 0.75", r)
	}
}

func TestNextStep(t *testing.T) {
	for in, want := range map[int]int{0: 5, 5: 25, 25: 100, 100: 100, 7: 25, 250: 100} {
		if got := NextStep(in); got != want {
			t.Fatalf("NextStep(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestInCohort(t *testing.T) {
	salt := []byte("tenant-salt")
	device := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	if InCohort(salt, device, 0) {
		t.Fatal("a 0% cohort included a device")
	}
	if !InCohort(salt, device, 100) {
		t.Fatal("a 100% cohort excluded a device")
	}
	// Stable across calls: a device that oscillates in and out between polls
	// gets a different bundle every five minutes.
	first := InCohort(salt, device, 25)
	for i := 0; i < 10; i++ {
		if InCohort(salt, device, 25) != first {
			t.Fatal("cohort membership is not stable for a fixed (tenant, device)")
		}
	}
	// Monotone in percent: widening never drops a device out of the cohort.
	for _, d := range []uuid.UUID{uuid.New(), uuid.New(), uuid.New()} {
		if InCohort(salt, d, 5) && !InCohort(salt, d, 25) {
			t.Fatal("widening 5% -> 25% dropped a device out of the cohort")
		}
	}
	// The salt matters: without it the same machines take every tenant's canary.
	devices := make([]uuid.UUID, 200)
	for i := range devices {
		devices[i] = uuid.New()
	}
	same := 0
	for _, d := range devices {
		if InCohort(salt, d, 25) == InCohort([]byte("other-tenant-salt"), d, 25) {
			same++
		}
	}
	if same == len(devices) {
		t.Fatal("cohort assignment ignores the tenant salt")
	}
	// Roughly proportional. Loose bounds: this is a sanity check on the mod-100
	// arithmetic, not a statistical test.
	in := 0
	for _, d := range devices {
		if InCohort(salt, d, 25) {
			in++
		}
	}
	if in < 20 || in > 80 {
		t.Fatalf("25%% cohort selected %d of %d devices", in, len(devices))
	}
}
