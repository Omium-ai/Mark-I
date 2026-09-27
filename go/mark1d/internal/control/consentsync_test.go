package control

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/contrib"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/evidence"
)

var consentKeys = []string{"e1", "cloud_judge", "training", "team", "local_rm", "cloud_rm", "contribute_outcomes"}

// fakeControld is 08 §3.7a in miniature, per device token: an absent key carries the previous row's value, a held key stays off until a body sends it false, a true → false body is a transition, and every 2xx answers the effective row.
type fakeControld struct {
	mu          sync.Mutex
	rows        map[string]map[string]bool
	held        map[string]map[string]bool
	history     map[string][]map[string]bool
	bodies      []map[string]bool
	tokens      []string
	transitions []string // token + "/" + key
	bare        bool     // answer without the effective row, as a legacy cloud does
	lose        int      // replies recorded and then lost (502)
	jitter      bool     // each request waits 0-20 ms before it lands, so racing relays interleave
	srv         *httptest.Server
}

func newFakeControld(t *testing.T) *fakeControld {
	f := &fakeControld{rows: map[string]map[string]bool{}, held: map[string]map[string]bool{}, history: map[string][]map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeControld) serve(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var body map[string]bool
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	jitter := f.jitter
	f.mu.Unlock()
	if jitter {
		time.Sleep(time.Duration(rand.IntN(20)) * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	prev, row := f.rows[tok], map[string]bool{}
	for _, k := range consentKeys {
		v, sent := body[k]
		switch {
		case !sent:
			row[k] = prev[k]
		case f.held[tok][k] && v:
			row[k] = false
		default:
			if !v {
				delete(f.held[tok], k)
				if prev[k] {
					f.transitions = append(f.transitions, tok+"/"+k)
				}
			}
			row[k] = v
		}
	}
	f.rows[tok] = row
	f.history[tok] = append(f.history[tok], row)
	f.bodies, f.tokens = append(f.bodies, body), append(f.tokens, tok)
	if f.lose > 0 {
		f.lose--
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	if f.bare {
		_, _ = w.Write([]byte(`{"recorded_at":"2026-09-26T00:00:00Z"}`))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"recorded_at": "2026-09-26T00:00:00Z", "consents": row})
}

// withdraw is another device of the same person turning keys off: this device's row takes them off and holds them.
func (f *fakeControld) withdraw(tok string, keys ...string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	row := map[string]bool{}
	for k, v := range f.rows[tok] {
		row[k] = v
	}
	if f.held[tok] == nil {
		f.held[tok] = map[string]bool{}
	}
	for _, k := range keys {
		row[k], f.held[tok][k] = false, true
	}
	f.rows[tok] = row
	f.history[tok] = append(f.history[tok], row)
	return len(f.history[tok])
}

func (f *fakeControld) row(tok string) map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rows[tok]
}

func (f *fakeControld) heldCount(tok string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.held[tok])
}

func (f *fakeControld) puts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeControld) body(i int) map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[i]
}

// regranted reports a row after index from with key true: a held withdrawal re-granted.
func (f *fakeControld) regranted(tok, key string, from int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.history[tok][from:] {
		if r[key] {
			return true
		}
	}
	return false
}

func keygen(t *testing.T, s *Server) string {
	t.Helper()
	resp, body := call(t, s, http.MethodPost, "/v1/enroll/keygen", nil)
	want(t, resp, body, http.StatusOK, "")
	var kg struct {
		KeyID string `json:"key_id"`
	}
	decodeTo(t, body, &kg)
	return kg.KeyID
}

// enrollAt enrolls s as device in tenant against f and returns the device token; relay settles every relay that enrollment started.
func enrollAt(t *testing.T, s *Server, f *fakeControld, tenant, device, keyID string) string {
	t.Helper()
	a := activeFor(tenant, device, keyID)
	a["endpoints"] = map[string]string{"ingest": f.srv.URL + "/m1p/v1/ingest"}
	resp, body := call(t, s, http.MethodPost, "/v1/enroll", a)
	want(t, resp, body, http.StatusOK, "")
	relay(t, s)
	return a["device_token"].(string)
}

// relay runs one relay; serialized with any the server started, so its return settles them.
func relay(t *testing.T, s *Server) {
	t.Helper()
	if err := s.relayConsents(context.Background()); err != nil {
		t.Fatalf("relay: %v", err)
	}
}

func consentOn(t *testing.T, s *Server, c map[string]bool) {
	t.Helper()
	resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": c}, currentCopy)
	want(t, resp, body, http.StatusOK, "")
	relay(t, s)
}

func restart(t *testing.T, s *Server, dir string) *Server {
	t.Helper()
	_ = s.Close()
	s2, err := Listen(Config{StateDir: dir, SpoolDir: filepath.Join(dir, "spool"), SpoolCap: 1 << 20, Version: "test", Log: s.cfg.Log})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s2.Serve() }()
	t.Cleanup(func() { _ = s2.Close() })
	return s2
}

func notes(t *testing.T, s *Server) (withdrawn, reset []string) {
	t.Helper()
	var o struct {
		CloudWithdrawal []string `json:"cloud_withdrawal"`
		CopyReset       []string `json:"copy_reset"`
	}
	_, body := call(t, s, http.MethodGet, "/v1/optins", nil)
	decodeTo(t, body, &o)
	return o.CloudWithdrawal, o.CopyReset
}

// TestCloudWithdrawalIsAdoptedAndReleased (review HIGH-2): a person-wide off made on another device reaches this one at the next session start: the field turns off here as a local off does (pending E1 parts and contributions purged, journalled, listed in GET /v1/optins cloud_withdrawal across a restart until the person sets it again), and the adopted false goes out at once, which releases controld's hold. A cloud that answers without the row changes nothing; the cloud never turns a field on; a cloud_judge or training off adopted under the outdated copy (controld's m1_107 reset) is filed as copy_reset.
func TestCloudWithdrawalIsAdoptedAndReleased(t *testing.T) {
	s, dir := newServer(t)
	f := newFakeControld(t)
	keyID := keygen(t, s)
	consentOn(t, s, map[string]bool{"e1": true, "training": true, "contribute_outcomes": true, "local_rm": true})
	f.bare = true
	tok := enrollAt(t, s, f, tenantA, deviceA, keyID)
	if c := consents.Read(dir); !c.E1 || !c.Training || !c.ContributeOutcomes || !c.LocalRM || consents.Pending(dir) || f.row(tok)["e1"] != true {
		t.Fatalf("a cloud answering without the row: %+v pending=%v row=%v", c, consents.Pending(dir), f.row(tok))
	}
	f.bare = false

	e1Part, contribPart := filepath.Join(evidence.E1Dir(dir), "task.part"), filepath.Join(contrib.Dir(dir), "pending.json")
	for _, p := range []string{e1Part, contribPart} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	from := f.withdraw(tok, "e1", "contribute_outcomes")
	before := f.puts()
	sid := [16]byte{1}
	s.Hub().Publish(&m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{Agent: "claude-code"}}})
	for deadline := time.Now().Add(5 * time.Second); f.heldCount(tok) > 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	relay(t, s)
	if f.puts() != before+2 || f.body(before)["e1"] != true || f.body(before + 1)["e1"] != false || f.body(before + 1)["contribute_outcomes"] != false {
		t.Fatalf("want the session-start sync then the releasing PUT: %d PUTs", f.puts()-before)
	}
	if f.heldCount(tok) != 0 || f.regranted(tok, "e1", from) || f.regranted(tok, "contribute_outcomes", from) || consents.Pending(dir) {
		t.Fatalf("hold not released cleanly: row %v held %d pending %v", f.row(tok), f.heldCount(tok), consents.Pending(dir))
	}
	c := consents.Read(dir)
	if c.E1 || c.ContributeOutcomes || !c.Training || !c.LocalRM || c.CloudJudge {
		t.Fatalf("adopted %+v", c)
	}
	for _, p := range []string{e1Part, contribPart} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s survived the cloud-side withdrawal", p)
		}
	}
	if journal, _ := os.ReadFile(filepath.Join(dir, "consent.jsonl")); !strings.Contains(string(journal), `"reason":"cloud_withdrawal"`) {
		t.Fatalf("journal lacks the adoption:\n%s", journal)
	}
	s = restart(t, s, dir)
	if w, r := notes(t, s); strings.Join(w, ",") != "e1,contribute_outcomes" || r != nil {
		t.Fatalf("after a restart: cloud_withdrawal %v copy_reset %v", w, r)
	}

	consentOn(t, s, map[string]bool{"e1": true})
	if w, _ := notes(t, s); strings.Join(w, ",") != "contribute_outcomes" || !f.row(tok)["e1"] {
		t.Fatalf("the person re-enabled e1 here: listed %v row %v", w, f.row(tok))
	}
	if _, err := s.adoptCloud(tenantA, consents.Consents{Training: true}, &consents.Consents{}, false); err != nil || !consents.Read(dir).E1 {
		t.Fatalf("an e1 turned on after the PUT was taken back: err=%v %+v", err, consents.Read(dir))
	}
	consentOn(t, s, map[string]bool{"cloud_judge": true})
	if _, err := s.adoptCloud(tenantA, consents.Consents{CloudJudge: true}, &consents.Consents{}, true); err != nil || consents.Read(dir).CloudJudge {
		t.Fatalf("legacy cloud_judge reset: err=%v %+v", err, consents.Read(dir))
	}
	if w, r := notes(t, s); slices.Contains(w, "cloud_judge") || !slices.Contains(r, "cloud_judge") {
		t.Fatalf("the legacy cloud_judge reset is a copy_reset, not another device's withdrawal: %v %v", w, r)
	}
	consentOn(t, s, map[string]bool{"training": true, "team": true})
	if _, err := s.adoptCloud(tenantA, consents.Consents{Training: true, Team: true}, &consents.Consents{}, true); err != nil || consents.Read(dir).Training {
		t.Fatalf("legacy training reset: err=%v %+v", err, consents.Read(dir))
	}
	if w, r := notes(t, s); slices.Contains(w, "training") || !slices.Contains(r, "training") || !slices.Contains(w, "team") {
		t.Fatalf("a pre-copy-2 training reset is a copy_reset; another field in the same row is still a withdrawal: %v %v", w, r)
	}
	consentOn(t, s, map[string]bool{"training": true})
	if _, err := s.adoptCloud(tenantA, consents.Consents{Training: true}, &consents.Consents{}, false); err != nil {
		t.Fatal(err)
	}
	if w, r := notes(t, s); !slices.Contains(w, "training") || slices.Contains(r, "training") {
		t.Fatalf("after the copy-2 stamp a training off is another device's withdrawal: %v %v", w, r)
	}
}

// TestConcurrentRelaysNeverReGrant (review HIGH-2): relays from every trigger at once still leave a withdrawn field off in the cloud: none PUTs a stale true after the adoption's false released the hold.
func TestConcurrentRelaysNeverReGrant(t *testing.T) {
	s, dir := newServer(t)
	f := newFakeControld(t)
	keyID := keygen(t, s)
	consentOn(t, s, map[string]bool{"e1": true, "training": true})
	tok := enrollAt(t, s, f, tenantA, deviceA, keyID)
	from := f.withdraw(tok, "e1")
	f.mu.Lock()
	f.jitter = true
	f.mu.Unlock()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 5 * time.Millisecond)
			s.consentSync.Store(true)
			_ = s.relayConsents(context.Background())
		}()
	}
	wg.Wait()
	if f.regranted(tok, "e1", from) || f.heldCount(tok) != 0 || consents.Read(dir).E1 || !f.row(tok)["training"] {
		t.Fatalf("row %v held %d local %+v", f.row(tok), f.heldCount(tok), consents.Read(dir))
	}
}

// TestLostReplyNeverReGrants (review HIGH-2): a PUT controld recorded but whose answer never arrived leaves the record as it was; the next relay is held again, adopted and released, and the cloud never shows the field on in between.
func TestLostReplyNeverReGrants(t *testing.T) {
	s, dir := newServer(t)
	f := newFakeControld(t)
	keyID := keygen(t, s)
	consentOn(t, s, map[string]bool{"e1": true})
	tok := enrollAt(t, s, f, tenantA, deviceA, keyID)
	from := f.withdraw(tok, "e1")
	f.lose = 1
	s.consentSync.Store(true)
	if err := s.relayConsents(context.Background()); err == nil || !consents.Read(dir).E1 {
		t.Fatalf("a lost reply: err=%v local %+v", err, consents.Read(dir))
	}
	s.consentSync.Store(true)
	relay(t, s)
	if f.regranted(tok, "e1", from) || f.heldCount(tok) != 0 || consents.Read(dir).E1 || consents.Pending(dir) {
		t.Fatalf("row %v held %d local %+v", f.row(tok), f.heldCount(tok), consents.Read(dir))
	}
}

// TestTenantRoundTripKeepsContributions (review HIGH-1): a tenant switch resets contribute_outcomes to undecided, which relays ABSENT, so going personal → team → personal (and leaving and re-joining the team) never sends the true → false that would withdraw and sweep the person's contributions; the row the device still holds true in that tenant is restored as their own choice there. A genuine off still withdraws.
func TestTenantRoundTripKeepsContributions(t *testing.T) {
	s, dir := newServer(t)
	f := newFakeControld(t)
	keyID := keygen(t, s)
	consentOn(t, s, map[string]bool{"contribute_outcomes": true})
	tokA := enrollAt(t, s, f, tenantA, deviceA, keyID)
	if !f.row(tokA)["contribute_outcomes"] {
		t.Fatalf("personal row %v", f.row(tokA))
	}
	tokB := enrollAt(t, s, f, tenantB, deviceB, keyID)
	if consents.Read(dir).ContributeOutcomes || !contrib.Undecided(dir) {
		t.Fatal("the switch resets contribute_outcomes to undecided")
	}
	for i := range f.puts() {
		if _, sent := f.body(i)["contribute_outcomes"]; sent && f.tokens[i] == tokB {
			t.Fatalf("an undecided contribute_outcomes was sent: %v", f.body(i))
		}
	}
	consentOn(t, s, map[string]bool{"contribute_outcomes": true})
	for _, step := range []struct {
		tenant, device, tok string
	}{{tenantA, deviceA, tokA}, {tenantB, deviceB, tokB}, {tenantA, deviceA, tokA}} {
		enrollAt(t, s, f, step.tenant, step.device, keyID)
		relay(t, s)
		var o struct {
			Consents consents.Consents `json:"consents"`
		}
		_, body := call(t, s, http.MethodGet, "/v1/optins", nil)
		decodeTo(t, body, &o)
		if !o.Consents.ContributeOutcomes || !contrib.Decided(dir) || !f.row(step.tok)["contribute_outcomes"] || len(f.transitions) != 0 {
			t.Fatalf("back in %s: local %+v decided=%v row %v transitions %v", step.tenant, o.Consents, contrib.Decided(dir), f.row(step.tok), f.transitions)
		}
	}
	consentOn(t, s, map[string]bool{"contribute_outcomes": false})
	if !slices.Contains(f.transitions, tokA+"/contribute_outcomes") {
		t.Fatalf("a genuine off must withdraw: %v", f.transitions)
	}
}

// TestOldCopyGrantsResetOnce (review LOW-5/6): a record never stamped with the current consent copy has cloud_judge and training turned off once at boot (journalled copy_reset, listed in GET /v1/optins copy_reset until the person sets the key again), then stamped, so a later grant through the copy gate survives the next restart. Neither note is ever accepted in a PUT body.
func TestOldCopyGrantsResetOnce(t *testing.T) {
	s, dir := newServer(t)
	if err := consents.Write(dir, consents.Consents{E1: true, CloudJudge: true, Training: true, CloudRM: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "gates", "consents_copy")); err != nil {
		t.Fatal(err)
	}
	s = restart(t, s, dir)
	if c := consents.Read(dir); c.CloudJudge || c.Training || !c.E1 || !c.CloudRM || !consents.CopyCurrent(dir) {
		t.Fatalf("after the copy reset: %+v stamped=%v", c, consents.CopyCurrent(dir))
	}
	if journal, _ := os.ReadFile(filepath.Join(dir, "consent.jsonl")); !strings.Contains(string(journal), `"reason":"copy_reset"`) {
		t.Fatalf("journal lacks the reset:\n%s", journal)
	}
	if w, r := notes(t, s); w != nil || strings.Join(r, ",") != "cloud_judge,training" {
		t.Fatalf("notes %v %v", w, r)
	}
	for _, k := range []string{"cloud_withdrawal", "copy_reset"} {
		resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{k: []string{}})
		want(t, resp, body, http.StatusBadRequest, "M1E-2001")
	}
	resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"cloud_judge": true}}, currentCopy)
	want(t, resp, body, http.StatusOK, "")
	if !strings.Contains(string(body), `"copy_reset":["training"]`) {
		t.Fatalf("the echo lists what is still reset: %s", body)
	}
	s = restart(t, s, dir)
	if c := consents.Read(dir); !c.CloudJudge || c.Training {
		t.Fatalf("the reset ran twice: %+v", c)
	}
	if _, r := notes(t, s); strings.Join(r, ",") != "training" {
		t.Fatalf("after a restart: copy_reset %v", r)
	}
}
