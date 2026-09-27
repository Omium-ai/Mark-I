package consents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
)

func relayedPath(stateDir string) string { return Path(stateDir) + ".relayed" }

// Pending says whether the live record differs from the last one controld acknowledged; a device that never consented has nothing to relay.
func Pending(stateDir string) bool {
	cur, err := os.ReadFile(Path(stateDir))
	if err != nil {
		return false
	}
	done, _ := os.ReadFile(relayedPath(stateDir))
	return !bytes.Equal(cur, done)
}

// MarkUnrelayed makes the live record Pending again, for a new device identity controld holds no consent row for.
func MarkUnrelayed(stateDir string) error {
	if err := os.Remove(relayedPath(stateDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Bearer is uplink.TokenSource's shape: the device token is read at send time from its custody, never held here.
type Bearer interface {
	Token(context.Context) (string, error)
}

// legacyWire is the body prod f85bff9's strict decoder accepts, and legacyAck the acknowledgement it earns: it names the cloud as legacy so the record stays Pending and the full body is tried again on every later relay, until an upgraded cloud takes it.
type legacyWire struct {
	E1         bool `json:"e1"`
	CloudJudge bool `json:"cloud_judge"`
	Training   bool `json:"training"`
}

type legacyAck struct {
	legacyWire
	LegacyCloud bool `json:"legacy_cloud"`
}

// ErrLegacyCloud: controld refused the later fields, so only e1, cloud_judge and training landed; the record stays Pending and the loop backs off.
var ErrLegacyCloud = errors.New("consents: controld predates team/local_rm/cloud_rm/contribute_outcomes; only e1, cloud_judge and training were relayed")

// Relay is Sync for callers that only need the relay.
func Relay(ctx context.Context, stateDir, server string, bearer Bearer) error {
	_, _, err := Sync(ctx, stateDir, server, bearer)
	return err
}

// Sync is the cloud half of the Step-4 record: PUT /api/v1/consents (controld ingest, m1_082) under the device token, every field explicit (controld reads an absent later field as unchanged and a true → false as a withdrawal) except the omit keys, sent absent so controld carries the device's previous value; marked relayed only on a 2xx, so a failed attempt stays Pending for the next tick. A 400 is retried with the three fields every controld knows, so a withdrawal of those still lands (ErrLegacyCloud). The local file is the truth either way. sent is the record as PUT (omitted keys read false) and cloud the device's effective row the 2xx answered with (08 §3.7a), nil when the answer carries none (a legacy cloud) or there was no 2xx.
func Sync(ctx context.Context, stateDir, server string, bearer Bearer, omit ...string) (sent Consents, cloud *Consents, err error) {
	cur, err := os.ReadFile(Path(stateDir))
	if err != nil {
		return sent, nil, err
	}
	if json.Unmarshal(cur, &sent) != nil {
		return sent, nil, errors.New("consents: local record is corrupt; not relayed")
	}
	var body map[string]bool
	b, _ := json.Marshal(sent)
	_ = json.Unmarshal(b, &body)
	for i, k := range keys {
		if slices.Contains(omit, k) {
			delete(body, k)
			*fields(&sent)[i] = false
		}
	}
	code, cloud, err := put(ctx, server, bearer, body)
	if err != nil {
		return sent, nil, err
	}
	if code == http.StatusBadRequest {
		legacy := legacyWire{E1: sent.E1, CloudJudge: sent.CloudJudge, Training: sent.Training}
		if code, cloud, err = put(ctx, server, bearer, legacy); err != nil {
			return sent, nil, err
		}
		if code/100 == 2 {
			b, _ := json.Marshal(legacyAck{legacy, true})
			if err := os.WriteFile(relayedPath(stateDir), b, 0o600); err != nil {
				return sent, cloud, err
			}
			return sent, cloud, ErrLegacyCloud
		}
	}
	if code/100 != 2 {
		return sent, nil, fmt.Errorf("consents: relay refused, HTTP %d", code)
	}
	return sent, cloud, os.WriteFile(relayedPath(stateDir), cur, 0o600)
}

var allOn = Consents{E1: true, CloudJudge: true, Training: true, Team: true, LocalRM: true, CloudRM: true, ContributeOutcomes: true}

// put sends w and decodes a 2xx body's "consents" over allOn, so a field the cloud does not name never reads as off; nil when there is none.
func put(ctx context.Context, server string, bearer Bearer, w any) (int, *Consents, error) {
	body, _ := json.Marshal(w)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, server+"/api/v1/consents", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	tok, err := bearer.Token(ctx)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, nil, nil
	}
	var ack struct {
		Consents json.RawMessage `json:"consents"`
	}
	eff := allOn
	if b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10)); err != nil || json.Unmarshal(b, &ack) != nil ||
		len(ack.Consents) == 0 || string(ack.Consents) == "null" || json.Unmarshal(ack.Consents, &eff) != nil {
		return resp.StatusCode, nil, nil
	}
	return resp.StatusCode, &eff, nil
}

// Adopt is local with every field turned off that the cloud's effective row says off while the record sent and local both say on: a withdrawal made on another device lands here too. The cloud never turns a field on, and a field the person turned on here after that PUT is theirs.
func Adopt(sent, cloud, local Consents) Consents {
	s, c, l := fields(&sent), fields(&cloud), fields(&local)
	for i := range l {
		if *s[i] && !*c[i] {
			*l[i] = false
		}
	}
	return local
}

// keys are the wire names of fields(), in its order.
var keys = []string{"e1", "cloud_judge", "training", "team", "local_rm", "cloud_rm", "contribute_outcomes"}

// TurnedOff names the fields on in was and off in now.
func TurnedOff(was, now Consents) []string {
	w, n := fields(&was), fields(&now)
	var out []string
	for i := range w {
		if *w[i] && !*n[i] {
			out = append(out, keys[i])
		}
	}
	return out
}

// The per-key notes GET /v1/optins shows beside the record, each cleared when the person sets that key here again.
const (
	ListCloudWithdrawal = "cloud_withdrawal" // turned off adopting another device's withdrawal
	ListCopyReset       = "copy_reset"       // turned off because it was granted under the outdated consent copy
)

func listPath(stateDir, name string) string {
	return filepath.Join(filepath.Dir(Path(stateDir)), "consents_"+name+".json")
}

// List reads a note list (ListCloudWithdrawal, ListCopyReset); absent or garbage reads as none.
func List(stateDir, name string) []string {
	var out []string
	if b, err := os.ReadFile(listPath(stateDir, name)); err != nil || json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

// UpdateList adds keys and drops the keys the person just set, persisted tmp+rename beside consents.json; an empty list removes the file.
func UpdateList(stateDir, name string, add, clear []string) error {
	cur := List(stateDir, name)
	var next []string
	for _, k := range keys {
		if (slices.Contains(cur, k) || slices.Contains(add, k)) && !slices.Contains(clear, k) {
			next = append(next, k)
		}
	}
	if slices.Equal(cur, next) {
		return nil
	}
	if len(next) == 0 {
		if err := os.Remove(listPath(stateDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, _ := json.Marshal(next)
	tmp := listPath(stateDir, name) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, listPath(stateDir, name))
}

// CopyVersion is the consent copy the current app shows (the X-Mark1-Consent-Copy it sends): the register's Nebius/global judge and Baseten/us RM.
const CopyVersion = "2"

func copyPath(stateDir string) string {
	return filepath.Join(filepath.Dir(Path(stateDir)), "consents_copy")
}

// CopyCurrent: the record's grants were made under CopyVersion (StampCopy ran).
func CopyCurrent(stateDir string) bool {
	b, err := os.ReadFile(copyPath(stateDir))
	return err == nil && string(b) == CopyVersion
}

// StampCopy marks the record as held under CopyVersion.
func StampCopy(stateDir string) error {
	if err := os.MkdirAll(filepath.Dir(copyPath(stateDir)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(copyPath(stateDir), []byte(CopyVersion), 0o600)
}

func fields(c *Consents) []*bool {
	return []*bool{&c.E1, &c.CloudJudge, &c.Training, &c.Team, &c.LocalRM, &c.CloudRM, &c.ContributeOutcomes}
}

// Acknowledged is the record controld last accepted from this device (zero when none): an upload gated on a consent waits until the cloud holds that consent, whatever else is still pending.
func Acknowledged(stateDir string) (c Consents) {
	if b, err := os.ReadFile(relayedPath(stateDir)); err != nil || json.Unmarshal(b, &c) != nil {
		return Consents{}
	}
	return c
}
