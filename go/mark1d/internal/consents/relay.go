package consents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
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

// Bearer is uplink.TokenSource's shape: the device token is read at send time from its custody, never held here.
type Bearer interface {
	Token(context.Context) (string, error)
}

// Relay is the cloud half of the Step-4 record: PUT /api/v1/consents (controld ingest, m1_082) under the device token, the whole triple every time so a revocation can never be lost to a partial write; marked relayed only on a 2xx, so a failed attempt stays Pending for the next tick. The local file is the truth either way.
func Relay(ctx context.Context, stateDir, server string, bearer Bearer) error {
	cur, err := os.ReadFile(Path(stateDir))
	if err != nil {
		return err
	}
	var c Consents
	if json.Unmarshal(cur, &c) != nil {
		return errors.New("consents: local record is corrupt; not relayed")
	}
	body, _ := json.Marshal(c)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, server+"/api/v1/consents", bytes.NewReader(body))
	if err != nil {
		return err
	}
	tok, err := bearer.Token(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("consents: relay refused, HTTP %d", resp.StatusCode)
	}
	return os.WriteFile(relayedPath(stateDir), cur, 0o600)
}
