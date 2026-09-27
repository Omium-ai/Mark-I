// Package consents is the Step-4 consent record (desktop spec §3.2): what the user let leave this machine. Absent, unreadable or garbage reads as nothing consented, per field — the same fail-closed rule as fabric's opt-in and the anchor store.
package consents

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Consents struct {
	E1                 bool `json:"e1"`                  // sanitized diff hunks (E1 evidence tier) may leave
	CloudJudge         bool `json:"cloud_judge"`         // verdicts from Omium's cloud judge under the subprocessor terms
	Training           bool `json:"training"`            // verified outcomes may enter the training corpus
	Team               bool `json:"team"`                // memory this user shares reaches their teammates (15-teams)
	LocalRM            bool `json:"local_rm"`            // the reward model downloads and scores on this machine; nothing leaves (16 §L6)
	CloudRM            bool `json:"cloud_rm"`            // the reward model scores E1 hunks in Omium's cloud (16 §L6 cloud half; needs e1)
	ContributeOutcomes bool `json:"contribute_outcomes"` // task text, redacted diff and delayed outcome labels upload for model evaluation and training (16 L8)
}

func Path(stateDir string) string { return filepath.Join(stateDir, "gates", "consents.json") }

func Read(stateDir string) (c Consents) {
	if b, err := os.ReadFile(Path(stateDir)); err != nil || json.Unmarshal(b, &c) != nil {
		return Consents{}
	}
	return c
}

// Write is tmp+rename, 0600, like every other gate artifact under <state>/gates.
func Write(stateDir string, c Consents) error {
	if err := os.MkdirAll(filepath.Dir(Path(stateDir)), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := Path(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, Path(stateDir))
}
