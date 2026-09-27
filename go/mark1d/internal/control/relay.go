package control

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/contrib"
)

const consentRelayEvery = time.Minute

// relayConsents pushes a pending Step-4 record to controld once the device is enrolled, or the acknowledged one again when a sync is due, and adopts what the cloud's answer carries; not enrolled yet is not an error, the record just stays pending for the next tick. Serialized: a relay that read the record before another's adoption would PUT a stale true and re-grant a held withdrawal.
func (s *Server) relayConsents(ctx context.Context) error {
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	doc, err := s.readEnrollment()
	if err != nil || doc.liveState() != "active" {
		return nil
	}
	due := s.consentSync.Swap(false)
	if _, err := os.Stat(consents.Path(s.cfg.StateDir)); !consents.Pending(s.cfg.StateDir) && (!due || err != nil) {
		return nil
	}
	for range 2 { // an adoption's off goes out at once: controld holds a withdrawn field until a body sends it false
		var omit []string
		if contrib.Undecided(s.cfg.StateDir) {
			omit = []string{"contribute_outcomes"} // absent: a tenant switch's reset must not read as a true → false withdrawal
		}
		legacyCopy := !consents.CopyCurrent(s.cfg.StateDir)
		sent, cloud, err := consents.Sync(ctx, s.cfg.StateDir, doc.Server, enrolledBearer{s}, omit...)
		changed, aerr := s.adoptCloud(doc.TenantID, sent, cloud, legacyCopy)
		if err := errors.Join(err, aerr); err != nil || !changed {
			return err
		}
	}
	return nil
}

// adoptCloud applies the effective row a PUT answered with (nil: none) while the device is still enrolled in tenant: every field the cloud turned off since the record sent (consents.Adopt, another device's withdrawal or controld's reset of pre-copy-2 cloud_judge/training grants) exactly as a local off (written, pending uploads purged, journalled, noted for GET /v1/optins), and an undecided contribute_outcomes the row still holds true restored as the person's own choice in this tenant (a tenant round trip). Nothing is marked acknowledged: the adopted record goes out as the next PUT, which releases the hold.
func (s *Server) adoptCloud(tenant string, sent consents.Consents, cloud *consents.Consents, legacyCopy bool) (bool, error) {
	if cloud == nil {
		return false, nil
	}
	s.files.Lock()
	defer s.files.Unlock()
	if doc, err := s.readEnrollment(); err != nil || doc.TenantID != tenant {
		return false, nil // re-enrolled meanwhile: that row is another tenant's device
	}
	was := consents.Read(s.cfg.StateDir)
	now := consents.Adopt(sent, *cloud, was)
	if err := s.recordConsents(was, now, "cloud_withdrawal"); err != nil {
		return false, err
	}
	var withdrawn, reset []string
	for _, k := range consents.TurnedOff(was, now) {
		if legacyCopy && (k == "cloud_judge" || k == "training") { // controld's m1_107 reset of pre-copy-2 grants, not another device
			reset = append(reset, k)
		} else {
			withdrawn = append(withdrawn, k)
		}
	}
	if err := errors.Join(consents.UpdateList(s.cfg.StateDir, consents.ListCloudWithdrawal, withdrawn, nil),
		consents.UpdateList(s.cfg.StateDir, consents.ListCopyReset, reset, nil)); err != nil {
		return false, err
	}
	restored := now
	restored.ContributeOutcomes = now.ContributeOutcomes || (cloud.ContributeOutcomes && contrib.Undecided(s.cfg.StateDir))
	if err := s.recordConsents(now, restored, "restored_prior_choice"); err != nil {
		return false, err
	}
	return restored != was, nil
}

// resetOldCopy is the one-shot local half of the copy change: a record never stamped with consents.CopyVersion had cloud_judge and training granted under v0.1.14's "Anthropic, US" copy, so both turn off (journalled copy_reset, noted in GET /v1/optins copy_reset) and the record is stamped; a grant from here on passes the X-Mark1-Consent-Copy gate.
func (s *Server) resetOldCopy() error {
	s.files.Lock()
	defer s.files.Unlock()
	if consents.CopyCurrent(s.cfg.StateDir) {
		return nil
	}
	was := consents.Read(s.cfg.StateDir)
	c := was
	c.CloudJudge, c.Training = false, false
	if err := s.recordConsents(was, c, "copy_reset"); err != nil {
		return err
	}
	if err := consents.UpdateList(s.cfg.StateDir, consents.ListCopyReset, consents.TurnedOff(was, c), nil); err != nil {
		return err
	}
	return consents.StampCopy(s.cfg.StateDir)
}

// syncConsents is the session-start sync: one relay off the caller's path that PUTs even with nothing pending, so a withdrawal made on another device lands before this session exports anything.
func (s *Server) syncConsents() {
	s.consentSync.Store(true)
	s.relayNow()
}

// enrolledBearer reads the device token out of the 0600 enrollment document at send time (uplink.TokenSource's shape), so no copy of it lives in this package.
type enrolledBearer struct{ s *Server }

func (b enrolledBearer) Token(context.Context) (string, error) {
	doc, err := b.s.readEnrollment()
	if err != nil {
		return "", err
	}
	return doc.DeviceToken, nil
}

// relayNow is one bounded attempt, off the request path; the loop is the retry.
func (s *Server) relayNow() bool {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	err := s.relayConsents(ctx)
	if errors.Is(err, consents.ErrLegacyCloud) {
		s.cfg.Log.Info("consents: controld accepted e1, cloud_judge and training only; the later consents wait for its upgrade", "err", err)
		return false
	}
	if err != nil {
		s.cfg.Log.Warn("consents: relay to controld failed; the record stays pending", "err", err)
		return false
	}
	return true
}

// relayLoop retries a failed relay with a backoff (a minute, doubling to an hour): a route the gateway does not serve yet is not coming back in the next sixty seconds, and one warning a minute was the founder's whole app log.
func (s *Server) relayLoop() {
	wait := consentRelayEvery
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			if s.relayNow() {
				wait = consentRelayEvery
			} else {
				wait = min(wait*2, time.Hour)
			}
			t.Reset(wait)
		}
	}
}
