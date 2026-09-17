package control

import (
	"context"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
)

const consentRelayEvery = time.Minute

// relayConsents pushes a pending Step-4 record to controld once the device is enrolled; not enrolled yet is not an error, the record just stays pending for the next tick.
func (s *Server) relayConsents(ctx context.Context) error {
	if !consents.Pending(s.cfg.StateDir) {
		return nil
	}
	doc, err := s.readEnrollment()
	if err != nil || doc.liveState() != "active" {
		return nil
	}
	return consents.Relay(ctx, s.cfg.StateDir, doc.Server, enrolledBearer{s})
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
// ponytail: two concurrent attempts can PUT the same record twice (an extra m1_082 row, never a lost revocation: each marks relayed only the bytes it sent); a mutex if the duplicate rows ever matter.
func (s *Server) relayNow() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.relayConsents(ctx); err != nil {
		s.cfg.Log.Warn("consents: relay to controld failed; the record stays pending", "err", err)
	}
}

func (s *Server) relayLoop(stop <-chan struct{}) {
	t := time.NewTicker(consentRelayEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.relayNow()
		}
	}
}
