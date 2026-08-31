//go:build integration

package chconn

// DSN-gated ClickHouse integration for boot refusal R3 (05 §1.2): the
// refusal must be FALSIFIABLE — proven to fire on effective settings of 0 —
// not asserted by proxy through an unreachable address. In-package so the
// tests can aim assertAsyncInsert at a connection rigged to an effective 0,
// which is exactly what Open's settings-free probe sees when the server-side
// m1p_ingest profile (07: users.d/m1p-ingest.yaml) is missing or wrong.
//
// Gate: M1_TEST_CH_DSN (same var and resolution as chproj's integration
// suite). Absent ⇒ skip, unless M1_REQUIRE_STORES=1 ⇒ fail.

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// chNativeEndpoint mirrors chproj's chEndpoint: the contract var is the HTTP
// URL (justfile, 12 §11.4), resolved to the native endpoint via the server's
// own tcp_port — sound in the sanctioned no-remap lane; container lanes with
// a remapped native port must pass clickhouse://user:pass@host:port instead.
func chNativeEndpoint(t *testing.T) (addr, user, pass string) {
	t.Helper()
	v := os.Getenv("M1_TEST_CH_DSN")
	if v == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_TEST_CH_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_TEST_CH_DSN unset; skipping ClickHouse-backed test")
	}
	u, err := url.Parse(v)
	if err != nil {
		t.Fatalf("M1_TEST_CH_DSN unparseable: %v", err)
	}
	user = "default"
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	switch u.Scheme {
	case "clickhouse", "tcp":
		return u.Host, user, pass
	case "http", "https":
	default:
		t.Fatalf("M1_TEST_CH_DSN scheme %q: want http(s) or clickhouse", u.Scheme)
	}
	probe := *u
	probe.User = nil
	q := probe.Query()
	q.Set("query", "SELECT getServerPort('tcp_port')")
	probe.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, probe.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-ClickHouse-User", user)
	if pass != "" {
		req.Header.Set("X-ClickHouse-Key", pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("cannot reach test ClickHouse over M1_TEST_CH_DSN: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("tcp_port probe over M1_TEST_CH_DSN: status %d: %s", resp.StatusCode, body)
	}
	return net.JoinHostPort(u.Hostname(), strings.TrimSpace(string(body))), user, pass
}

// R3 negative, live: a connection whose EFFECTIVE settings are 0 must refuse.
// Client settings of 0 produce the same effective values getSetting reports
// when the server-side profile is absent, so this exercises the exact
// refusal branch Open's settings-free probe relies on.
func TestIntegrationR3RefusesEffectiveZeroSettings(t *testing.T) {
	addr, user, pass := chNativeEndpoint(t)
	ctx := context.Background()
	for _, name := range []string{"async_insert", "wait_for_async_insert"} {
		raw, err := clickhouse.Open(&clickhouse.Options{
			Addr:     []string{addr},
			Auth:     clickhouse.Auth{Database: "default", Username: user, Password: pass},
			Settings: clickhouse.Settings{name: 0},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = assertAsyncInsert(ctx, raw, "test rig")
		_ = raw.Close()
		if err == nil {
			t.Fatalf("R3 assertion passed with effective %s=0 — the refusal can never fire", name)
		}
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("refusal must name the offending setting %s: %v", name, err)
		}
	}
}

// The unreachable-store shape of the boot refusal: Open must error, never
// hand back a half-connected handle (05 §1.2: no degraded half-boot).
func TestIntegrationOpenRefusesUnreachableStore(t *testing.T) {
	chNativeEndpoint(t) // same gate: this is a store-lane test even though it dials a dead port
	if _, err := Open(context.Background(), Options{Addr: "127.0.0.1:1", Database: "x", Username: "u"}); err == nil {
		t.Fatal("chconn.Open reached an unreachable store")
	}
}
