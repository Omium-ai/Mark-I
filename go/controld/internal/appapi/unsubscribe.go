package appapi

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// GET/POST /api/v1/unsubscribe/{token} (public): GET only shows a confirm page, so a link scanner that opens it changes nothing; POST (the page's button, or a mail client's RFC 8058 one-click) turns the weekly digest off.

var unsubToken = regexp.MustCompile(`^[0-9a-f]{64}$`)

// nobody is the GUC the token lookup runs under: no tenant has this id, so RLS answers nothing and only m1_091's definer reads.
var nobody = uuid.MustParse("00000000-0000-0000-0000-00000000dead")

const unsubPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Mark 1 email</title>
<style>body{margin:0;font:16px/1.5 system-ui,sans-serif;background:#f6f6f7;color:#18181b}main{max-width:440px;margin:12vh auto;padding:32px;background:#fff;border-radius:12px}h1{font-size:20px;margin:0 0 12px}p{margin:0 0 20px;color:#52525b}button{font:inherit;padding:10px 18px;border:0;border-radius:8px;background:#18181b;color:#fff;cursor:pointer}@media (prefers-color-scheme:dark){body{background:#111113;color:#f4f4f5}main{background:#1c1c1f}p{color:#a1a1aa}button{background:#f4f4f5;color:#18181b}}</style>
</head><body><main>`

func writePage(w http.ResponseWriter, status int, inner string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, unsubPage+inner+"</main></body></html>")
}

const pageGone = `<h1>This link no longer works</h1><p>Turn the weekly email off in Mark 1 › Settings › General.</p>`

// unsubscriber finds the prefs row a token names; ok=false means the page was written.
func (m *Module) unsubscriber(w http.ResponseWriter, r *http.Request) (querychoke.TenantID, string, bool) {
	token := r.PathValue("token")
	if !unsubToken.MatchString(token) {
		writePage(w, http.StatusNotFound, pageGone)
		return querychoke.TenantID{}, "", false
	}
	none, _ := querychoke.FromClaims(auth.Claims{TenantID: nobody})
	var tenant uuid.UUID
	var subject string
	err := m.deps.PG.WithTenant(r.Context(), none, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT pref_tenant, pref_subject FROM m1_notification_unsub_lookup($1)`, token).Scan(&tenant, &subject)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writePage(w, http.StatusNotFound, pageGone)
		return querychoke.TenantID{}, "", false
	}
	if err != nil {
		slog.Error("appapi: unsubscribe lookup", "err", err)
		writePage(w, http.StatusServiceUnavailable, `<h1>Something went wrong</h1><p>Please try again in a minute.</p>`)
		return querychoke.TenantID{}, "", false
	}
	tid, err := querychoke.FromClaims(auth.Claims{TenantID: tenant})
	if err != nil {
		writePage(w, http.StatusNotFound, pageGone)
		return querychoke.TenantID{}, "", false
	}
	return tid, subject, true
}

func (m *Module) handleUnsubscribePage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := m.unsubscriber(w, r); !ok {
		return
	}
	writePage(w, http.StatusOK, `<h1>Stop the weekly savings email?</h1><p>You will stop getting Mark 1's weekly summary. You can turn it back on in Mark 1 › Settings › General.</p><form method="post"><button type="submit">Unsubscribe</button></form>`)
}

func (m *Module) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 1<<10))
	tid, subject, ok := m.unsubscriber(w, r)
	if !ok {
		return
	}
	err := m.deps.PG.WithTenant(r.Context(), tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `UPDATE m1_notification_prefs SET weekly_digest = false, updated_at = now() WHERE tenant_id = $1 AND subject = $2`, tid.UUID(), subject)
		return err
	})
	if err != nil {
		slog.Error("appapi: unsubscribe", "err", err)
		writePage(w, http.StatusServiceUnavailable, `<h1>Something went wrong</h1><p>Please try again in a minute.</p>`)
		return
	}
	writePage(w, http.StatusOK, `<h1>You're unsubscribed</h1><p>No more weekly savings emails. You can turn them back on in Mark 1 › Settings › General.</p>`)
}
