package ingest

import (
	"encoding/json"
	"net/http"
)

// apiErr is one 08 §9 taxonomy row as it leaves the wire:
// {"error": {"code": "M1E-…", "message": "…", "detail": {…}}}.
// Codes are cited, never invented — a new failure mode gets a new 08 §9 row
// first (08 §9's own rule).
type apiErr struct {
	status int
	code   string
	msg    string
	detail any
}

// The ingest-relevant rows of 08 §9, as constructors so call sites read like
// the taxonomy.
func errMalformed(msg string) apiErr {
	return apiErr{http.StatusBadRequest, "M1E-2001", msg, nil}
}
func errDivergentBatch() apiErr {
	return apiErr{http.StatusConflict, "M1E-2003", "batch_id already landed with different content bytes", nil}
}
func errTooLarge() apiErr {
	return apiErr{http.StatusRequestEntityTooLarge, "M1E-2004", "decoded batch exceeds 32 MiB", nil}
}
func errMediaType(msg string) apiErr {
	return apiErr{http.StatusUnsupportedMediaType, "M1E-2005", msg, nil}
}
func errInvariant(eventIDs []string, kinds []string) apiErr {
	return apiErr{http.StatusUnprocessableEntity, "M1E-2006", "invariant-violating events",
		map[string]any{"event_ids": eventIDs, "kinds": kinds}}
}
func errIdentityDisagreement() apiErr {
	return apiErr{http.StatusForbidden, "M1E-8003", "envelope identity disagrees with verified token claims", nil}
}
func errRateLimited() apiErr {
	return apiErr{http.StatusTooManyRequests, "M1E-9001", "rate limited", nil}
}
func errServer(msg string) apiErr {
	return apiErr{http.StatusServiceUnavailable, "M1E-9500", msg, nil}
}

func writeErr(w http.ResponseWriter, e apiErr) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.status)
	body := map[string]any{"error": map[string]any{"code": e.code, "message": e.msg}}
	if e.detail != nil {
		body["error"].(map[string]any)["detail"] = e.detail
	}
	_ = json.NewEncoder(w).Encode(body)
}

// writeUpgradeRequired is the 426 M1E-2007 shape of 08 §10.2: the structured
// upgrade hint rides beside the error, not inside it.
func writeUpgradeRequired(w http.ResponseWriter, presented string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUpgradeRequired)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": "M1E-2007", "message": "schema out of accepted window"},
		"upgrade": map[string]any{
			"presented": presented,
			"accepted":  []string{schemaV1},
			"min_edge":  nil, "window_closes": nil,
			"notes_uri": "https://docs.omium.ai/mark1/upgrade/m1p-v1",
		},
	})
}
