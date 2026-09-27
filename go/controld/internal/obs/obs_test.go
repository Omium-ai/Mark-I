package obs

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Ids in a path never become label values: two invites cancelled are one series under the route's pattern.
func TestHTTPMetricsLabelThePatternNotThePath(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("DELETE /api/v1/team/invites/{id}", Config{ServiceName: "obs-label-test"}.HTTPMiddleware(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	for _, id := range []string{"invite:a", "invite:b"} {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, "/api/v1/team/invites/"+id, nil))
	}
	if n := testutil.ToFloat64(httpRequests.WithLabelValues("obs-label-test", "DELETE", "/api/v1/team/invites/{id}", "200")); n != 2 {
		t.Fatalf("pattern series counted %v, want 2", n)
	}
	if n := testutil.CollectAndCount(httpRequests, "omium_http_requests_total"); n != 1 {
		t.Fatalf("%d request series, want the one pattern series", n)
	}
	if got := RouteLabel(httptest.NewRequest(http.MethodGet, "/x/123", nil)); got != "unrouted" {
		t.Fatalf("an unrouted request labels %q", got)
	}
}
