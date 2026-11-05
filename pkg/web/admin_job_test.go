package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// jobRequest builds GET /admin/jobs/{id}.
func jobRequest(id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin/jobs/"+id, nil)
	r.SetPathValue("id", id)
	return r
}

func TestAdminJob_PendingShowsProgressThenRedirects(t *testing.T) {
	s := &Server{jobs: newRequestStore[jobResult](time.Minute)}
	s.parseTemplates()
	id := s.jobs.enqueue()
	s.jobs.progress(id, 1, 3)

	rec := httptest.NewRecorder()
	s.handleAdminJob(rec, jobRequest(id.String()))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "1 of 3") || !strings.Contains(body, `http-equiv="refresh"`) {
		t.Fatalf("pending job: %d, want 200 with progress and a refresh, body %q", rec.Code, body)
	}

	s.jobs.markDone(id, jobResult{Target: flashAdminBulkDeleted.on("/admin/devices")})
	rec = httptest.NewRecorder()
	s.handleAdminJob(rec, jobRequest(id.String()))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != flashAdminBulkDeleted.on("/admin/devices") {
		t.Fatalf("done job: %d %q, want 302 to its target", rec.Code, rec.Header().Get("Location"))
	}

	rec = httptest.NewRecorder()
	s.handleAdminJob(rec, jobRequest(id.String()))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `http-equiv="refresh"`) {
		t.Fatalf("read job: %d, want 200 without a refresh", rec.Code)
	}
}

func TestAdminJob_BadIDIs404(t *testing.T) {
	s := &Server{jobs: newRequestStore[jobResult](time.Minute)}
	rec := httptest.NewRecorder()
	s.handleAdminJob(rec, jobRequest("not-a-uuid"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRequestStore_PruneKeepsPendingWork(t *testing.T) {
	s := newRequestStore[jobResult](time.Minute)
	running, finished := s.enqueue(), s.enqueue()
	s.markDone(finished, jobResult{})
	s.pruneBefore(time.Now().Add(time.Hour))
	if s.get(running) == nil {
		t.Fatal("prune dropped a job that is still running")
	}
	if s.get(finished) != nil {
		t.Fatal("prune kept a finished job past its TTL")
	}
	if s.get(uuid.New()) != nil {
		t.Fatal("unknown id returned an entry")
	}
}
