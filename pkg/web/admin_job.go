// Admin work that can outlast the edge proxy's request timeout runs as a
// job: the POST starts it and redirects to /admin/jobs/{id}, which refreshes
// until the job is done and then redirects to the page it names.
package web

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// jobResult is where a finished job sends the operator. The target carries
// registered flash codes only, never request text.
type jobResult struct{ Target string }

// startJob runs work in the background and answers with the job page. The
// work outlives the request, so it gets a context free of its cancellation.
// in: writer, request, total units, work(ctx, progress(done)) returning the
// redirect target. out: 302 to /admin/jobs/{id}.
func (s *Server) startJob(w http.ResponseWriter, r *http.Request, total int, work func(ctx context.Context, progress func(done int)) string) {
	id := s.jobs.enqueue()
	s.jobs.progress(id, 0, total)
	ctx := context.WithoutCancel(r.Context())
	go func() {
		target := work(ctx, func(done int) { s.jobs.progress(id, done, total) })
		s.jobs.markDone(id, jobResult{Target: target})
	}()
	http.Redirect(w, r, "/admin/jobs/"+id.String(), http.StatusFound)
}

// handleAdminJob shows a running job's progress, redirects a finished one to
// its target, and says so when the id is unknown, read or expired.
// in: writer, GET /admin/jobs/{id}. out: HTML page or 302.
func (s *Server) handleAdminJob(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	e := s.jobs.get(id)
	if e != nil && e.Status != reqStatusPending {
		http.Redirect(w, r, e.Response.Target, http.StatusFound)
		return
	}
	data := map[string]interface{}{"Running": e != nil}
	if e != nil {
		data["Done"], data["Total"] = e.Done, e.Total
	}
	s.render(w, r, "admin-job.html", data)
}
