// Admin work that can outlast the edge proxy's request timeout runs as a
// job: the POST starts it and redirects to /admin/jobs/{id}, which refreshes
// until the job is done and then redirects to the page it names.
package web

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/safego"
)

// jobResult is where a finished job sends the operator. The target carries
// registered flash codes only, never request text.
type jobResult struct{ Target string }

// errJobsDrained is DrainJobs giving up with work still running.
var errJobsDrained = errors.New("admin jobs still running at the shutdown deadline")

// jobRunner tracks job goroutines so shutdown can stop and wait for them.
// The zero value is ready to use.
type jobRunner struct {
	mu       sync.Mutex
	wg       sync.WaitGroup
	stopped  bool
	stop     chan struct{}
	deadline time.Time // when the drain gives up, zero when it has none
}

// begin registers one job. in: none. out: done func, a channel closed on
// shutdown, false once draining has started.
func (j *jobRunner) begin() (func(), <-chan struct{}, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.stopped {
		return nil, nil, false
	}
	if j.stop == nil {
		j.stop = make(chan struct{})
	}
	j.wg.Add(1)
	return j.wg.Done, j.stop, true
}

// drain refuses new jobs, signals running ones, and waits until they return
// or ctx ends. in: ctx bounding the wait. out: errJobsDrained on the deadline.
func (j *jobRunner) drain(ctx context.Context) error {
	j.mu.Lock()
	if !j.stopped {
		j.stopped = true
		j.deadline, _ = ctx.Deadline()
		if j.stop != nil {
			close(j.stop)
		}
	}
	j.mu.Unlock()
	done := make(chan struct{})
	go func() { j.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errJobsDrained
	}
}

// nearDeadline reports whether a drain is under way and ends within margin.
// in: margin. out: true when work should not start a step it cannot finish.
func (j *jobRunner) nearDeadline(margin time.Duration) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.stopped && !j.deadline.IsZero() && time.Until(j.deadline) < margin
}

// DrainJobs cancels admin job contexts and waits for the jobs, bounded by
// ctx. A delete job finishes the device it is on unless ctx ends within
// stopMargin, then stops before that device's DB delete.
// in: ctx bounding the wait. out: error when jobs were still running.
func (s *Server) DrainJobs(ctx context.Context) error {
	return s.runner.drain(ctx)
}

// startJob runs work in the background and answers with the job page. The
// work outlives the request, so its context drops the request's cancellation
// and is cancelled by DrainJobs instead. work decides where it may stop.
// A panic in work finishes the job at failTarget, not a page that never ends.
// in: writer, request, total units, failure target, work(ctx, progress(done))
// returning the redirect target. out: 302 to /admin/jobs/{id}, 503 while shutting down.
func (s *Server) startJob(w http.ResponseWriter, r *http.Request, total int, failTarget string, work func(ctx context.Context, progress func(done int)) string) {
	done, stop, ok := s.runner.begin()
	if !ok {
		http.Error(w, "server is shutting down, retry shortly", http.StatusServiceUnavailable)
		return
	}
	id := s.jobs.enqueue()
	s.jobs.progress(id, 0, total)
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	go func() {
		defer done()
		defer cancel()
		go func() {
			select {
			case <-stop:
				cancel()
			case <-ctx.Done():
			}
		}()
		target := failTarget
		safego.Run("web.admin_job", func() {
			target = work(ctx, func(n int) { s.jobs.progress(id, n, total) })
		}, "job_id", id)
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
