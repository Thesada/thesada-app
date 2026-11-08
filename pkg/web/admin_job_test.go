package web

import (
	"context"
	"errors"
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
	s := &Server{jobs: newRequestStore[jobResult](time.Minute, t.Context().Done())}
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

	// A lost redirect or a second tab reads the outcome again.
	rec = httptest.NewRecorder()
	s.handleAdminJob(rec, jobRequest(id.String()))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != flashAdminBulkDeleted.on("/admin/devices") {
		t.Fatalf("second read: %d %q, want the same 302", rec.Code, rec.Header().Get("Location"))
	}

	s.jobs.pruneBefore(time.Now().Add(time.Hour))
	rec = httptest.NewRecorder()
	s.handleAdminJob(rec, jobRequest(id.String()))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `http-equiv="refresh"`) {
		t.Fatalf("expired job: %d, want 200 without a refresh", rec.Code)
	}
}

func TestRequestStore_PruneKeepsFinishedWorkInsideItsTTL(t *testing.T) {
	s := newRequestStore[jobResult](time.Minute, t.Context().Done())
	finished := s.enqueue()
	s.markDone(finished, jobResult{Target: "/admin"})
	s.pruneBefore(time.Now().Add(-time.Minute))
	if e := s.get(finished); e == nil || e.Response.Target != "/admin" {
		t.Fatalf("prune with a past cutoff dropped a fresh outcome: %+v", e)
	}
}

func TestRequestStore_PruneStopsOnStop(t *testing.T) {
	stop := make(chan struct{})
	s := &requestStore[jobResult]{entries: map[uuid.UUID]*requestEntry[jobResult]{}}
	exited := make(chan struct{})
	go func() { s.prune(stop); close(exited) }()
	close(stop)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("prune goroutine kept running after stop closed")
	}
}

func TestStartJob_AnswersBeforeTheWorkEnds(t *testing.T) {
	s := &Server{jobs: newRequestStore[jobResult](time.Minute, t.Context().Done())}
	release := make(chan struct{})
	finished := make(chan struct{})
	rec := postTestJob(s, func(context.Context, func(int)) string {
		<-release
		close(finished)
		return "/admin"
	})
	select {
	case <-finished:
		t.Fatal("work finished before release")
	default:
	}
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/admin/jobs/") {
		t.Fatalf("startJob = %d %q, want 302 to the job page while the work runs", rec.Code, rec.Header().Get("Location"))
	}
	close(release)
	<-finished
}

func TestJobRunner_DrainCancelsBeforeItReleasesTheLock(t *testing.T) {
	var j jobRunner
	ctx, cancel := context.WithCancel(context.Background())
	done, ok := j.begin(cancel)
	if !ok {
		t.Fatal("begin refused before any drain")
	}
	drained := make(chan error, 1)
	go func() { drained <- j.drain(context.Background()) }()
	for {
		j.mu.Lock()
		stopped := j.stopped
		j.mu.Unlock()
		if stopped {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() == nil {
		t.Fatal("drain is under way but the job context is still live")
	}
	if _, ok := j.begin(func() {}); ok {
		t.Fatal("begin admitted a job after the drain started")
	}
	done()
	if err := <-drained; err != nil {
		t.Fatal(err)
	}
}

func TestAdminJob_BadIDIs404(t *testing.T) {
	s := &Server{jobs: newRequestStore[jobResult](time.Minute, t.Context().Done())}
	rec := httptest.NewRecorder()
	s.handleAdminJob(rec, jobRequest("not-a-uuid"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRequestStore_PruneKeepsPendingWork(t *testing.T) {
	s := newRequestStore[jobResult](time.Minute, t.Context().Done())
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

// postTestJob posts to startJob with work and returns the recorder.
func postTestJob(s *Server, work func(ctx context.Context, progress func(int)) string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.startJob(rec, httptest.NewRequest(http.MethodPost, "/", nil), 1, "/admin", work)
	return rec
}

func TestDrainJobs_CancelsAndWaitsForRunningJobs(t *testing.T) {
	s := &Server{jobs: newRequestStore[jobResult](time.Minute, t.Context().Done())}
	started, finished := make(chan struct{}), make(chan struct{})
	rec := postTestJob(s, func(ctx context.Context, _ func(int)) string {
		close(started)
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond)
		close(finished)
		return "/admin"
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("startJob = %d, want 302", rec.Code)
	}
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.DrainJobs(ctx); err != nil {
		t.Fatalf("DrainJobs = %v, want nil", err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("DrainJobs returned before the job did")
	}
	if rec := postTestJob(s, func(context.Context, func(int)) string { return "" }); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("startJob after drain = %d, want 503", rec.Code)
	}
}

func TestDrainJobs_GivesUpAtTheDeadline(t *testing.T) {
	s := &Server{jobs: newRequestStore[jobResult](time.Minute, t.Context().Done())}
	release := make(chan struct{})
	defer close(release)
	postTestJob(s, func(context.Context, func(int)) string {
		<-release
		return ""
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.DrainJobs(ctx); !errors.Is(err, errJobsDrained) {
		t.Fatalf("DrainJobs = %v, want errJobsDrained", err)
	}
}

func TestDrainJobs_NoJobsReturnsAtOnce(t *testing.T) {
	s := &Server{}
	if err := s.DrainJobs(context.Background()); err != nil {
		t.Fatalf("DrainJobs with no jobs = %v", err)
	}
}

func TestJobRunner_NearDeadlineOnlyWhileDrainingCloseToIt(t *testing.T) {
	var j jobRunner
	if j.nearDeadline(time.Hour) {
		t.Fatal("near the deadline before any drain")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := j.drain(ctx); err != nil {
		t.Fatal(err)
	}
	if !j.nearDeadline(3 * time.Second) {
		t.Fatal("1 s left, margin 3 s: want near")
	}
	if j.nearDeadline(100 * time.Millisecond) {
		t.Fatal("1 s left, margin 100 ms: want not near")
	}
	var open jobRunner
	if err := open.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if open.nearDeadline(time.Hour) {
		t.Fatal("a drain with no deadline is never near it")
	}
}
