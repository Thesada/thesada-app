package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/ratelimit"
	"thesada.app/app/pkg/safego/safegotest"
)

// waitTerminal polls a store until the entry leaves pending. get drops a
// terminal entry, so the returned snapshot is the only read.
func waitTerminal[T any](t *testing.T, s *requestStore[T], id uuid.UUID) *requestEntry[T] {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e := s.get(id); e == nil || e.Status != reqStatusPending {
			return e
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("entry %s still pending", id)
	return nil
}

func TestGoCLI_PanicMarksTheRequestFailed(t *testing.T) {
	log := safegotest.Capture(t)
	s := &Server{cliRequests: newCLIRequestStore(time.Minute)}
	id := s.cliRequests.enqueue()
	s.goCLI(id, "web.cli_cmd", "dev1", func() { panic("device output broke the parser") })

	if rec := log.WaitPanic(t, "web.cli_cmd"); rec["device"] != "dev1" {
		t.Fatalf("panic record = %v, want device=dev1", rec)
	}
	e := waitTerminal(t, s.cliRequests, id)
	if e == nil || e.Status != reqStatusError || !strings.Contains(e.ErrorMsg, "internal error") {
		t.Fatalf("entry = %+v, want an error status the page can stop polling on", e)
	}
}

func TestGoCLI_PanicAfterDoneKeepsTheResult(t *testing.T) {
	log := safegotest.Capture(t)
	s := &Server{cliRequests: newCLIRequestStore(time.Minute)}
	id := s.cliRequests.enqueue()
	resp := &mqtt.CLIResponse{OK: true}
	s.guardCLI(id, "web.cli_cmd", "dev1", func() {
		s.cliRequests.markDone(id, resp)
		panic("snapshot after the reply broke")
	})

	log.WaitPanic(t, "web.cli_cmd")
	if e := s.cliRequests.get(id); e == nil || e.Status != reqStatusDone || e.Response != resp {
		t.Fatalf("entry = %+v, want the done result the device sent", e)
	}
}

func startTestJob(t *testing.T, s *Server, fail string, work func(context.Context, func(int)) string) uuid.UUID {
	t.Helper()
	rec := httptest.NewRecorder()
	s.startJob(rec, httptest.NewRequest(http.MethodPost, "/admin/devices/bulk", nil), 2, fail, work)
	id, err := uuid.Parse(strings.TrimPrefix(rec.Header().Get("Location"), "/admin/jobs/"))
	if err != nil {
		t.Fatalf("job redirect %q: %v", rec.Header().Get("Location"), err)
	}
	return id
}

func TestStartJob_PanicFinishesAtTheFailTarget(t *testing.T) {
	log := safegotest.Capture(t)
	s := &Server{jobs: newRequestStore[jobResult](time.Minute)}
	fail := flashAdminDeleteFailed.on("/admin/devices")
	id := startTestJob(t, s, fail, func(context.Context, func(int)) string { panic("cascade blew up") })

	log.WaitPanic(t, "web.admin_job")
	if e := waitTerminal(t, s.jobs, id); e == nil || e.Response.Target != fail {
		t.Fatalf("job = %+v, want done at %q", e, fail)
	}
}

func TestStartJob_CleanRunFinishesAtTheWorkTarget(t *testing.T) {
	s := &Server{jobs: newRequestStore[jobResult](time.Minute)}
	ok := flashAdminBulkDeleted.on("/admin/devices")
	id := startTestJob(t, s, flashAdminDeleteFailed.on("/admin/devices"),
		func(context.Context, func(int)) string { return ok })
	if e := waitTerminal(t, s.jobs, id); e == nil || e.Response.Target != ok {
		t.Fatalf("job = %+v, want done at %q", e, ok)
	}
}

func TestNotifyAdminWaitlist_SendPanicIsRecovered(t *testing.T) {
	log := safegotest.Capture(t)
	// No mailer: Send panics on the nil receiver.
	s := &Server{cfg: &config.Config{AdminEmail: "ops@example.com"}, waitlistNotify: ratelimit.New(time.Hour, 1)}
	s.notifyAdminWaitlist("someone@example.com", "", "203.0.113.9")
	log.WaitPanic(t, "web.waitlist_notify")
}
