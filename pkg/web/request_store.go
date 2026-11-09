// In-memory store for async work the page polls: device CLI requests on
// /admin/devices/{id}/config/cmd and the bulk and tenant delete jobs.
// Enqueue stashes a pending entry keyed by uuid, a goroutine does the work
// and updates the entry, the poll endpoint reads it.
//
// Terminal entries are pruned entryTTL after they finish, so a second read
// (a lost redirect, another tab) still sees the outcome. A pending entry is never pruned: its goroutine always ends,
// every step it runs is bounded. The store is per-Server, not persisted.
package web

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/mqtt"
)

// requestStatus tracks the lifecycle of a single async request.
type requestStatus string

const (
	reqStatusPending requestStatus = "pending"
	reqStatusDone    requestStatus = "done"
	reqStatusTimeout requestStatus = "timeout"
	reqStatusError   requestStatus = "error"
)

// requestEntry is one in-flight or completed request. Response is set on
// done, ErrorMsg on timeout or error, Done and Total while it runs.
type requestEntry[T any] struct {
	Status     requestStatus
	Response   T
	ErrorMsg   string
	Done       int
	Total      int
	CreatedAt  time.Time
	FinishedAt time.Time
}

// requestStore is a goroutine-safe map of async requests keyed by id.
type requestStore[T any] struct {
	mu       sync.Mutex
	entries  map[uuid.UUID]*requestEntry[T]
	entryTTL time.Duration
}

// cliRequestStore holds the device CLI round-trips.
type cliRequestStore = requestStore[*mqtt.CLIResponse]

// newRequestStore builds a store and starts the prune goroutine, which ends
// when stop closes (nil: never). entryTTL is how long a terminal entry stays readable.
// in: entryTTL, stop. out: ready store.
func newRequestStore[T any](entryTTL time.Duration, stop <-chan struct{}) *requestStore[T] {
	s := &requestStore[T]{
		entries:  make(map[uuid.UUID]*requestEntry[T]),
		entryTTL: entryTTL,
	}
	go s.prune(stop)
	return s
}

// newCLIRequestStore builds the CLI store. entryTTL should be
// CLIRequestTimeout plus a small grace (e.g. 60s).
// in: entryTTL, stop. out: ready *cliRequestStore.
func newCLIRequestStore(entryTTL time.Duration, stop <-chan struct{}) *cliRequestStore {
	return newRequestStore[*mqtt.CLIResponse](entryTTL, stop)
}

// enqueue stores a fresh pending entry and returns its uuid.
// in: receiver. out: new request id.
func (s *requestStore[T]) enqueue() uuid.UUID {
	id := uuid.New()
	s.mu.Lock()
	s.entries[id] = &requestEntry[T]{
		Status:    reqStatusPending,
		CreatedAt: time.Now(),
	}
	s.mu.Unlock()
	return id
}

// progress records how far a pending request got.
// in: receiver, request id, done, total. out: none.
func (s *requestStore[T]) progress(id uuid.UUID, done, total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[id]; ok {
		e.Done, e.Total = done, total
	}
}

// markDone records a successful response.
// in: receiver, request id, response. out: none.
func (s *requestStore[T]) markDone(id uuid.UUID, resp T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[id]; ok {
		e.Status = reqStatusDone
		e.Response = resp
		e.FinishedAt = time.Now()
	}
}

// markError records a failure (timeout or transport error).
// status should be reqStatusTimeout or reqStatusError.
// in: receiver, request id, status, message. out: none.
func (s *requestStore[T]) markError(id uuid.UUID, status requestStatus, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[id]; ok {
		e.Status = status
		e.ErrorMsg = msg
		e.FinishedAt = time.Now()
	}
}

// failPending marks an entry error only while it is still pending, so a
// late failure cannot overwrite a request that already finished.
// in: receiver, request id, message. out: none.
func (s *requestStore[T]) failPending(id uuid.UUID, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[id]; ok && e.Status == reqStatusPending {
		e.Status = reqStatusError
		e.ErrorMsg = msg
		e.FinishedAt = time.Now()
	}
}

// get returns a snapshot of the entry, or nil if not found. It never evicts:
// pruneBefore does, so every read until then sees the outcome.
// in: receiver, request id. out: entry snapshot or nil.
func (s *requestStore[T]) get(id uuid.UUID) *requestEntry[T] {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return nil
	}
	// Snapshot so the caller never touches the stored pointer.
	snap := *e
	return &snap
}

// prune evicts terminal entries entryTTL after they finished, every 30s.
// Catches the case where the frontend never polled the terminal state
// (browser closed, network drop) so abandoned entries do not pile up.
// in: receiver, stop. out: returns when stop closes.
func (s *requestStore[T]) prune(stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.pruneBefore(time.Now().Add(-s.entryTTL))
		case <-stop:
			return
		}
	}
}

// pruneBefore drops terminal entries that finished before cutoff.
// in: receiver, cutoff. out: none.
func (s *requestStore[T]) pruneBefore(cutoff time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.entries {
		if e.Status != reqStatusPending && e.FinishedAt.Before(cutoff) {
			delete(s.entries, id)
		}
	}
}
