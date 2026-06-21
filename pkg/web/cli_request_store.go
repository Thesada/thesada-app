// In-memory store for in-flight async device CLI requests. Used by the
// poll-based /admin/devices/{id}/config/cmd endpoint pair: enqueue stashes
// a pending entry keyed by uuid, a goroutine waits for the MQTT response
// and updates the entry, the result endpoint reads + drops the entry.
//
// Entries are pruned after entryTTL (timeout budget plus a grace window) so
// abandoned requests do not leak. The store is per-Server, not persisted.
//
// 
package web

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/mqtt"
)

// cliRequestStatus tracks the lifecycle of a single async CLI request.
type cliRequestStatus string

const (
	cliStatusPending cliRequestStatus = "pending"
	cliStatusDone    cliRequestStatus = "done"
	cliStatusTimeout cliRequestStatus = "timeout"
	cliStatusError   cliRequestStatus = "error"
)

// cliRequestEntry is one in-flight or completed CLI request.
// Response is populated on cliStatusDone. ErrorMsg is populated on
// cliStatusTimeout / cliStatusError.
type cliRequestEntry struct {
	Status    cliRequestStatus
	Response  *mqtt.CLIResponse
	ErrorMsg  string
	CreatedAt time.Time
}

// cliRequestStore is a goroutine-safe map of pending CLI requests keyed by
// request id. Entries older than entryTTL are pruned periodically.
type cliRequestStore struct {
	mu       sync.Mutex
	entries  map[uuid.UUID]*cliRequestEntry
	entryTTL time.Duration
}

// newCLIRequestStore builds a store and starts the prune goroutine.
// entryTTL should be CLIRequestTimeout plus a small grace (e.g. 60s) so the
// frontend always has a chance to read terminal state.
// in: entryTTL. out: ready *cliRequestStore.
func newCLIRequestStore(entryTTL time.Duration) *cliRequestStore {
	s := &cliRequestStore{
		entries:  make(map[uuid.UUID]*cliRequestEntry),
		entryTTL: entryTTL,
	}
	go s.prune()
	return s
}

// enqueue stores a fresh pending entry and returns its uuid.
// in: receiver. out: new request id.
func (s *cliRequestStore) enqueue() uuid.UUID {
	id := uuid.New()
	s.mu.Lock()
	s.entries[id] = &cliRequestEntry{
		Status:    cliStatusPending,
		CreatedAt: time.Now(),
	}
	s.mu.Unlock()
	return id
}

// markDone records a successful response.
// in: receiver, request id, response. out: none.
func (s *cliRequestStore) markDone(id uuid.UUID, resp *mqtt.CLIResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[id]; ok {
		e.Status = cliStatusDone
		e.Response = resp
	}
}

// markError records a failure (timeout or transport error).
// status should be cliStatusTimeout or cliStatusError.
// in: receiver, request id, status, message. out: none.
func (s *cliRequestStore) markError(id uuid.UUID, status cliRequestStatus, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[id]; ok {
		e.Status = status
		e.ErrorMsg = msg
	}
}

// get returns a snapshot of the entry, or nil if not found.
// Terminal entries (done / timeout / error) are dropped after the caller
// reads them - the frontend only polls until it sees a terminal state, and
// keeping them around past that just wastes memory.
// in: receiver, request id. out: entry snapshot or nil.
func (s *cliRequestStore) get(id uuid.UUID) *cliRequestEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return nil
	}
	// Snapshot so the caller never touches the stored pointer.
	snap := *e
	if e.Status != cliStatusPending {
		delete(s.entries, id)
	}
	return &snap
}

// prune evicts entries older than entryTTL every 30s. Catches the case
// where the frontend never polled the terminal state (browser closed,
// network drop) so abandoned entries do not pile up indefinitely.
// in: receiver. out: never returns.
func (s *cliRequestStore) prune() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-s.entryTTL)
		s.mu.Lock()
		for id, e := range s.entries {
			if e.CreatedAt.Before(cutoff) {
				delete(s.entries, id)
			}
		}
		s.mu.Unlock()
	}
}
