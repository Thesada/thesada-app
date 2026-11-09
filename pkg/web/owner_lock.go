package web

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// ownerLocks serializes a delete's ownership check and commands with a
// reassignment of the same device. An entry lives only while held or awaited.
type ownerLocks struct {
	mu sync.Mutex
	m  map[uuid.UUID]*ownerLock
}

type ownerLock struct {
	ch   chan struct{} // holds one token while locked
	refs int           // holders plus waiters
}

func (o *ownerLocks) ref(id uuid.UUID) *ownerLock {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.m == nil {
		o.m = map[uuid.UUID]*ownerLock{}
	}
	l := o.m[id]
	if l == nil {
		l = &ownerLock{ch: make(chan struct{}, 1)}
		o.m[id] = l
	}
	l.refs++
	return l
}

func (o *ownerLocks) unref(id uuid.UUID, l *ownerLock) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if l.refs--; l.refs == 0 {
		delete(o.m, id)
	}
}

// lock takes id's lock, waiting for it until ctx ends. A free lock is taken
// even when ctx is already done, so only a real wait can be canceled.
// in: ctx, device id. out: release func, or ctx's error with nothing held.
func (o *ownerLocks) lock(ctx context.Context, id uuid.UUID) (func(), error) {
	l := o.ref(id)
	release := func() { <-l.ch; o.unref(id, l) }
	select {
	case l.ch <- struct{}{}:
		return release, nil
	default:
	}
	select {
	case l.ch <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		o.unref(id, l)
		return nil, ctx.Err()
	}
}

// tryLock takes id's lock only when it is free.
// in: device id. out: release func and true, or nil and false.
func (o *ownerLocks) tryLock(id uuid.UUID) (func(), bool) {
	l := o.ref(id)
	select {
	case l.ch <- struct{}{}:
		return func() { <-l.ch; o.unref(id, l) }, true
	default:
		o.unref(id, l)
		return nil, false
	}
}

// size is the number of live entries. Tests only.
func (o *ownerLocks) size() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.m)
}
