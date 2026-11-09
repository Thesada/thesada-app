package web

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOwnerLocks_EntryGoesWithItsLastHolder(t *testing.T) {
	var o ownerLocks
	id := uuid.New()
	release, err := o.lock(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := o.tryLock(id); ok {
		t.Fatal("second holder got a held lock")
	}
	release()
	if n := o.size(); n != 0 {
		t.Fatalf("%d entries left after release, want 0", n)
	}
	for i := 0; i < 100; i++ {
		if rel, ok := o.tryLock(uuid.New()); ok {
			rel()
		}
	}
	if n := o.size(); n != 0 {
		t.Fatalf("%d entries left for unused ids, want 0", n)
	}
}

func TestOwnerLocks_WaiterGivesUpOnCancel(t *testing.T) {
	var o ownerLocks
	id := uuid.New()
	release, _ := o.lock(context.Background(), id)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := o.lock(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter = %v, want deadline exceeded", err)
	}
	release()
	if n := o.size(); n != 0 {
		t.Fatalf("%d entries left, want 0", n)
	}
	got, err := o.lock(context.Background(), id)
	if err != nil {
		t.Fatalf("lock after the waiter left: %v", err)
	}
	got()
}

func TestOwnerLocks_FreeLockIgnoresADoneContext(t *testing.T) {
	var o ownerLocks
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 50; i++ {
		release, err := o.lock(ctx, uuid.New())
		if err != nil {
			t.Fatalf("free lock refused on a done ctx: %v", err)
		}
		release()
	}
}
