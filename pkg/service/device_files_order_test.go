package service

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// A store running for one device holds only that device: other devices and plain
// token reads go on, a write to the same device waits for the store.
func TestDeviceOrder_LockIsPerDevice(t *testing.T) {
	s := &DeviceFilesService{}
	a, b := uuid.New(), uuid.New()
	d := s.order(a)
	d.mu.Lock()

	others := make(chan struct{})
	go func() {
		s.WriteLanded(b)
		s.ReadToken(a)
		close(others)
	}()
	select {
	case <-others:
	case <-time.After(time.Second):
		t.Fatal("a store on one device blocked another device or a token read")
	}

	same := make(chan uint64)
	go func() { same <- s.WriteLanded(a) }()
	select {
	case <-same:
		t.Fatal("a write landed while a store for the same device was running")
	case <-time.After(50 * time.Millisecond):
	}
	d.mu.Unlock()
	if got := <-same; got != 1 {
		t.Errorf("generation after the write = %d, want 1", got)
	}
}

func TestDeviceOrder_DistrustOpenNetworks(t *testing.T) {
	s := &DeviceFilesService{}
	pk := uuid.New()
	if !s.OpenNetworksTrusted(pk) {
		t.Fatal("a new device starts distrusted")
	}
	s.DistrustOpenNetworks(pk)
	if s.OpenNetworksTrusted(pk) {
		t.Error("open networks still trusted after DistrustOpenNetworks")
	}
}
