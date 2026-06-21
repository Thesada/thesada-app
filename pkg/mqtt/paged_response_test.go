// Unit tests for awaitPagedCLIResponse - the multi-page cli/response
// accumulator. Pure logic over an in-memory channel; no broker / DB.
package mqtt

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// feed marshals each CLIResponse and pushes it onto a buffered channel in
// the given order, then returns the channel for awaitPagedCLIResponse.
func feed(t *testing.T, msgs ...CLIResponse) chan []byte {
	t.Helper()
	ch := make(chan []byte, len(msgs))
	for _, m := range msgs {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		ch <- b
	}
	return ch
}

func intp(i int) *int    { return &i }
func boolp(b bool) *bool { return &b }

func TestAwaitPagedCLIResponse(t *testing.T) {
	t.Run("single page no pagination fields (pre-1.4.6 firmware)", func(t *testing.T) {
		ch := feed(t, CLIResponse{Cmd: "version", OK: true, Output: []string{"v1.4.5"}})
		resp, err := awaitPagedCLIResponse(context.Background(), ch)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !resp.OK || len(resp.Output) != 1 || resp.Output[0] != "v1.4.5" {
			t.Fatalf("got %+v", resp)
		}
		if resp.Page != nil || resp.More != nil {
			t.Fatalf("Page/More should be cleared, got %+v", resp)
		}
	})

	t.Run("single page with page:0 more:false", func(t *testing.T) {
		ch := feed(t, CLIResponse{Cmd: "help", OK: true, Page: intp(0), More: boolp(false), Output: []string{"a", "b"}})
		resp, err := awaitPagedCLIResponse(context.Background(), ch)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(resp.Output) != 2 || resp.Output[0] != "a" || resp.Output[1] != "b" {
			t.Fatalf("got %+v", resp)
		}
	})

	t.Run("multi page in order", func(t *testing.T) {
		ch := feed(t,
			CLIResponse{Cmd: "fs.ls", OK: true, Page: intp(0), More: boolp(true), Output: []string{"a", "b"}},
			CLIResponse{Cmd: "fs.ls", OK: true, Page: intp(1), More: boolp(true), Output: []string{"c"}},
			CLIResponse{Cmd: "fs.ls", OK: true, Page: intp(2), More: boolp(false), Output: []string{"d", "e"}},
		)
		resp, err := awaitPagedCLIResponse(context.Background(), ch)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		want := []string{"a", "b", "c", "d", "e"}
		if len(resp.Output) != len(want) {
			t.Fatalf("len: got %v want %v", resp.Output, want)
		}
		for i := range want {
			if resp.Output[i] != want[i] {
				t.Fatalf("idx %d: got %q want %q", i, resp.Output[i], want[i])
			}
		}
		if resp.Page != nil || resp.More != nil {
			t.Fatalf("Page/More should be cleared")
		}
	})

	t.Run("multi page out of order (final arrives before middle)", func(t *testing.T) {
		ch := feed(t,
			CLIResponse{Cmd: "fs.ls", OK: true, Page: intp(0), More: boolp(true), Output: []string{"a"}},
			CLIResponse{Cmd: "fs.ls", OK: true, Page: intp(2), More: boolp(false), Output: []string{"c"}},
			CLIResponse{Cmd: "fs.ls", OK: true, Page: intp(1), More: boolp(true), Output: []string{"b"}},
		)
		resp, err := awaitPagedCLIResponse(context.Background(), ch)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		want := []string{"a", "b", "c"}
		for i := range want {
			if resp.Output[i] != want[i] {
				t.Fatalf("idx %d: got %q want %q", i, resp.Output[i], want[i])
			}
		}
	})

	t.Run("times out when a page never arrives", func(t *testing.T) {
		ch := feed(t,
			CLIResponse{Cmd: "fs.ls", OK: true, Page: intp(0), More: boolp(true), Output: []string{"a"}},
			CLIResponse{Cmd: "fs.ls", OK: true, Page: intp(2), More: boolp(false), Output: []string{"c"}},
		)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := awaitPagedCLIResponse(ctx, ch)
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
	})
}
