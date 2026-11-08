package web

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/mqtt"
)

// fakeFS answers the CLI commands stagedWrite sends with the firmware's
// reply texts, over an in-memory LittleFS. A hook can replace any reply.
type fakeFS struct {
	files map[string]string
	calls []string
	hook  func(n int, cmd, arg string) *fakeReply
}

// fakeReply overrides one reply. errTimeout makes the call wait out its deadline.
type fakeReply struct {
	resp *mqtt.CLIResponse
	err  error
}

var errTimeout = errors.New("wait for the deadline")

func newFakeFS(files map[string]string) *fakeFS {
	return &fakeFS{files: files}
}

func (f *fakeFS) reply(ctx context.Context, cmd, arg string, run func() *mqtt.CLIResponse) (*mqtt.CLIResponse, error) {
	f.calls = append(f.calls, cmd+" "+arg)
	if f.hook != nil {
		if r := f.hook(len(f.calls), cmd, arg); r != nil {
			if errors.Is(r.err, errTimeout) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return r.resp, r.err
		}
	}
	return run(), nil
}

// okLines is an ok:true reply. Lines are cut to 63 bytes like the firmware's char msg[64].
func okLines(cmd string, lines ...string) *mqtt.CLIResponse {
	for i, l := range lines {
		if len(l) > 63 {
			lines[i] = l[:63]
		}
	}
	return &mqtt.CLIResponse{Cmd: cmd, OK: true, Output: lines}
}

func (f *fakeFS) CLIRequestRaw(ctx context.Context, _, cmd string, raw []byte) (*mqtt.CLIResponse, error) {
	path, content, _ := strings.Cut(string(raw), "\n")
	return f.reply(ctx, cmd, path, func() *mqtt.CLIResponse {
		if cmd == "fs.append" {
			f.files[path] += content
			return okLines(cmd, fmt.Sprintf("Appended %d bytes to %s", len(content), path))
		}
		f.files[path] = content
		return okLines(cmd, fmt.Sprintf("Wrote %d bytes to %s", len(content), path))
	})
}

func (f *fakeFS) CLIRequest(ctx context.Context, _, cmd, args string) (*mqtt.CLIResponse, error) {
	return f.reply(ctx, cmd, args, func() *mqtt.CLIResponse {
		switch cmd {
		case "fs.cat":
			path, _, _ := strings.Cut(args, " ")
			body, ok := f.files[path]
			if !ok {
				return &mqtt.CLIResponse{Cmd: cmd, OK: false, Output: []string{"File not found"}}
			}
			total := len(body)
			return &mqtt.CLIResponse{Cmd: cmd, OK: true, Total: &total}
		case "fs.mv":
			src, dst, _ := strings.Cut(args, " ")
			body, ok := f.files[src]
			if !ok {
				return okLines(cmd, "Failed to rename")
			}
			f.files[dst] = body
			delete(f.files, src)
			return okLines(cmd, "Renamed "+src+" -> "+dst)
		case "fs.rm":
			if _, ok := f.files[args]; !ok {
				return okLines(cmd, "Failed to remove (file not found or directory)")
			}
			delete(f.files, args)
			return okLines(cmd, "Removed "+args)
		}
		return &mqtt.CLIResponse{Cmd: cmd, OK: false, Output: []string{"Unknown command: " + cmd}}
	})
}

// when returns a reply for the calls cond picks, nil for the rest.
func when(cond bool, resp *mqtt.CLIResponse, err error) *fakeReply {
	if !cond {
		return nil
	}
	return &fakeReply{resp, err}
}

const oldConfig = `{"wifi":{"ssid":"old"}}`

func cmdNames(calls []string) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i], _, _ = strings.Cut(c, " ")
	}
	return out
}

func TestStagedWrite_RenamesOnlyAfterEveryChunkAcked(t *testing.T) {
	for _, size := range []int{10, writeChunkSize, 2*writeChunkSize + 7} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			fs := newFakeFS(map[string]string{"/config.json": oldConfig})
			content := strings.Repeat("x", size)
			if err := stagedWrite(context.Background(), fs, time.Second, "p", "/config.json", []byte(content)); err != nil {
				t.Fatalf("stagedWrite: %v", err)
			}
			n := writeChunkCount(size)
			want := []string{"fs.write /config.json.new"}
			for i := 1; i < n; i++ {
				want = append(want, "fs.append /config.json.new")
			}
			want = append(want, fmt.Sprintf("fs.cat /config.json.new %d 1", size), "fs.mv /config.json.new /config.json")
			if strings.Join(fs.calls, "|") != strings.Join(want, "|") {
				t.Fatalf("calls = %q, want %q", fs.calls, want)
			}
			if fs.files["/config.json"] != content {
				t.Fatalf("config.json holds %d bytes, want %d", len(fs.files["/config.json"]), size)
			}
			if _, left := fs.files["/config.json.new"]; left {
				t.Fatal("staging file left behind")
			}
		})
	}
}

func TestStagedWrite_FailureLeavesConfigAndRemovesStaging(t *testing.T) {
	content := []byte(strings.Repeat("y", 2*writeChunkSize+7)) // three chunks
	deviceErr := &mqtt.CLIResponse{OK: false, Output: []string{"Failed to open file"}}
	cases := []struct {
		name       string
		hook       func(n int, cmd, arg string) *fakeReply
		wantStatus requestStatus
		wantCalls  string
		wantMsg    string
		landed     bool // the failed chunk reached the device before the reply was lost
	}{
		{"middle chunk device error",
			func(n int, _, _ string) *fakeReply { return when(n == 2, deviceErr, nil) },
			reqStatusError, "fs.write|fs.append|fs.rm", "chunk 2/3 device error", false},
		{"middle chunk short write",
			func(n int, cmd, arg string) *fakeReply {
				return when(n == 2, &mqtt.CLIResponse{OK: true, Output: []string{"Appended 100 bytes to " + arg}}, nil)
			},
			reqStatusError, "fs.write|fs.append|fs.rm", "chunk 2/3 short write", false},
		{"middle chunk transport error",
			func(n int, _, _ string) *fakeReply {
				return when(n == 2, nil, errors.New("broker gone"))
			},
			reqStatusError, "fs.write|fs.append|fs.rm", "chunk 2/3 failed: broker gone", false},
		{"middle chunk timeout",
			func(n int, _, _ string) *fakeReply {
				return when(n == 2, nil, errTimeout)
			},
			reqStatusTimeout, "fs.write|fs.append|fs.rm", "chunk 2/3 timed out", false},
		{"unreadable ack",
			func(n int, _, _ string) *fakeReply {
				return when(n == 3, &mqtt.CLIResponse{OK: true, Output: []string{"ok"}}, nil)
			},
			reqStatusError, "fs.write|fs.append|fs.append|fs.rm", "chunk 3/3 short write", false},
		{"stale ack for another file",
			func(n int, _, _ string) *fakeReply {
				return when(n == 2, okLines("fs.append", "Appended 3900 bytes to /scripts/rules.lua.new"), nil)
			},
			reqStatusError, "fs.write|fs.append|fs.rm", "chunk 2/3 short write", false},
		{"committed size short of the content",
			func(_ int, cmd, _ string) *fakeReply {
				short := len(content) - 100
				return when(cmd == "fs.cat", &mqtt.CLIResponse{OK: true, Total: &short}, nil)
			},
			reqStatusError, "fs.write|fs.append|fs.append|fs.cat|fs.rm", "size check of /config.json.new: device holds 7707 bytes, want 7807", false},
		{"no size in the fs.cat reply",
			func(_ int, cmd, _ string) *fakeReply {
				return when(cmd == "fs.cat", okLines("fs.cat", "yyyy"), nil)
			},
			reqStatusError, "fs.write|fs.append|fs.append|fs.cat|fs.rm", "device holds no size", false},
		{"first chunk timeout still removes staging",
			func(n int, _, _ string) *fakeReply {
				return when(n == 1, nil, errTimeout)
			},
			reqStatusTimeout, "fs.write|fs.rm", "chunk 1/3 timed out", true},
		{"first chunk refused sends nothing more",
			func(n int, _, _ string) *fakeReply { return when(n == 1, deviceErr, nil) },
			reqStatusError, "fs.write", "chunk 1/3 device error", false},
		{"fs.mv reports failure with ok true",
			func(_ int, cmd, _ string) *fakeReply {
				return when(cmd == "fs.mv", &mqtt.CLIResponse{OK: true, Output: []string{"Failed to rename"}}, nil)
			},
			reqStatusError, "fs.write|fs.append|fs.append|fs.cat|fs.mv|fs.rm", "rename /config.json.new to /config.json failed: Failed to rename", false},
		{"fs.mv unknown to the firmware",
			func(_ int, cmd, _ string) *fakeReply {
				return when(cmd == "fs.mv", &mqtt.CLIResponse{OK: false, Output: []string{"Unknown command: fs.mv  (type 'help')"}}, nil)
			},
			reqStatusError, "fs.write|fs.append|fs.append|fs.cat|fs.mv|fs.rm", "rename /config.json.new to /config.json device error", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeFS(map[string]string{"/config.json": oldConfig})
			if tc.landed {
				fs.files["/config.json.new"] = "partial"
			}
			fs.hook = tc.hook
			err := stagedWrite(context.Background(), fs, 50*time.Millisecond, "p", "/config.json", content)
			var f *writeFailure
			if !errors.As(err, &f) {
				t.Fatalf("err = %v, want *writeFailure", err)
			}
			if f.status != tc.wantStatus || !strings.Contains(f.msg, tc.wantMsg) {
				t.Fatalf("failure = %q %q, want %q containing %q", f.status, f.msg, tc.wantStatus, tc.wantMsg)
			}
			if got := strings.Join(cmdNames(fs.calls), "|"); got != tc.wantCalls {
				t.Fatalf("calls = %s, want %s", got, tc.wantCalls)
			}
			if fs.files["/config.json"] != oldConfig {
				t.Fatalf("config.json changed to %d bytes", len(fs.files["/config.json"]))
			}
			if _, left := fs.files["/config.json.new"]; left {
				t.Fatal("staging file left behind")
			}
			if strings.Contains(f.msg, "may remain") {
				t.Fatalf("cleanup reported a leftover: %s", f.msg)
			}
			for _, c := range fs.calls {
				if c == "fs.write /config.json" || c == "fs.append /config.json" {
					t.Fatalf("wrote the live file in place: %q", c)
				}
			}
		})
	}
}

func TestStagedWrite_ReportsStagingLeftWhenRemoveFails(t *testing.T) {
	fs := newFakeFS(map[string]string{"/config.json": oldConfig})
	fs.hook = func(_ int, cmd, _ string) *fakeReply {
		return when(cmd == "fs.mv" || cmd == "fs.rm", nil, errors.New("broker gone"))
	}
	err := stagedWrite(context.Background(), fs, time.Second, "p", "/config.json", []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "/config.json.new may remain on the device") {
		t.Fatalf("err = %v, want the leftover named", err)
	}
	if fs.files["/config.json"] != oldConfig {
		t.Fatal("config.json changed")
	}
}

func TestStagedWrite_RefusesPathsTheShellSplits(t *testing.T) {
	for _, p := range []string{"/my config.json", "/scripts/*.lua", "/a?.lua", "/x\t.lua"} {
		fs := newFakeFS(map[string]string{})
		if err := stagedWrite(context.Background(), fs, time.Second, "p", p, []byte("{}")); err == nil {
			t.Errorf("%q accepted", p)
		}
		if len(fs.calls) != 0 {
			t.Errorf("%q sent %q", p, fs.calls)
		}
	}
}

func TestWriteSteps_CoversChunksSizeCheckRenameAndRemove(t *testing.T) {
	if got := writeSteps(writeChunkSize + 1); got != 6 {
		t.Fatalf("writeSteps = %d, want 2 chunks + fs.cat + fs.mv + readback or fs.rm pair", got)
	}
}

func TestStagedWrite_AcceptsTheFirmwareCutAckForALongPath(t *testing.T) {
	path := "/scripts/" + strings.Repeat("a", 40) + ".lua"
	fs := newFakeFS(map[string]string{})
	content := strings.Repeat("z", writeChunkSize+1)
	if err := stagedWrite(context.Background(), fs, time.Second, "p", path, []byte(content)); err != nil {
		t.Fatalf("stagedWrite: %v (calls %q)", err, fs.calls)
	}
	if fs.files[path] != content {
		t.Fatal("long path not installed")
	}
}

func TestStagedWrite_RefusesSDPaths(t *testing.T) {
	for _, p := range []string{"/sd", "/sd/log042.csv"} {
		fs := newFakeFS(map[string]string{p: "old"})
		err := stagedWrite(context.Background(), fs, time.Second, "p", p, []byte("new"))
		if err == nil || !strings.Contains(err.Error(), "/sd") || len(fs.calls) != 0 {
			t.Errorf("%q: err=%v calls=%q, want a refusal before any command", p, err, fs.calls)
		}
	}
	fs := newFakeFS(map[string]string{})
	if err := stagedWrite(context.Background(), fs, time.Second, "p", "/sdcard.json", []byte("{}")); err != nil {
		t.Errorf("/sdcard.json is on LittleFS, refused: %v", err)
	}
}

func TestClaimDeviceWrite_OneWritePerDevice(t *testing.T) {
	s := &Server{}
	a, b := uuid.New(), uuid.New()
	ta, okA := s.claimDeviceWrite(a, time.Minute)
	_, okB := s.claimDeviceWrite(b, time.Minute)
	if !okA || !okB {
		t.Fatal("first claim refused")
	}
	if _, ok := s.claimDeviceWrite(a, time.Minute); ok {
		t.Fatal("second write to the same device claimed")
	}
	s.releaseDeviceWrite(a, ta)
	if _, ok := s.claimDeviceWrite(a, time.Minute); !ok {
		t.Fatal("claim not released")
	}
}

func TestClaimDeviceWrite_SecondReleaseKeepsTheNextWritesClaim(t *testing.T) {
	s := &Server{}
	dev := uuid.New()
	first, _ := s.claimDeviceWrite(dev, time.Minute)
	s.releaseDeviceWrite(dev, first)
	if _, ok := s.claimDeviceWrite(dev, time.Minute); !ok {
		t.Fatal("next write refused after release")
	}
	s.releaseDeviceWrite(dev, first)
	if _, ok := s.claimDeviceWrite(dev, time.Minute); ok {
		t.Fatal("the first write's deferred release dropped the next write's claim")
	}
}

func TestClaimDeviceWrite_ExpiredClaimIsTakenOver(t *testing.T) {
	s := &Server{}
	dev := uuid.New()
	stale, _ := s.claimDeviceWrite(dev, -time.Second)
	fresh, ok := s.claimDeviceWrite(dev, time.Minute)
	if !ok {
		t.Fatal("a claim past its expiry still blocks the device")
	}
	s.releaseDeviceWrite(dev, stale)
	if _, ok := s.claimDeviceWrite(dev, time.Minute); ok {
		t.Fatal("the stale owner's release dropped the live claim")
	}
	s.releaseDeviceWrite(dev, fresh)
	if _, ok := s.claimDeviceWrite(dev, time.Minute); !ok {
		t.Fatal("live claim not released by its owner")
	}
}

func TestWriteClaimTTL_OutlastsEveryStep(t *testing.T) {
	step := 30 * time.Second
	if got, min := writeClaimTTL(step, 3*writeChunkSize), time.Duration(writeSteps(3*writeChunkSize))*step+snapshotUpsertTimeout; got <= min {
		t.Fatalf("claim ttl %s, want more than the %s the steps can take", got, min)
	}
}

func TestStagedWrite_RefusesAPathTheStagingCopyPushesPastTheFirmwareCap(t *testing.T) {
	fit := "/" + strings.Repeat("a", fwPathCap-1-len(stagedSuffix)-1)
	if err := stagedWrite(context.Background(), newFakeFS(map[string]string{}), time.Second, "p", fit, []byte("{}")); err != nil {
		t.Fatalf("%d-byte path refused: %v", len(fit), err)
	}
	long := fit + "b"
	fs := newFakeFS(map[string]string{})
	err := stagedWrite(context.Background(), fs, time.Second, "p", long, []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "path too long") || len(fs.calls) != 0 {
		t.Fatalf("%d-byte path: err=%v calls=%q, want a refusal before any command", len(long), err, fs.calls)
	}
}

func TestStagedWrite_RenameTimeoutReadsBackTheOutcome(t *testing.T) {
	content := []byte(`{"wifi":{"ssid":"new"}}`)
	cases := []struct {
		name       string
		renamed    bool // the device ran fs.mv, only the reply was lost
		readback   func(n int, cmd, arg string) *fakeReply
		wantErr    string
		wantStatus requestStatus
		wantCalls  string
		wantLive   string
	}{
		{"rename landed", true, nil, "", "",
			"fs.write|fs.cat|fs.mv|fs.cat|fs.cat", string(content)},
		{"rename never ran", false, nil, "timed out", reqStatusTimeout,
			"fs.write|fs.cat|fs.mv|fs.cat|fs.rm", oldConfig},
		{"readback lost too", true,
			func(n int, cmd, _ string) *fakeReply { return when(n == 4, nil, errTimeout) },
			"rename outcome is unknown", reqStatusTimeout,
			"fs.write|fs.cat|fs.mv|fs.cat", string(content)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeFS(map[string]string{"/config.json": oldConfig})
			fs.hook = func(n int, cmd, arg string) *fakeReply {
				if cmd == "fs.mv" {
					if tc.renamed {
						fs.files["/config.json"] = fs.files["/config.json.new"]
						delete(fs.files, "/config.json.new")
					}
					return &fakeReply{nil, errTimeout}
				}
				if tc.readback != nil {
					return tc.readback(n, cmd, arg)
				}
				return nil
			}
			err := stagedWrite(context.Background(), fs, 50*time.Millisecond, "p", "/config.json", content)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("stagedWrite = %v, want success read back", err)
				}
			} else {
				var f *writeFailure
				if !errors.As(err, &f) || f.status != tc.wantStatus || !strings.Contains(f.msg, tc.wantErr) {
					t.Fatalf("err = %v, want %s containing %q", err, tc.wantStatus, tc.wantErr)
				}
			}
			if got := strings.Join(cmdNames(fs.calls), "|"); got != tc.wantCalls {
				t.Fatalf("calls = %s, want %s", got, tc.wantCalls)
			}
			if fs.files["/config.json"] != tc.wantLive {
				t.Fatalf("config.json = %q, want %q", fs.files["/config.json"], tc.wantLive)
			}
		})
	}
}
