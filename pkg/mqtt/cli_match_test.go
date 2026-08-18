// Unit tests for cliMatchesRequest - the CLI reply correlation guard.
// Pure logic over an in-memory byte slice and strings; no broker / DB.
package mqtt

import (
	"testing"
)

func TestCliMatchesRequest(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		reqID   string
		cmd     string
		want    bool
	}{
		{
			name:    "matching req_id",
			payload: []byte(`{"req_id":"req-123","cmd":"version","ok":true}`),
			reqID:   "req-123",
			cmd:     "version",
			want:    true,
		},
		{
			name:    "mismatched req_id",
			payload: []byte(`{"req_id":"req-123","cmd":"version","ok":true}`),
			reqID:   "req-456",
			cmd:     "version",
			want:    false,
		},
		{
			name:    "invalid json matches on purpose",
			payload: []byte(`raw binary or plain text reply`),
			reqID:   "req-123",
			cmd:     "version",
			want:    true,
		},
		{
			name:    "no req_id on either side, cmd matches",
			payload: []byte(`{"cmd":"version","ok":true}`),
			reqID:   "",
			cmd:     "version",
			want:    true,
		},
		{
			name:    "no req_id on either side, cmd differs",
			payload: []byte(`{"cmd":"version","ok":true}`),
			reqID:   "",
			cmd:     "fs.ls",
			want:    false,
		},
		{
			name:    "no req_id on either side, cmd absent entirely",
			payload: []byte(`{"ok":true}`),
			reqID:   "",
			cmd:     "fs.ls",
			want:    true,
		},
		// Caller has no id but the payload does: correlation falls back to
		// the command name rather than dropping the reply.
		{
			name:    "payload carries req_id, caller has none",
			payload: []byte(`{"req_id":"req-123","cmd":"version"}`),
			reqID:   "",
			cmd:     "version",
			want:    true,
		},
		{
			name:    "payload carries req_id, caller has none, cmd differs",
			payload: []byte(`{"req_id":"req-123","cmd":"version"}`),
			reqID:   "",
			cmd:     "fs.ls",
			want:    false,
		},
		// Same answer, different routes: empty fails to unmarshal and takes
		// the raw path, null parses into a zero probe and takes the cmd path.
		{
			name:    "empty payload",
			payload: []byte(``),
			reqID:   "req-123",
			cmd:     "version",
			want:    true,
		},
		{
			name:    "literal json null",
			payload: []byte(`null`),
			reqID:   "req-123",
			cmd:     "version",
			want:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cliMatchesRequest(tc.payload, tc.reqID, tc.cmd)
			if got != tc.want {
				t.Fatalf("cliMatchesRequest(%q, %q, %q) = %v, want %v",
					string(tc.payload), tc.reqID, tc.cmd, got, tc.want)
			}
		})
	}
}
