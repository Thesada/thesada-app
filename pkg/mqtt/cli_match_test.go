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
