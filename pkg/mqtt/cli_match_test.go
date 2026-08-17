package mqtt

import "testing"

func TestCliMatchesRequest(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		reqID   string
		command string
		want    bool
	}{
		{"matching request ID", `{"req_id":"req-1","cmd":"version"}`, "req-1", "version", true},
		{"different request ID", `{"req_id":"req-old","cmd":"version"}`, "req-new", "version", false},
		{"unparseable payload", `not-json`, "req-1", "version", true},
		{"matching command without request IDs", `{"cmd":"fs.cat"}`, "", "fs.cat", true},
		{"different command without request IDs", `{"cmd":"fs.ls"}`, "", "fs.cat", false},
		{"missing command without request IDs", `{"ok":true}`, "", "fs.cat", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cliMatchesRequest([]byte(tt.payload), tt.reqID, tt.command)
			if got != tt.want {
				t.Fatalf("cliMatchesRequest(%q, %q, %q) = %v, want %v", tt.payload, tt.reqID, tt.command, got, tt.want)
			}
		})
	}
}
