package mqtt

import "testing"

// A device that answers not done with no length must end the pull, not ask
// for the same offset again forever.
func TestNextChunk_StopsWithoutProgress(t *testing.T) {
	yes, no := true, false
	zero, neg, n, at := 0, -1, 2048, 4096
	cases := []struct {
		name     string
		resp     CLIResponse
		wantNext int
		wantMore bool
		wantErr  bool
	}{
		{"done", CLIResponse{Offset: &at, Done: &yes, Length: &n}, 0, false, false},
		{"progress", CLIResponse{Offset: &at, Done: &no, Length: &n}, 6144, true, false},
		{"zero length", CLIResponse{Offset: &at, Done: &no, Length: &zero}, 0, false, true},
		{"negative length", CLIResponse{Offset: &at, Done: &no, Length: &neg}, 0, false, true},
		{"no length", CLIResponse{Offset: &at, Done: &no}, 0, false, false},
	}
	for _, tc := range cases {
		next, more, err := nextChunk(at, &tc.resp)
		if (err != nil) != tc.wantErr || more != tc.wantMore || (tc.wantMore && next != tc.wantNext) {
			t.Errorf("%s: next=%d more=%v err=%v", tc.name, next, more, err)
		}
	}
}

// A late reply to an earlier chunk, or one that names no offset, cannot be
// tied to this request, so its data must not join the read.
func TestNextChunk_RefusesAReplyForAnotherOffset(t *testing.T) {
	yes, no := true, false
	n, earlier := 2048, 2048
	cases := []struct {
		name string
		resp CLIResponse
	}{
		{"earlier offset", CLIResponse{Offset: &earlier, Done: &no, Length: &n}},
		{"earlier offset done", CLIResponse{Offset: &earlier, Done: &yes, Length: &n}},
		{"no offset", CLIResponse{Done: &no, Length: &n}},
		{"no offset done", CLIResponse{Done: &yes, Length: &n}},
	}
	for _, tc := range cases {
		if _, more, err := nextChunk(4096, &tc.resp); err == nil || more {
			t.Errorf("%s: more=%v err=%v, want an error", tc.name, more, err)
		}
	}
}
