package mqtt

import "testing"

// A device that answers not done with no length must end the pull, not ask
// for the same offset again forever.
func TestNextChunk_StopsWithoutProgress(t *testing.T) {
	yes, no := true, false
	zero, neg, n := 0, -1, 2048
	cases := []struct {
		name     string
		resp     CLIResponse
		wantNext int
		wantMore bool
		wantErr  bool
	}{
		{"done", CLIResponse{Done: &yes, Length: &n}, 0, false, false},
		{"progress", CLIResponse{Done: &no, Length: &n}, 2048, true, false},
		{"zero length", CLIResponse{Done: &no, Length: &zero}, 0, false, true},
		{"negative length", CLIResponse{Done: &no, Length: &neg}, 0, false, true},
		{"no length", CLIResponse{Done: &no}, 0, false, false},
	}
	for _, tc := range cases {
		next, more, err := nextChunk(0, &tc.resp)
		if (err != nil) != tc.wantErr || more != tc.wantMore || (tc.wantMore && next != tc.wantNext) {
			t.Errorf("%s: next=%d more=%v err=%v", tc.name, next, more, err)
		}
	}
}
