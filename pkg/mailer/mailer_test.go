package mailer

import "testing"

// TestSanitizeHeader verifies CR/LF are stripped so a hostile recipient or
// subject cannot inject additional headers or a message body.
func TestSanitizeHeader(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "user@example.com", "user@example.com"},
		{"subject", "Your device alert", "Your device alert"},
		{"crlf header inject", "user@example.com\r\nBcc: victim@example.com", "user@example.comBcc: victim@example.com"},
		{"lf only", "Subject line\ninjected", "Subject lineinjected"},
		{"cr only", "a\rb", "ab"},
		{"body inject", "subj\r\n\r\nfake body", "subjfake body"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeHeader(c.in); got != c.want {
				t.Errorf("sanitizeHeader(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
