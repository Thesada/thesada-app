package mqtt

import (
	"testing"
	"unicode/utf8"
)

func TestTruncForLog(t *testing.T) {
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"shorter", "hello", 10, "hello"},
		{"exact", "hello", 5, "hello"},
		{"one_over", "hello!", 5, "hello..."},
		{"empty", "", 5, ""},
		{"empty_zero", "", 0, ""},
		{"zero_n", "hello", 0, "..."},
		{"negative_n", "hello", -1, "..."},
		{"utf8_degree", "temp 12°C", 8, "temp 12..."},
		{"utf8_umlaut", "Geräte", 4, "Ger..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncForLog(tt.in, tt.n)
			if !utf8.ValidString(got) {
				t.Fatalf("invalid utf8: %q", got)
			}
			if got != tt.want {
				t.Fatalf("truncForLog(%q, %d)=%q want %q", tt.in, tt.n, got, tt.want)
			}
		})
	}
}
