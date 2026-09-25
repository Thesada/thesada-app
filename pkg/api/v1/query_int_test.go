package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryInt(t *testing.T) {
	const def, max = 20, 100
	tests := []struct {
		name  string
		query string
		want  int
	}{
		{"absent", "", def},
		{"empty", "limit=", def},
		{"unparseable", "limit=abc", def},
		{"zero", "limit=0", def},
		{"negative", "limit=-5", def},
		{"above max", "limit=250", max},
		{"in range", "limit=50", 50},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/?"+tt.query, nil)
			if got := queryInt(r, "limit", def, max); got != tt.want {
				t.Errorf("queryInt() = %d, want %d", got, tt.want)
			}
		})
	}
}
