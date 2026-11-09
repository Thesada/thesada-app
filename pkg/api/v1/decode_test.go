package v1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// decodeJSON reads a small body and refuses one past maxJSONBody with 413.
func TestDecodeJSON_CapsBody(t *testing.T) {
	for _, c := range []struct {
		name string
		body string
		ok   bool
		code int
	}{
		{"small", `{"email":"a@b.c"}`, true, http.StatusOK},
		{"too large", `{"email":"` + strings.Repeat("a", maxJSONBody) + `"}`, false, http.StatusRequestEntityTooLarge},
		{"malformed", `{`, false, http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		var dst struct{ Email string }
		ok := decodeJSON(rec, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(c.body)), &dst)
		if ok != c.ok || rec.Code != c.code {
			t.Errorf("%s: ok=%v code=%d, want ok=%v code=%d", c.name, ok, rec.Code, c.ok, c.code)
		}
	}
}
