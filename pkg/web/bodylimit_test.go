package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A form body past maxFormBody fails to parse. A small one and a JSON body
// pass through untouched.
func TestLimitFormBody(t *testing.T) {
	var parseErr error
	var read int
	h := limitFormBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			b, _ := io.ReadAll(r.Body)
			read = len(b)
			return
		}
		parseErr = r.ParseForm()
	}))
	post := func(ct, body string) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	post("application/x-www-form-urlencoded", url.Values{"email": {"a@b.c"}}.Encode())
	if parseErr != nil {
		t.Fatalf("small form: %v", parseErr)
	}
	post("application/x-www-form-urlencoded; charset=UTF-8", url.Values{"note": {strings.Repeat("a", maxFormBody)}}.Encode())
	if parseErr == nil {
		t.Fatal("form past the cap parsed")
	}
	big := strings.Repeat("a", maxFormBody+1)
	post("application/json", big)
	if read != len(big) {
		t.Fatalf("json body read %d bytes, want %d untouched", read, len(big))
	}
}
