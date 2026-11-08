package web

import (
	"net/http"
	"strings"
)

// maxFormBody caps a form-encoded or multipart request body.
const maxFormBody = 64 << 10

// limitFormBody caps form bodies before anything parses them, the CSRF check
// included. JSON endpoints keep their own caps.
// in: next handler. out: wrapped handler.
func limitFormBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/form-data") {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
		}
		next.ServeHTTP(w, r)
	})
}
