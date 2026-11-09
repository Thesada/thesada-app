package web

import (
	"mime"
	"net/http"
)

// maxFormBody caps a form-encoded or multipart request body.
const maxFormBody = 64 << 10

// limitFormBody caps form bodies before anything parses them, the CSRF check
// included. JSON endpoints keep their own caps.
// in: next handler. out: wrapped handler.
func limitFormBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same parser as ParseForm, so any type it reads as a form is capped,
		// and a type it cannot read is capped too.
		if ct := r.Header.Get("Content-Type"); ct != "" {
			mt, _, err := mime.ParseMediaType(ct)
			if err != nil || mt == "application/x-www-form-urlencoded" || mt == "multipart/form-data" {
				r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
			}
		}
		next.ServeHTTP(w, r)
	})
}
