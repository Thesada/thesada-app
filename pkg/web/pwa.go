package web

import (
	"io/fs"
	"net/http"
)

// handleServiceWorker serves the app-shell worker from the site root so
// its default scope is the whole origin, not /static/.
func (s *Server) handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	body, err := fs.ReadFile(staticFS, "static/sw.js")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Service-Worker-Allowed", "/")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(body)
}
