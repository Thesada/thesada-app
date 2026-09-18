// Public unauthenticated build metadata for operators and tooling.
// SPDX-License-Identifier: AGPL-3.0-only
package v1

import (
	"net/http"
	"strings"

	"thesada.app/app/pkg/buildinfo"
)

// stripReleaseTagPrefix drops a leading "v" from release tags (v26.09.1 ->
// 26.09.1). Unreleased builds stay as-is ("dev").
func stripReleaseTagPrefix(v string) string {
	return strings.TrimPrefix(v, "v")
}

// handleVersion is unauthenticated and read-only.
// in: writer, request. out: 200 {"version","commit","build_time"}.
func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version":    stripReleaseTagPrefix(buildinfo.Version),
		"commit":     buildinfo.Commit,
		"build_time": buildinfo.BuildTime,
	})
}
