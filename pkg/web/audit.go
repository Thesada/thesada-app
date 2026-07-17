// Best-effort audit shim between admin handlers and the durable
// AuditService trail. Handlers call s.audit AFTER the mutation succeeds;
// a failed audit write must never undo or fail the action the operator
// already saw succeed, so the error is logged loud and swallowed here.
// (The impersonation edges are the exception: they are recorded inside
// the mutation's own tx in pkg/service/auth_sessions.go.)
package web

import (
	"context"
	"log/slog"

	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/service"
)

// audit records one privileged mutation, filling the actor from the
// resolved user. Best-effort: failure logs audit.record_failed and returns.
// in: ctx (request ctx, or a fresh one on post-request paths), actor
// (nil tolerated), action, partially-filled entry. out: none.
func (s *Server) audit(ctx context.Context, actor *service.User, action authz.Action, e service.AuditEntry) {
	e.Action = string(action)
	if actor != nil {
		id := actor.ID
		e.ActorUserID = &id
		e.ActorEmail = actor.Email
	}
	if err := s.services.Audit.Record(ctx, e); err != nil {
		slog.Error("audit.record_failed", "action", e.Action,
			"target_type", e.TargetType, "target", e.TargetID, "err", err)
	}
}
