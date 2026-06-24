## Summary

<!-- What changed and why, in 1-3 bullets. -->

## Test plan

- [ ] Tests added for the new contract (not just a bug repro)
- [ ] Existing suite passes

## Security

- [ ] Security review checklist run
- [ ] Threat model updated if this PR introduces a new attack surface
- [ ] Structured logging at new state transitions (dotted `subsystem.action`; `state_change` on security edges)
- [ ] No secrets in the diff; config read via the secrets wrapper / env
