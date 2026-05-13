---
name: secure-agent/security-review
purpose: Review outputs before closure.
inputs:
  - changed-files.json
  - verifier-results.json
outputs:
  - secure-agent/security-review.json
policy_notes:
  - Verify no protected files, blocked commands, or secrets were touched.
determinism: deterministic
---

Check changed files, command audit, secret scan, policy decisions, and verifier
results. Fail closed if evidence is incomplete.
