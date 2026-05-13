---
name: secure-agent/closure
purpose: Produce final closure for the secure-agent run.
inputs:
  - security-review.json
outputs:
  - secure-agent/closure.json
policy_notes:
  - Closure fails if evidence, policy, verifier, or replay metadata is missing.
determinism: deterministic
---

Summarize status, changed files, verifiers, policy counts, and evidence pack
location.
