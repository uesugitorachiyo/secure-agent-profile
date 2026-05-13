---
name: secure-agent/implementation
purpose: Apply a guarded code change inside an isolated workspace.
inputs:
  - plan.json
outputs:
  - secure-agent/patch.diff
policy_notes:
  - Every write and shell command must have an allow decision first.
determinism: model-assisted
---

Produce patch artifacts only. Do not apply changes to the source repository in
v1. Stop on approval-required or blocked decisions.
