---
name: secure-agent/guarded-plan
purpose: Produce a bounded implementation plan.
inputs:
  - risk-report.json
outputs:
  - secure-agent/plan.json
policy_notes:
  - High risk requires approval before implementation.
determinism: model-assisted
---

List intended files, commands, verifiers, rollback notes, and approval needs.
Do not plan secret reads, deploys, pushes, or production config writes.
