---
name: secure-agent/intake
purpose: Convert a task brief into structured secure-agent input.
inputs:
  - task brief
outputs:
  - secure-agent/intake.json
policy_notes:
  - Do not invent approval.
determinism: deterministic
---

Extract requested change, allowed paths, protected paths, network policy, and
declared verifiers. Block when required front matter is missing.
