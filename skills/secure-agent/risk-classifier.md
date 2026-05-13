---
name: secure-agent/risk-classifier
purpose: Classify file, command, network, and secret risk.
inputs:
  - repo-scan.json
  - task brief
outputs:
  - secure-agent/risk-report.json
policy_notes:
  - Deterministic classifier output is source of truth.
determinism: deterministic
---

Emit low, medium, high, or blocked risk. Never downgrade secret, deploy, remote
write, or destructive command findings.
