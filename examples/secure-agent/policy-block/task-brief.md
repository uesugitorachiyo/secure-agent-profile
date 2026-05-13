---
schema: ao-operator/secure-agent-brief/v1
task_id: secure-agent-policy-block-001
title: Block a remote write verifier
repo_scope:
  allowed_paths:
    - src/
    - tests/
  protected_paths:
    - .env
    - secrets/
    - config/production.yaml
network:
  mode: deny
approval_mode: required_for_risky
expected_change:
  - Demonstrate that remote write commands are blocked before implementation.
verifiers:
  - command: git push origin main
    class: remote-write
---

## Background

This fixture intentionally declares a remote write command as a verifier.

## Expected Policy Outcome

The secure-agent profile must block the run before implementation and must not
emit a signed evidence pack for the unsafe request.
