---
schema: ao-operator/secure-agent-brief/v1
task_id: secure-agent-demo-001
title: Add input validation to math utility
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
  - Add validation for divide-by-zero
  - Add tests
verifiers:
  - command: python -m pytest tests/test_math_utils.py
    class: test
---

## Background

The helper function currently fails with a raw ZeroDivisionError.

## Requested Change

Return a clear ValueError when denominator is zero.
