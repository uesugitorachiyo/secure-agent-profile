---
schema: ao-operator/secure-agent-brief/v1
task_id: secure-agent-pr-001
title: Produce PR evidence pack
repo_scope:
  allowed_paths:
    - src/
    - tests/
  protected_paths:
    - .env
    - secrets/
network:
  mode: deny
verifiers: []
---

Produce a read-only evidence pack for an existing patch.
