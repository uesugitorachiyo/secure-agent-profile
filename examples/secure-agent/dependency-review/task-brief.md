---
schema: ao-operator/secure-agent-brief/v1
task_id: secure-agent-deps-001
title: Review dependency manifests
repo_scope:
  allowed_paths:
    - ./
  protected_paths:
    - .env
    - secrets/
network:
  mode: deny
verifiers: []
---

Review dependency manifests without installing packages.
