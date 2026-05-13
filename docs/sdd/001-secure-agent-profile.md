# Secure Agent Profile SDD Implementation Note

Source SDD:
`${AO_STRATEGY_REPO}/secure-agent-profile-sdd.md`

This repository implements the standalone Secure Agent Profile product artifact.
The v0.1 implementation covers:

- profile contracts under `profiles/secure-agent/`;
- fail-closed policy overlay in `policy/secure-agent.policy.yaml`;
- deterministic command, file-scope, secret, and risk classifiers;
- safe and unsafe fixtures;
- three workflows: guarded code change, dependency review, PR evidence;
- AO RunSpec materialization;
- local execution and AO Runtime execution path;
- signed `.tar.zst` evidence packs;
- verify and replay commands;
- tests for allowed and blocked behavior.

The implementation intentionally does not apply patches to the source repo,
does not deploy, does not push, and does not read secret files.
