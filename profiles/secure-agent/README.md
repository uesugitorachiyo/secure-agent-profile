# Secure Agent Profiles

These AO Operator profile contracts define policy-gated coding-agent workflows
for AO Runtime:

- `secure-agent:guarded-code-change`
- `secure-agent:dependency-review`
- `secure-agent:pr-evidence`

The runnable standalone implementation is the `sap` CLI in this repository.
It always works in an isolated workspace and emits signed replayable evidence
packs.
