# F-002-V007 — compute_thumbprint(RSA missing 'e') silently produced thumbprint; RFC 7638 §3.2 requires raising

- **Severity**: medium
- **Surface**: compute
- **VULN_AUDIT ID**: V007
- **Crash file**: `cycle_139/adversary/fuzz/crashes/compute/crash-f8407e180bd92589b728af21c5626c18770cf26b`
- **Crash bytes**: `b9` (1 byte(s))
- **Harness category**: 5 (V007 reproducer: recognized kty missing required member)
- **Triage captured**: 2026-09-28T11:19:54.073210+00:00

## What surfaces

```
V007 REPRODUCED: compute_thumbprint({'kty': 'RSA', 'n': 'abc'}) on missing-required member kty='RSA' SILENTLY produced a thumbprint — RFC 7638 §3.2 requires the call to raise
```

## Stack trace (captured by harness replay)

```
Traceback (most recent call last):
  File "/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01/cycle_139/adversary/fuzz/_build_findings.py", line 301, in <module>
    h.TestOneInput(data)
  File "/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01/cycle_139/adversary/fuzz/harness_compute.py", line 214, in TestOneInput
    raise AssertionError(
AssertionError: V007 REPRODUCED: compute_thumbprint({'kty': 'RSA', 'n': 'abc'}) on missing-required member kty='RSA' SILENTLY produced a thumbprint — RFC 7638 §3.2 requires the call to raise
```

## Suggested fix

Define MISSING_REQUIRED_MEMBERS(ValueError); raise in filter loop when a recognized kty is missing a required member.

## Standalone reproducer

See `minimized.py` — runs against the editable-installed package and exercises the same code path without the harness.
