# F-005-V010 — canonical_json({True: 1}) produced '{true:1}' (unquoted key) — invalid JSON output

- **Severity**: medium
- **Surface**: canonical
- **VULN_AUDIT ID**: V010
- **Crash file**: `cycle_139/adversary/fuzz/crashes/canonical/crash-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc`
- **Crash bytes**: `0a` (1 byte(s))
- **Harness category**: 10 (V010 reproducer: bool as dict key)
- **Triage captured**: 2026-09-28T11:19:54.073210+00:00

## What surfaces

```
V010 REPRODUCED: canonical_json({True: 1}) = '{true:1}' contains an unquoted identifier as a key — invalid JSON (SPEC promises valid JSON output)
```

## Stack trace (captured by harness replay)

```
Traceback (most recent call last):
  File "/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01/cycle_139/adversary/fuzz/_build_findings.py", line 301, in <module>
    h.TestOneInput(data)
  File "/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01/cycle_139/adversary/fuzz/harness_canonical.py", line 214, in TestOneInput
    raise AssertionError(
AssertionError: V010 REPRODUCED: canonical_json({True: 1}) = '{true:1}' contains an unquoted identifier as a key — invalid JSON (SPEC promises valid JSON output)
```

## Suggested fix

Reject bool keys before recursion, OR coerce keys to strings (true -> 'true'), OR raise TypeError on non-str keys.

## Standalone reproducer

See `minimized.py` — runs against the editable-installed package and exercises the same code path without the harness.
