# F-003-V002 — verify(depth=470) leaked RecursionError; verify() must catch and return False (DoS surface)

- **Severity**: high
- **Surface**: verify
- **VULN_AUDIT ID**: V002
- **Crash file**: `cycle_139/adversary/fuzz/crashes/verify/crash-6b9a758c8e74dc63f8539965eaf962f7e9d31c2e`
- **Crash bytes**: `417801` (3 byte(s))
- **Harness category**: 1 (V002 reproducer: deeply-nested JWK)
- **Depth**: 470
- **Triage captured**: 2026-09-28T11:19:54.073210+00:00

## What surfaces

```
V002 REPRODUCED: verify(depth=470) leaked RecursionError (RecursionError('maximum recursion depth exceeded in __instancecheck__')) — verify() must catch RecursionError and return False (DoS surface)
```

## Stack trace (captured by harness replay)

```
Traceback (most recent call last):
  File "/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01/cycle_139/adversary/fuzz/harness_verify.py", line 135, in TestOneInput
    ok = verify(jwk, "any")
         ^^^^^^^^^^^^^^^^^^
  File "/root/projects/jwk-thumbprint-pure/src/jwk_thumbprint_pure/thumbprint.py", line 126, in verify
    actual = thumbprint(jwk, alg)
             ^^^^^^^^^^^^^^^^^^^^
  File "/root/projects/jwk-thumbprint-pure/src/jwk_thumbprint_pure/thumbprint.py", line 94, in thumbprint
  ... [truncated, 1999 lines omitted] ...
The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01/cycle_139/adversary/fuzz/_build_findings.py", line 301, in <module>
    h.TestOneInput(data)
  File "/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01/cycle_139/adversary/fuzz/harness_verify.py", line 137, in TestOneInput
    raise AssertionError(
AssertionError: V002 REPRODUCED: verify(depth=470) leaked RecursionError (RecursionError('maximum recursion depth exceeded in __instancecheck__')) — verify() must catch RecursionError and return False (DoS surface)
```

## Suggested fix

Broaden verify()'s except tuple to include (RecursionError, MemoryError); or wrap entire verify() body in try/except Exception: return False.

## Standalone reproducer

See `minimized.py` — runs against the editable-installed package and exercises the same code path without the harness.
