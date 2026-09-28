# F-004-V002-mutated — verify(depth=350) leaked RecursionError (mutated-from-V002 repro)

- **Severity**: high
- **Surface**: verify
- **VULN_AUDIT ID**: V002
- **Crash file**: `cycle_139/adversary/fuzz/crashes/verify/crash-b753d636f6ee46bb9242d01ff8b61f715e9a88c3`
- **Crash bytes**: `e1` (1 byte(s))
- **Harness category**: 1 (V002 reproducer: deeply-nested JWK (mutated input))
- **Depth**: 350
- **Triage captured**: 2026-09-28T11:19:54.073210+00:00

## What surfaces

```
V002 REPRODUCED: verify(depth=350) leaked RecursionError (RecursionError('maximum recursion depth exceeded in __instancecheck__')) — verify() must catch RecursionError and return False (DoS surface)
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
AssertionError: V002 REPRODUCED: verify(depth=350) leaked RecursionError (RecursionError('maximum recursion depth exceeded in __instancecheck__')) — verify() must catch RecursionError and return False (DoS surface)
```

## Suggested fix

Same fix as F-003. This is a mutated reproducer confirming the V002 finding is robust across multiple depth values.

## Standalone reproducer

See `minimized.py` — runs against the editable-installed package and exercises the same code path without the harness.
