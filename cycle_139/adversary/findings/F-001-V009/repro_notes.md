# F-001-V009 — compute_thumbprint(mixed-type dict) raised TypeError; SPEC promises ValueError

- **Severity**: low
- **Surface**: compute
- **VULN_AUDIT ID**: V009
- **Crash file**: `cycle_139/adversary/fuzz/crashes/compute/crash-1e5c2f367f02e47a8c160cda1cd9d91decbac441`
- **Crash bytes**: `5b` (1 byte(s))
- **Harness category**: 7 (V009 reproducer: mixed-type dict keys)
- **Triage captured**: 2026-09-28T11:19:54.073210+00:00

## What surfaces

```
V009 REPRODUCED: compute_thumbprint(mixed-type dict) raised TypeError (TypeError("'<' not supported between instances of 'int' and 'str'")) — SPEC promises ValueError
```

## Stack trace (captured by harness replay)

```
Traceback (most recent call last):
  File "/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01/cycle_139/adversary/fuzz/harness_compute.py", line 250, in TestOneInput
    compute_thumbprint(jwk)
  File "/root/projects/jwk-thumbprint-pure/src/jwk_thumbprint_pure/thumbprint.py", line 94, in thumbprint
    canon = canonical_json(filtered)
            ^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/projects/jwk-thumbprint-pure/src/jwk_thumbprint_pure/canonical.py", line 76, in canonical_json
    items = sorted(obj.items(), key=lambda kv: kv[0])
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
TypeError: '<' not supported between instances of 'int' and 'str'

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01/cycle_139/adversary/fuzz/_build_findings.py", line 301, in <module>
    h.TestOneInput(data)
  File "/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01/cycle_139/adversary/fuzz/harness_compute.py", line 255, in TestOneInput
    raise AssertionError(
AssertionError: V009 REPRODUCED: compute_thumbprint(mixed-type dict) raised TypeError (TypeError("'<' not supported between instances of 'int' and 'str'")) — SPEC promises ValueError
```

## Suggested fix

Catch TypeError at thumbprint()/canonical_json() and re-raise as ValueError, OR guard against non-str keys before canonical_json.

## Standalone reproducer

See `minimized.py` — runs against the editable-installed package and exercises the same code path without the harness.
