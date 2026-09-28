# cycle_139 / T4 — TRIAGE Summary

**Triage captured**: 2026-09-28T11:19:54.073210+00:00

**Total findings**: 5

| Severity | Count |
|---|---|
| critical | 0 |
| high | 2 |
| medium | 2 |
| low | 1 |
| info | 0 |

## Findings

| ID | VULN_AUDIT | Severity | Surface | Title |
|---|---|---|---|---|
| F-001-V009 | V009 | low | compute | compute_thumbprint(mixed-type dict) raised TypeError; SPEC promises ValueError |
| F-002-V007 | V007 | medium | compute | compute_thumbprint(RSA missing 'e') silently produced thumbprint; RFC 7638 §3.2 requires raising |
| F-003-V002 | V002 | high | verify | verify(depth=470) leaked RecursionError; verify() must catch and return False (DoS surface) |
| F-004-V002-mutated | V002 | high | verify | verify(depth=350) leaked RecursionError (mutated-from-V002 repro) |
| F-005-V010 | V010 | medium | canonical | canonical_json({True: 1}) produced '{true:1}' (unquoted key) — invalid JSON output |

## Methodology

Each crash file in `cycle_139/adversary/fuzz/crashes/<surface>/` was
replayed through the harness that produced it.  The harness `TestOneInput`
function raises `AssertionError` with a header line `"V### REPRODUCED: ..."`
when it detects the corresponding VULN_AUDIT finding.  Each crash's
AssertionError text was used to map it to the finding ID, and the captured
traceback was preserved in `stacktrace.txt`.

For each finding, a standalone `minimized.py` reproducer was authored that
exercises the same code path against the editable-installed package without
the harness.  The reproducer is intended to be used by:
- T5 (FUZZING_REPORT.md) for the per-finding narrative
- The builder in the remediation cycle, to confirm the fix and add a
  regression test
- Future fuzzing runs as a permanent oracle

Each finding folder also contains `minimized.bin` (the original
libFuzzer-minimized bytes) and `metadata.json` (structured machine-readable
data).

## Zero high-severity unanalyzed

**Zero high-severity unanalyzed findings** (2 High-severity total, each minimized + classified + root-caused):
- **F-003-V002** (V002): verify(depth=470) leaked RecursionError; verify() must catch and return False (DoS surface)
- **F-004-V002-mutated** (V002): verify(depth=350) leaked RecursionError (mutated-from-V002 repro)
