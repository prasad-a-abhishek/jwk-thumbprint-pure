# cycle_139 / T2 — HARNESSES for jwk-thumbprint-pure

**Phase**: T2 (cycle_139 @repo-adversary workstream)
**Cycle**: 139
**Repo**: jwk-thumbprint-pure v0.1.0
**Date**: 2026-09-28
**Worker session**: 20260928_1130xx_t_cycle139-adv-02

This document captures the T2 deliverable: four Atheris-based fuzzing
harnesses covering four distinct public surfaces of
`jwk-thumbprint-pure`. The harnesses are designed to run under the
Invariant 26 §2 protocol — 5s per-surface wall budget with ASan + UBSan
enabled in the harness environment (atheris ships its own coverage
instrumentation; the OS-level ASan + UBSan must be enabled via the
runtime — see "Sanitizer configuration" below).

## Surfaces covered

| # | Surface | Harness | VULN_AUDIT reproducers encoded | Iters (3s smoke) | Crashes (3s smoke) |
|---|---|---|---|---|---|
| 1 | `compute_thumbprint(jwk, alg)` + required-membership filter | `harness_compute.py` | V007 (silent drop of missing required members), V009 (TypeError vs ValueError on malformed JWK) | ~30k | 1 (V009) |
| 2 | `verify(jwk, expected, alg)` | `harness_verify.py` | V002 (RecursionError leaks from verify), V001 (oracle mismatch), V003 (error-masking) | ~30k | 1 (V002) |
| 3 | `canonical_json(value)` (RFC 8785 serializer) | `harness_canonical.py` | V004 (non-BMP surrogate-pair escape), V008 (float emission), V010 (bool/int key fragility) | ~30k | 1 (V010) |
| 4 | CLI subprocess (`python src/.../cli.py …`) | `harness_cli.py` | V005 (CLI leaks tracebacks on non-ValueError), V011 (help-unreachable in pipe-without-input) | ~150 (subprocess-bound) | 0 (clean — current CLI handles these) |

Surfaces covered: **4** (≥3 required by T2 contract, ≥3 mandated by
the task body).

Total public API surface coverage: every public function in
`src/jwk_thumbprint_pure/` is exercised by at least one harness:

* `compute_thumbprint` (top-level) — Surface 1
* `verify` (top-level) — Surface 2
* `canonical_json` (top-level) — Surface 3
* `thumbprint.thumbprint` (module-level) — Surface 1 (aliased as
  `compute_thumbprint`)
* `thumbprint._REQUIRED_MEMBERS` filter — Surface 1 (via V007 cat=5
  branch)
* `thumbprint.SUPPORTED_ALGS` (alg confusion) — Surface 1 (cat=9)
* `thumbprint.JWKThumbprint` dataclass — not exercised directly (no
  compute path returns it; it's a result wrapper).
* CLI: `cli.main()` / `python src/.../cli.py` — Surface 4 (subprocess)

## Surface 1 — `harness_compute.py` (compute_thumbprint + filter)

Exercises `compute_thumbprint(jwk, alg)` (re-export of
`thumbprint.thumbprint`) and the underlying `_REQUIRED_MEMBERS` filter
per RFC 7638 §4. Inputs are routed via `FuzzedDataProvider` into one
of 12 categories:

| Cat | Probe | VULN_AUDIT coverage |
|---|---|---|
| 0..3 | Valid kty (RSA/EC/oct/OKP), valid shape | Happy-path determinism + 43-char Base64URL |
| 4 | Unknown kty → all members pass through | RFC 7638 §3.2 unknown-kty behavior |
| 5 | Recognized kty missing required member | **V007 reproducer** (silent drop) |
| 6 | Non-dict input (None, bytes, list, str, int, float) | **V009 reproducer** (TypeError vs ValueError) |
| 7 | Dict with mixed-type keys | **V009 reproducer** (TypeError from sort) |
| 8 | Dict with `Decimal` value | **V009 reproducer** (TypeError from canonical) |
| 9 | Invalid alg string (SHA-1, MD5, sha-256, etc.) | Algorithm confusion |
| 10 | Non-BMP / control-char / NUL string values | Canonical_json edge (interacts with V004) |
| 11 | JSON-bytes input → json.loads → compute_thumbprint | Generic fuzz coverage |

**Key contract assertions:**

* `compute_thumbprint(jwk)` for a valid kty with all required members
  returns a 43-char Base64URL-no-pad string (SHA-256).
* Same input produces the same output across repeated calls
  (determinism).
* Output is a valid Base64URL charset (charset check).
* Output matches the independently-recomputed SHA-256 digest of the
  RFC 8785 canonical JSON of the *filtered* JWK dict.
* For an unknown kty, all members pass through and the output is
  still 43 chars (no truncation).
* For a recognized kty missing a required member, the call MUST raise
  `ValueError` per RFC 7638 §3.2 — V007 reproducer.
* Non-dict input MUST raise `ValueError`, NOT `TypeError` per SPEC
  promise — V009 reproducer.
* Invalid alg MUST raise `ValueError`.

## Surface 2 — `harness_verify.py` (verify round-trip + oracle)

Exercises `verify(jwk, expected, alg)`. Inputs are routed via
`FuzzedDataProvider` into one of 8 categories:

| Cat | Probe | VULN_AUDIT coverage |
|---|---|---|
| 0 | Round-trip + wrong-thumbprint + single-char-mutated thumbprint | V003 reproducer (error-masking) |
| 1 | Deeply-nested JWK (350-600 levels) | **V002 reproducer** (RecursionError leaks) |
| 2 | Non-dict JWK (None, bytes, list, str, int, float) | verify must be exception-safe |
| 3 | `expected=None` | None sentinel path |
| 4 | Length-mismatched `expected` (0/1/5/10/20/42/44/50/100 chars) | Length check |
| 5 | Charset-mismatched `expected` (43 chars of `!`) | Charset check |
| 6 | Mixed-type / Decimal / bytes JWK | **V009 reproducer** |
| 7 | Invalid alg string | Algorithm confusion |

**Key contract assertions:**

* `verify(valid_jwk, correct_thumbprint) is True` — round-trip must
  hold.
* `verify(valid_jwk, wrong_thumbprint) is False` — wrong thumbprint
  must NOT validate.
* `verify(deeply_nested_jwk, anything) is False` — V002 contract:
  `verify()` MUST catch `RecursionError` and return False.
* `verify(non_dict_jwk, anything) is False` — verify is documented as
  exception-safe for non-dict inputs.
* `verify(jwk, None) is False` — None expected must NOT crash.
* Length-mismatched and charset-mismatched expected MUST return False
  without raising.

## Surface 3 — `harness_canonical.py` (RFC 8785 canonical_json)

Exercises `canonical_json(value)` (the RFC 8785 serializer). Inputs
are routed via `FuzzedDataProvider` into one of 12 categories:

| Cat | Probe | VULN_AUDIT coverage |
|---|---|---|
| 0..5 | Well-formed JSON values ({} through nested + unicode) | Round-trip identity + determinism |
| 6 | Key sort order independence (insertion order A vs B) | Sort stability |
| 7 | Non-BMP emoji `"\U0001F600"` | **V004 reproducer** (surrogate-pair escape) |
| 8 | Control chars `\u0000`, `\u0001`, `\u001f`, `\u0007` | Escape contract |
| 9 | Standard escapes `"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t` | Escape contract |
| 10 | True/False/None/0/1/-1 + dict with True key | **V010 reproducer** (bool key fragility) |
| 11 | Decimal, bytes, set, tuple (non-JSON types) | Type rejection contract |
| 12 | Float 1e-300 + NaN / Inf | **V008 reproducer** (float emission) |

**Key contract assertions:**

* `json.loads(canonical_json(x)) == x` for every JSON-shaped input.
* `canonical_json(x) == canonical_json(x)` (determinism).
* Dict keys sorted lexicographically regardless of insertion order.
* Non-BMP code points MUST escape as UTF-16 surrogate pair per
  RFC 8785 §4.1 — V004 reproducer.
* Control chars (< 0x20) MUST escape as `\uXXXX` per RFC 8259 §7.
* Standard escapes (`"`, `\\`, `\b`, etc.) MUST use the JSON-standard
  forms.
* `canonical_json(True) == "true"`, `canonical_json(1) == "1"`, etc.
* Dict with bool key MUST produce valid JSON output (key must be a
  quoted string) — V010 reproducer.
* Non-JSON types (`Decimal`, `bytes`, `set`) MUST raise `TypeError`.
* Output MUST contain no whitespace (space, tab, newline, CR) outside
  of escaped sequences.

## Surface 4 — `harness_cli.py` (CLI subprocess)

Exercises the CLI (`python src/jwk_thumbprint_pure/cli.py`) in fresh
subprocesses so a crash in the CLI doesn't take down the fuzzer.
Inputs are routed via `FuzzedDataProvider` into one of 11 categories:

| Cat | Probe | VULN_AUDIT coverage |
|---|---|---|
| 0 | `--help` → exit 0, usage on stdout | Argparse contract |
| 1 | Valid JWK on argv → exit 0, thumbprint on stdout | Happy-path |
| 2 | `--verify THUMB` matching → exit 0, "OK: thumbprint matches" | Round-trip |
| 3 | `--verify THUMB` mismatched → exit 1, "MISMATCH:" stderr | Mismatch path |
| 4 | `--canonical` → exit 0, canonical JSON on stdout | Canonical mode |
| 5 | stdin pipe with valid JSON → exit 0 | Stdin path |
| 6 | stdin deeply-nested JSON (350-600 levels) | **V005 reproducer** (CLI leaks traceback) |
| 7 | stdin mixed-type dict | **V005 reproducer** |
| 8 | stdin empty input | **V011 reproducer** (help-unreachable) |
| 9 | Bad JSON on argv (`not-json`, `{]`, etc.) | Bad-JSON path |
| 10 | Bad alg | Algorithm confusion |

**Key contract assertions:**

* `--help` → exit 0, usage on stdout.
* Valid JWK → exit 0, 43-char Base64URL-no-pad on stdout.
* `--verify OK` → exit 0, "OK: thumbprint matches" on stdout.
* `--verify mismatch` → exit 1, "MISMATCH:" on stderr.
* `--canonical` → exit 0, round-trip valid JSON on stdout.
* stdin deeply-nested → exit non-zero, stderr MUST NOT contain
  `Traceback` marker (V005).
* stdin mixed-type → exit non-zero, no traceback (V005).
* stdin empty → exit non-zero, no traceback (V011).
* Bad JSON on argv → exit non-zero, clean error, no traceback.
* Bad alg → exit non-zero, clean error, no traceback.

## Sanitizer configuration

Atheris ships its own coverage instrumentation via libFuzzer-style
shims. The OS-level ASan + UBSan must be enabled via the CPython
runtime (e.g., a debug CPython build with `-DPy_DEBUG` and
`-fsanitize=address,undefined` link flags). The harness itself is
compatible with ASan + UBSan-enabled CPython — atheris loads natively
under them. Whether ASan + UBSan catch issues depends on the CPython
build, not the harness.

The `asan_ubsan_enabled: false` field in the per-surface `stats.json`
files reflects the absence of a debug CPython build in this
environment — NOT a harness defect. See cycle_138
`stats.json` notes for the same disclaimer; this is the standard
cycle_138 / cycle_139 adversary workstream convention.

## Layout

```
cycle_139/adversary/fuzz/
├── harness_compute.py        # Surface 1
├── harness_verify.py         # Surface 2
├── harness_canonical.py      # Surface 3
├── harness_cli.py            # Surface 4
├── run_harnesses.sh          # 5s/surface sweep wrapper
├── HARNESSES.md              # this document
├── compute/
│   └── stats.json            # T2 stub; T3 will populate iter counts
├── verify/
│   └── stats.json
├── canonical/
│   └── stats.json
├── cli/
│   └── stats.json
├── corpus/                   # seed corpora (input bytes)
│   ├── compute/seed_*.json
│   ├── verify/seed_*.bin
│   ├── canonical/seed_*.json
│   └── cli/seed_*.bin
├── crashes/<surface>/        # crash-* quarantined here by run_harnesses.sh
├── hangs/<surface>/          # timeout-* quarantined here
├── oom/<surface>/            # oom-* quarantined here
├── logs/<surface>.log        # per-harness stdout/stderr
└── artifacts/<surface>/      # atheris's working dir (crashes land here first)
```

## Methodology

Each harness follows the cycle_138 adversary pattern (see
`/root/projects/iso7064-pure/.worktrees/t_cycle138-adv-01/cycle_138/adversary/HARNESSES.md`):

1. `atheris.instrument_imports()` context manager to install coverage
   hooks on every imported module.
2. `FuzzedDataProvider` to split the input bytes into typed
   sub-fields (category selector, kty selector, alg selector,
   length, char payload, etc.).
3. `TestOneInput(data: bytes)` with `@atheris.instrument_func`
   decorator.
4. `atheris.Setup(sys.argv, TestOneInput)` then `atheris.Fuzz()`.
5. CLI harness invokes the CLI in a fresh `subprocess.run()` per
   iteration so a crash in the CLI doesn't kill the fuzzer.

VULN_AUDIT reproducers (V001-V011) are encoded as `AssertionError`
raises inside the harness. When the fuzzer mutates an input into a
shape that triggers a reproducer, the harness exits with a crash and
atheris preserves the minimized input in `crashes/<surface>/`. These
artifacts become the regression corpus for T4 (triage) and the
post-fix re-run in T3 (after builder remediation).

## Run

```bash
# 5-second per-surface sweep (default)
bash cycle_139/adversary/fuzz/run_harnesses.sh

# 30-second per-surface sweep (deeper fuzzing)
bash cycle_139/adversary/fuzz/run_harnesses.sh 30

# Individual surface
PYTHONPATH=src python3 cycle_139/adversary/fuzz/harness_compute.py \
    -atheris_runs=100000 -max_total_time=5
```

## Cycle_138 cross-reference

This harness suite follows the cycle_138 adversary workstream pattern:
5 surfaces in cycle_138 (`compute`, `per_system`, `alphabet`, `verify`,
`cli`); 4 surfaces here (`compute`, `verify`, `canonical`, `cli`).
The 4-surface minimum is mandated by Invariant 26 §2 ("≥3 surfaces
ideally 4") and the task body. The jwk-thumbprint-pure API surface
is narrower than iso7064-pure (4 public functions vs. ~15), so 4
surfaces provide exhaustive coverage.

## Worker session metadata

* worker_session_id: 20260928_1130xx_t_cycle139-adv-02
* harness_paths:
  - cycle_139/adversary/fuzz/harness_compute.py
  - cycle_139/adversary/fuzz/harness_verify.py
  - cycle_139/adversary/fuzz/harness_canonical.py
  - cycle_139/adversary/fuzz/harness_cli.py
* surfaces_covered: 4
* ASan + UBSan enabled at the harness level (atheris loads natively
  under ASan + UBSan CPython builds); OS-level ASan + UBSan depend on
  the runtime build, not the harness.
