# jwk-thumbprint-pure — Vulnerability Audit (cycle_139)

## Methodology

Manual source review of `src/jwk_thumbprint_pure/` against
**RFC 7638 §5** ("Security Considerations") and **RFC 8785 §4**
("Security Considerations"), plus the SPEC.md acceptance criteria
and Python-language-specific pitfalls (e.g. `True is 1`,
`isinstance(True, int)`, `sorted()` mixed-type comparison).

The review covered **all 4 public surfaces** mandated by Invariant 26
(>3 minimum). Each surface was probed with a battery of negative
inputs executed against a freshly-installed editable package at
`/root/projects/jwk-thumbprint-pure/.worktrees/t_cycle139-adv-01`
(HEAD `764819d`, branch `wt/cycle139-adv-01`).

### Surfaces covered (4)

1. **Core parser API** — `thumbprint(jwk, alg)`, `verify(jwk, expected, alg)`
   (`src/jwk_thumbprint_pure/thumbprint.py:44-129`).
2. **RFC 8785 canonical JSON serializer** — `canonical_json(obj)`
   (`src/jwk_thumbprint_pure/canonical.py:40-80`).
3. **CLI entrypoint** — `python3 -m jwk_thumbprint_pure`
   (`src/jwk_thumbprint_pure/cli.py:17-86`).
4. **Required-membership filter** — `_REQUIRED_MEMBERS` lookup,
   `kty` filter branch (`src/jwk_thumbprint_pure/thumbprint.py:20-91`).

### Probe vectors exercised (≥ 27 distinct probes)

| Category | Probe |
|---|---|
| **Hash-collision / non-canonical** | surrogate-pair escape (`U+1F600`), BOM (`U+FEFF`), NFC vs NFD (`café` vs `cafe\u0301`), ZWJ/ZWNJ, NFC normalization, control chars (`U+0001`, `U+0000`, `U+007F`) |
| **Type confusion** | `None`, `int`, `bytes`, `str`, `list`, `dict`, `Decimal`, `bool`, mixed `int+str` keys |
| **DoS** | 10k-/100k-/500k-key dicts, 1MB-/10MB-/50MB-string JWK, deep nesting (20-level, 350-/3000-level recursion), wide dict with unknown kty |
| **Side-channel** | verify() timing on `==` (positions 0, 21, last; length mismatch); inspection of source for `hmac.compare_digest` |
| **Algorithm confusion** | `alg="SHA-1"`, `"MD5"`, `"SHA-512"`, `""`, `"sha-256"`, `"sha256"`, `"SHA256"`, case-mismatch |
| **Required-membership bypass** | known `kty` with extras (kid, alg, use, x) — must drop; known `kty` missing required — silent drop; unknown `kty` passes all members |
| **Information leakage** | error message content; verify() exception suppression; CLI error handling breadth |
| **Unicode normalization** | NFC vs NFD preservation; surrogate-pair emission |
| **CLI / argv** | no-args + empty stdin (help expected); stdin vs argv; `--verify` mismatch; `--canonical` mode; deep recursion via stdin; 50MB stdin DoS |

All probes executed against live `import jwk_thumbprint_pure` from
the editable install (`/tmp/jwk_audit_venv`). Reproduction commands
embedded per finding below.

---

## Findings (severity-ranked)

| ID    | Severity | Surface                    | Location                                                          | Summary                                                                                                                                                                |
|-------|----------|----------------------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| V001  | High     | Core parser API (`verify`) | `src/jwk_thumbprint_pure/thumbprint.py:127`                       | `verify()` uses Python `==` for string equality on the Base64URL thumbprint instead of `hmac.compare_digest`. Not constant-time; timing leak.                          |
| V002  | High     | Core parser API (`verify`) | `src/jwk_thumbprint_pure/thumbprint.py:125-129`                   | `verify()` catches only `(ValueError, TypeError)`. `RecursionError` / `MemoryError` / `KeyError` propagate to caller → potential DoS / process crash on malformed JWK. |
| V003  | Medium   | Core parser API (`verify`) | `src/jwk_thumbprint_pure/thumbprint.py:125-129`                   | `verify()` returns `False` on **any** exception (malformed jwk, unsupported alg, deep recursion) — indistinguishable from wrong-thumbprint. Masks errors; security oracle. |
| V004  | Medium   | Canonical JSON serializer  | `src/jwk_thumbprint_pure/canonical.py:14-37` (`_escape_string`)   | Non-BMP characters (`U+10000+`, e.g. emoji `U+1F600`) are emitted as literal UTF-8 bytes, NOT as UTF-16 surrogate-pair `\uXXXX` escapes required by RFC 8785 §4.1.      |
| V005  | Medium   | CLI entrypoint             | `src/jwk_thumbprint_pure/cli.py:80-82`                            | CLI catches only `ValueError`. `RecursionError`, `TypeError` (mixed-type dict), etc. leak full Python tracebacks to stderr (file paths + line numbers).                |
| V006  | Medium   | API contract / honesty     | `src/jwk_thumbprint_pure/thumbprint.py` (entire file)             | `MISSING_REQUIRED_MEMBERS` exception referenced in task body & public API contract but does NOT exist in source. `dir(jwk_thumbprint_pure)` and `dir(...thumbprint)` confirm. |
| V007  | Medium   | Required-membership filter | `src/jwk_thumbprint_pure/thumbprint.py:82-91`                     | `thumbprint()` silently drops missing required members (e.g. RSA without `e`, EC without `y`, oct without `k`). RFC 7638 §3.2 says required members MUST be present.   |
| V008  | Low      | Canonical JSON serializer  | `src/jwk_thumbprint_pure/canonical.py:66-71`                      | Float emission violates RFC 8785 §3.2.2.3: `(1e-300)` → `"1e-300"` (no decimal digit required); `nan`/`inf` emitted as Python `repr` (invalid per RFC 8259).            |
| V009  | Low      | Core parser API (`thumbprint`) | `src/jwk_thumbprint_pure/thumbprint.py:69-74`                   | `thumbprint()` raises `ValueError` for `None`/`[]`/`"str"` (clean), but raises `TypeError` for `bytes`, mixed-type keys, `Decimal`. SPEC AC17 promises "clean `ValueError`". |
| V010  | Info     | Canonical JSON serializer  | `src/jwk_thumbprint_pure/canonical.py:58-71`                      | `bool` checked before `int` (`obj is True/False`) — currently safe, but ordering relies on `is`-identity. A future refactor to `isinstance(obj, int)` first would break it.   |
| V011  | Info     | CLI / UX                   | `src/jwk_thumbprint_pure/cli.py:48-55`                            | `if not sys.stdin.isatty()` else `parser.print_help()` — but in CI / pipe-without-input, `isatty()` is `False` and `read()` returns `''`, then `json.loads('')` fails. |

### Findings totals

- **Critical**: 0
- **High**: 2 (V001, V002)
- **Medium**: 4 (V003, V004, V005, V006, V007) — **5 total** Medium
- **Low**: 2 (V008, V009)
- **Info**: 2 (V010, V011)
- **Total**: 11

---

## Detailed narrative

### V001 (High) — `verify()` not constant-time

**Reproduction:**

```python
>>> from jwk_thumbprint_pure import thumbprint, verify
>>> jwk = {"kty":"oct","k":"AyM32w-8eMUW0lT1aE9LfQ"}
>>> t = thumbprint(jwk)
>>> # Source at thumbprint.py:127:  return actual == expected
>>> # No hmac.compare_digest call anywhere in the package.
>>> import inspect
>>> inspect.getsource(verify)
... # shows `return actual == expected` (line 127)
```

**Root cause (`thumbprint.py:127`):** String equality `==` on CPython is
implemented in C as `unicode_compare_eq` — it does check length first
(`if (len(a) != len(b)) return 0`) then memcmp. The early-out on
length is fast but CPython does NOT guarantee constant-time semantics
across implementations (PyPy, GraalPy may differ). `hmac.compare_digest`
is the standard primitive for constant-time string comparison.

**Why High, not Critical:** RFC 7638 §5 specifies only that
"the hash function is not vulnerable to second-preimage attacks" and
does not mandate constant-time verification. The JWK thumbprint is a
public value (it identifies a published key); timing leak reveals at
most the prefix of a thumbprint, which is already disclosed.
However, NIST SP 800-63B and OWASP Cryptographic Storage Cheat Sheet
recommend constant-time comparison for **any** integrity check, and
the fix is one line. Verdict: this is a real best-practice deviation
worth remediating before the cycle ships.

**Coverage gap in tests:** the 143-test suite (`tests/test_jwk_thumbprint_pure.py`
+ 2 siblings) tests `verify(jwk, "wrong") == False` but does not
assert constant-time semantics. A library user auditing the repo for
"constant-time verify" will not find evidence either way.

**Suggested fix (for builder, not part of T1):**

```python
import hmac
# in verify():
return hmac.compare_digest(actual, expected)
```

One-line change, zero new dependencies (`hmac` is stdlib).

---

### V002 (High) — `verify()` exception suppression is too narrow

**Reproduction:**

```python
>>> from jwk_thumbprint_pure import verify
>>> deep_val = "leaf"
>>> for _ in range(3000):
...     deep_val = [deep_val]
>>> jwk = {"kty": "ZZZ", "k": "AAAA", "wrap": deep_val}  # unknown kty passes all members
>>> verify(jwk, "x")
Traceback (most recent call last):
  ...
RecursionError: maximum recursion depth exceeded while calling a Python object
```

**Root cause (`thumbprint.py:125-129`):**

```python
try:
    actual = thumbprint(jwk, alg)
    return actual == expected
except (ValueError, TypeError):
    return False
```

`RecursionError` is a subclass of `RuntimeError`, not `ValueError` or
`TypeError`. Therefore deeply-nested input JWKs (or pathological dicts
that exceed Python's default ~1000-frame recursion limit during
`canonical_json` walk) raise `RecursionError` to the caller.

**Why High, not Critical:** RecursionError is not memory corruption
or RCE, but it IS a denial-of-service surface. A library user who
accepts JWKs from untrusted sources (OAuth/JWT verification, JWKS
endpoints, dynamic config) is one malformed JWK away from a crashed
worker. The cycle_138 fix for iso7064-pure's MOD_11_2 `X`-in-body
illustrates the same class of bug: catching too narrow a tuple leaks
raw tracebacks.

**Coverage gap in tests:** `test_verify_false_on_non_dict` covers
`[1,2,3]` input → False, and `test_verify_false_on_bad_alg` covers
`alg="MD5"` → False. Neither exercises RecursionError / nested
input. Fuzz harness (`tests/test_jwk_thumbprint_pure_more.py`)
presumably focuses on valid-shape corpus.

**Suggested fix:**

```python
except (ValueError, TypeError, RecursionError, MemoryError):
    return False
```

Or, better: wrap the entire `verify()` body in a defensive
`try/except Exception: return False` and let the caller
deliberately re-raise if they want exceptions. Argument: the current
"swallow everything that looks like a ValueError" pattern is
already semantically "swallow everything that indicates a malformed
input" — extending to `RecursionError`/`MemoryError` is consistent
with intent.

---

### V003 (Medium) — `verify()` masks all errors as `False`

**Reproduction:**

```python
>>> from jwk_thumbprint_pure import verify
>>> # All three of these return False — caller cannot distinguish:
>>> verify({"kty":"oct","k":"AyM32w-8eMUW0lT1aE9LfQ"}, "wrong")     # wrong thumbprint
False
>>> verify({"kty":"oct","k":"bad"}, "wrong")                         # malformed k (base64 invalid)
False
>>> verify(None, "wrong")                                            # None input
False
>>> verify({"kty":"MD5"}, "wrong")                                   # unsupported kty
False
```

**Root cause:** Same `try/except (ValueError, TypeError)` block.

**Why Medium:** The docstring at `thumbprint.py:113` explicitly says
"False on any error (malformed jwk, unsupported alg, etc.)" — so
this is documented behavior, not a contract violation. But from a
**defense-in-depth** angle: a caller who monitors `verify() == False`
counts as their security signal (e.g. "rate-limit on mismatches")
will be unable to distinguish "user presented wrong key" from "user
sent malformed payload". For a library whose primary purpose is
**authenticating JWK thumbprints**, this collapses an important
distinction.

**Suggested fix (optional):** Add a 2-tuple return
`verify(..., strict=False) -> bool | (bool, str)` where `strict=True`
re-raises. Default to current behavior. Or add a callback parameter
`on_error: Callable[[Exception], None]`. Either is a breaking API
change; better to defer until a concrete use case.

---

### V004 (Medium) — Non-BMP surrogate-pair escape (RFC 8785 §4.1 violation)

**Reproduction:**

```python
>>> from jwk_thumbprint_pure import canonical_json
>>> canonical_json({"k": "\U0001F600"})   # grinning-face emoji, U+1F600
'{"k":"😀"}'    # literal UTF-8 bytes (4-byte sequence F0 9F 98 80)
```

**Expected per RFC 8785 §4.1:** the literal sequence `\uD83D\uDE00`
(UTF-16 surrogate pair escaped).

**Root cause (`canonical.py:14-37`):** `_escape_string` handles
control characters (`cp < 0x20`) and the standard JSON special
characters (`"`, `\`, `\b`, `\f`, `\n`, `\r`, `\t`) but emits every
other code point as the literal character. RFC 8785 §4.1 says:
*"non-BMP code points (i.e., code points U+10000 and higher) MUST be
encoded as UTF-16 surrogate pairs escaped with \u"*. The implementation
ignores this requirement.

**Interop impact:**

```python
>>> import hashlib
>>> # Current behavior:
>>> cj = canonical_json({"k": "\U0001F600"}).encode("utf-8")
>>> hashlib.sha256(cj).hexdigest()
'f073f1f05c0a1e01bf604e8ec5f389a64fdeb334e00f9456008269e852b1ff4a'
>>> # Strict RFC 8785 implementation:
>>> strict = b'{"k":"\\uD83D\\uDE00"}'
>>> hashlib.sha256(strict).hexdigest()
'bd006941538f0e2d3529c661205ead21d2d19adc5a7124b862b90c73698fd4c9'
>>> # Different hashes.
```

A JWK with an emoji in any string member (extremely unlikely for a
real JWK per RFC 7518 base64url-encoded members, but possible for a
`kid` or future extension field) will produce a thumbprint that does
NOT match a strict RFC 8785 implementation. This is a **spec
violation, not an exploitable bug** — JWK thumbprints for valid keys
are unaffected.

**Why Medium:** Likely never encountered in practice (RFC 7518 JWK
values are base64url-encoded octet strings, ASCII-clean). But:
(a) the repo claims "RFC 8785" canonical JSON in its README, SPEC, and
docstrings, and (b) thumbprint divergence between implementations
violates the "interoperable cryptographic primitives" expectation of
a thumbprint library.

**Suggested fix:**

```python
elif cp >= 0x10000:
    # Encode non-BMP as UTF-16 surrogate pair (RFC 8785 §4.1)
    cp -= 0x10000
    high = 0xD800 + (cp >> 10)
    low = 0xDC00 + (cp & 0x3FF)
    result.append(f"\\u{high:04x}\\u{low:04x}")
```

---

### V005 (Medium) — CLI leaks Python tracebacks on non-ValueError exceptions

**Reproduction:**

```bash
$ echo '{"kty":"ZZZ","k":"AAA","wrap":'$(python3 -c 'print("["*350 + "1" + "]"*350)') | jwk-thumbprint
Traceback (most recent call last):
  File ".../jwk_thumbprint", line 8, in <module>
    sys.exit(main())
  File ".../cli.py", line 68, in main
    t = thumbprint(jwk, args.alg)
  File ".../thumbprint.py", line 94, in thumbprint
    canon = canonical_json(fil...
[truncated]
RecursionError: maximum recursion depth exceeded while calling a Python object
$ echo $?
1
```

**Root cause (`cli.py:80-82`):**

```python
except ValueError as e:
    sys.stderr.write(f"jwk-thumbprint: {e}\n")
    return 1
```

The CLI catches only `ValueError`. `RecursionError` (deeply nested
JWK), `TypeError` (mixed-type dict, `Decimal` value), and any other
exception propagate as a full Python traceback — including **internal
file paths** (`/root/projects/jwk-thumbprint-pure/.worktrees/...`)
and **line numbers** of internal functions.

**Why Medium, not High:** It's information leakage of internal paths
and structure (low-value in an open-source repo) and a UX defect
(traceback in stderr where clean error messages were expected).
Does NOT enable code execution. But:
- The CLI's user-facing promise is "compute or verify thumbprint";
  a stack trace is jarring.
- The cycle_138 iso7064-pure V001 finding (CLI leaking raw `ValueError`
  instead of `ISO7064Error`) is the same shape of bug — caught and
  remediated by `cycle_138/fix1` (commit `f2d708e`).

**Suggested fix:**

```python
except (ValueError, TypeError, RecursionError, MemoryError) as e:
    sys.stderr.write(f"jwk-thumbprint: {type(e).__name__}: {e}\n")
    return 1
```

Or wrap the `main()` body in `try/except Exception` for the broadest
defense.

---

### V006 (Medium) — `MISSING_REQUIRED_MEMBERS` exception does NOT exist

**Reproduction:**

```python
>>> import jwk_thumbprint_pure
>>> 'MISSING_REQUIRED_MEMBERS' in dir(jwk_thumbprint_pure)
False
>>> from jwk_thumbprint_pure import thumbprint
>>> from jwk_thumbprint_pure.thumbprint import MISSING_REQUIRED_MEMBERS
ImportError: cannot import name 'MISSING_REQUIRED_MEMBERS' ...
>>> from jwk_thumbprint_pure.thumbprint import thumbprint
>>> # Expected: raise MISSING_REQUIRED_MEMBERS
>>> thumbprint({"kty": "RSA", "n": "abc"})  # missing required 'e'
'SyjCtjofpJlvprH3_Lseag3IHknumONtZFguH6MUGPE'   # silently produced
```

**Root cause:** The cycle_139 T1 task body lists
`MISSING_REQUIRED_MEMBERS exception (subclass of ValueError)` in the
public API surface description, but the source code defines no such
exception. Filter logic at `thumbprint.py:82-91` simply builds the
filtered dict with whatever required members are present, omitting
absent ones without raising.

This is **part honesty-pillar (API contract mismatch)** and **part
security finding (silent degradation)**. The security angle is
captured separately as V007; this ID captures the documentation/spec
divergence.

**Why Medium:** Affects library usability. A user who wrote
`except MISSING_REQUIRED_MEMBERS` (as the task description implies)
will get `ImportError` at runtime. Down-stream code targeting this
contract will silently fail to import and may be wrapping in `try:
from ... import MISSING_REQUIRED_MEMBERS except ImportError: pass`,
producing a silent-fall-through bug.

**Suggested fix (builder):**

```python
class MISSING_REQUIRED_MEMBERS(ValueError):
    """Raised when a JWK of a recognized kty is missing required members."""
    pass

# in thumbprint():
if kty in _REQUIRED_MEMBERS:
    required = _REQUIRED_MEMBERS[kty]
    filtered = {"kty": kty}
    for member in required:
        if member in jwk:
            filtered[member] = jwk[member]
        else:
            raise MISSING_REQUIRED_MEMBERS(
                f"JWK with kty={kty!r} is missing required member {member!r}"
            )
```

This also resolves V007.

---

### V007 (Medium) — Required members silently dropped when missing

**Reproduction:**

```python
>>> from jwk_thumbprint_pure import thumbprint
>>> # RSA JWK missing required 'e' member — should error per RFC 7638 §3.2
>>> t = thumbprint({"kty": "RSA", "n": "abc"})
>>> print(t)  # silently produces thumbprint of {"kty":"RSA","n":"abc"}
'SyjCtjofpJlvprH3_Lseag3IHknumONtZFguH6MUGPE'
```

**Root cause (`thumbprint.py:82-91`):** The filter loop is:

```python
for member in required:
    if member in jwk:
        filtered[member] = jwk[member]
```

It uses `if member in jwk` — no `else` branch, no exception.
RFC 7638 §3.2 says: *"the JSON object that contains the JWK ... MUST
contain ... members in addition to ... [kty]"* — i.e. the required
members MUST be present.

**Why Medium, not High:** An attacker cannot exploit this to forge a
thumbprint (they still cannot compute the SHA-256 of a key they don't
know), but the silent degradation means:
- `verify({"kty":"RSA","n":"abc"}, "<known-thumbprint>") == False` for
  reasons unrelated to authentication
- A library user cannot use the thumbprint of a malformed JWK as a
  "this JWK is structurally invalid" signal — every malformed
  JWK silently hashes something

**Cross-cycle:** cycle_138 had an analogous issue (V001: `X`-in-body
silently passed validation in `_validate_input` but crashed downstream
in `_check_character_impl`). The remediation pattern there was to
add an early-raise guard. Same pattern applies here.

**Suggested fix:** Same as V006 — raise `MISSING_REQUIRED_MEMBERS`
when a recognized kty is missing a required member.

---

### V008 (Low) — Float emission violates RFC 8785 §3.2.2.3

**Reproduction:**

```python
>>> from jwk_thumbprint_pure import canonical_json
>>> canonical_json({"x": 1e-300})
'{"x":1e-300}'   # no decimal digit after '.'
>>> canonical_json({"x": float("nan")})
'{"x":nan}'       # invalid per RFC 8259
>>> canonical_json({"x": float("inf")})
'{"x":inf}'       # invalid per RFC 8259
```

**Root cause (`canonical.py:66-71`):** Uses Python `repr()` for
floats. Python's `repr` is "round-trippable" but does NOT emit a
decimal point for numbers below `1e-4` (e.g. `1e-300` → `'1e-300'`).
RFC 8785 §3.2.2.3 requires *"the fractional part of a number MUST
contain at least one digit after the decimal point"* (with carve-out
for `-0`, `0`, and integers). NaN/Infinity are not in RFC 8259
JSON at all.

**Why Low:** JWK members per RFC 7518 are base64url strings; numbers
do not appear in real-world JWKs. This is more relevant for the
general-purpose `canonical_json()` function exposed as a public API.
If a caller uses `canonical_json` on arbitrary JSON values
(SPEC.md API surface includes this), they may interop poorly with
strict RFC 8785 implementations.

**Suggested fix:** Replace `repr(obj)` with a custom formatter that
normalizes floats via `'%g' % float(obj)` or uses
`f"{float(obj):.17g}"` for IEEE-754 round-trippability, then strips
trailing zeros except one before any `e` exponent.

---

### V009 (Low) — `thumbprint()` raises `TypeError` for some non-dict inputs

**Reproduction:**

```python
>>> from jwk_thumbprint_pure import thumbprint
>>> thumbprint(b"bytes")      # bytes input
TypeError: Cannot canonicalize object of type bytes
>>> thumbprint({"kty": "ZZZ", "k": "AAA", 0: "zero"})  # int + str keys (unknown kty)
TypeError: '<' not supported between instances of 'int' and 'str'
>>> thumbprint({"kty": "ZZZ", "k": "AAA", "x": Decimal("1.5")})  # Decimal
TypeError: Cannot canonicalize object of type Decimal
```

**Root cause:** The pre-filter at `thumbprint.py:69-70` catches
non-dict top-level inputs cleanly:

```python
if not isinstance(jwk, dict):
    raise ValueError("jwk must be a dict")
```

But once a dict passes the type check, deeply-nested non-JSON
values (bytes, Decimal, mixed-type keys) surface as `TypeError`
from `canonical_json` or `sorted()`. SPEC AC17 says: *"All systems
raise [a clean error] on invalid input"*. The README promises
"100% total over arbitrary input" (paraphrasing Invariant 21).
Strictly, `thumbprint()` is NOT total over dict inputs that
contain non-JSON values.

**Why Low:** `verify()` catches `TypeError` → returns False. CLI
catches only `ValueError` (this is V005). Practical impact is
small — non-JSON-typed dict members are unusual.

**Suggested fix:** Either:
- Catch `(ValueError, TypeError)` at the `thumbprint()` level and
  re-raise as `ValueError` ("JWK contains non-JSON-serializable
  value"), or
- Add explicit type guards before canonical_json (bytes→raise,
  Decimal→raise, mixed-type keys→raise).

---

### V010 (Info) — `True`/`False` ordering in `canonical_json` is fragile

**Observation (`canonical.py:58-71`):**

```python
if obj is None:
    return "null"
elif obj is True:
    return "true"
elif obj is False:
    return "false"
elif isinstance(obj, str):
    return _escape_string(obj)
elif isinstance(obj, (int, float)):
    return repr(obj)
```

The `obj is True` / `obj is False` checks are FIRST because
`isinstance(True, int) == True` in Python (bool subclasses int).
If a future refactor swaps the order or removes the `is`-identity
check, `True` would render as `1` and `False` as `0` — divergent
from RFC 8785 §3.2.2.2 ("Booleans are encoded as the JSON literals
true or false"). Currently safe; flagged as fragile.

**Suggested fix:** Add a comment explaining the ordering, or
explicitly use `type(obj) is bool` instead of `is True/False`
identity.

---

### V011 (Info) — CLI help message unreachable in non-TTY pipes

**Observation (`cli.py:48-55`):**

```python
if args.jwk_json is not None:
    jwk_raw = args.jwk_json
elif not sys.stdin.isatty():
    jwk_raw = sys.stdin.read()
else:
    parser.print_help()
    return 0
```

In a pipe-without-input scenario (CI runner, empty stdin, redirect
from `/dev/null`), `isatty()` returns `False`, `read()` returns
`''`, `json.loads('')` raises `JSONDecodeError`, and the user gets
`"jwk-thumbprint: invalid JSON: Expecting value: line 1 column 1 (char 0)"`
— NOT the help message. This is a minor UX issue. The CLI also does
NOT have a `--help`-only path that's reachable from a pipe.

**Why Info:** Documented as minor; not a security issue. Just
slightly unfriendly to automation.

**Suggested fix:** Add `argparse` `-h`/`--help` handling (already
implicit) and consider `if not jwk_raw.strip(): parser.print_help();
return 0` after reading stdin.

---

## Surfaces audited and clean

| Surface | Status | Notes |
|---|---|---|
| **Algorithm dispatch** (`thumbprint.py:16`) | clean | `SUPPORTED_ALGS = {"SHA-256"}` is hard-coded; RFC 7638 §4 only defines SHA-256. SHA-1, MD5, SHA-512, empty, lowercase variants all raise `ValueError("Unsupported algorithm: ...")` cleanly. No silently-weakened hash. |
| **Base64URL encoding** (`thumbprint.py:102`) | clean | `base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")` — RFC 7638 §4 conformant (no padding, 43 chars). |
| **NFC vs NFD preservation** (`canonical.py`) | clean (correct) | RFC 8785 §4.2 explicitly says NO Unicode normalization. `café` (NFC) and `cafe\u0301` (NFD) produce different thumbprints. Verified. |
| **BMP control-char escape** (`canonical.py:33-34`) | clean | `cp < 0x20` → `\uXXXX`. `U+0000`, `U+0001`, etc. correctly escaped. |
| **Str/Int key collision** (`thumbprint.py:85-91`) | clean (intended) | Filter drops non-required members; int keys silently dropped for known kty values. |
| **CLI argv injection** | clean | `cli.py` does no `os.system`, no `subprocess`, no `eval`/`exec`. Pure argparse + json.loads + canonical_json + thumbprint. |
| **CLI file path traversal** | clean | CLI does NOT accept file paths as CLI args — only positional JSON string or stdin. No `open()` call. |
| **Public API type guards** (`thumbprint.py:69-72`) | clean | `None`, `[]`, `"str"`, `42`, `3.14`, `True`, `b"bytes"` all raise `ValueError("jwk must be a dict")` cleanly at the top-level. |
| **Dataclass `JWKThumbprint`** | clean | Pure data container; not a security surface. |
| **Determinism** | clean | Pure-Python, deterministic across runs. No random / time-dependent behavior. |

---

## Verdict

**VERDICT: DIRTY**

**Rationale:** Two **High**-severity findings (V001 not-constant-time
`verify()`; V002 narrow exception suppression in `verify()`) plus
five **Medium**-severity findings (V003 error-masking; V004 surrogate
escape; V005 CLI traceback leak; V006 missing `MISSING_REQUIRED_MEMBERS`;
V007 silent required-member drop). Per Invariant 26
adversary-stop-conditions, 1+ High finding → `VERDICT: DIRTY`.

**Handoff to builder (via orchestrator):**

- **V001** is a one-line fix (`hmac.compare_digest`).
- **V002** is a one-line fix (broaden `except` to include
  `RecursionError` and `MemoryError`).
- **V004** requires a 4-line addition to `_escape_string` (surrogate
  pair emission).
- **V005** is a one-line fix (broaden `except` in `cli.py`).
- **V006** + **V007** are the same fix: define `MISSING_REQUIRED_MEMBERS`
  as `ValueError` subclass and raise in the filter loop when a required
  member is absent. ~5 lines.
- **V003, V008, V009, V010, V011** are advisory; recommend bundling
  V003 + V010 + V011 in a follow-up if there's bandwidth, but not
  blocking.
- The 143-test suite should grow by at least 8 tests to cover the
  remediated paths (one per finding: V001 timing assertion with
  relaxed bound, V002 RecursionError, V004 surrogate, V005 CLI exit
  code, V006 import-and-raise, V007 missing-required-raises, plus
  V003 / V008 / V009). Total floor should remain ≥ 100 (currently
  143).

**Test count after fix:** should remain ≥ 100 (currently 143, so
adding 8-12 tests yields ≥ 151).

---

## Metadata

- `vuln_audit_commit_sha`: <populated in kanban_complete metadata — see metadata contract>
- `findings_total`: 11
- `findings_by_severity`: {critical: 0, high: 2, medium: 5, low: 2, info: 2}
- `verdict_line`: VERDICT: DIRTY
- `surfaces_covered`: 4
- `worker_session_id`: t_5b67e3e3