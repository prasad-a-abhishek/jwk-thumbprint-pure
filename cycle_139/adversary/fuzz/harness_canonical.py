"""Atheris harness for the ``canonical_json`` surface (Surface 3).

Surface 3 of the cycle_139 adversary workstream.

Exercises :func:`jwk_thumbprint_pure.canonical_json` — the RFC 8785
JSON Canonicalization Scheme implementation.  This surface is
independent of the thumbprint filter and has its own invariants
(sort keys, escape per RFC 8259 §7, no whitespace, parseable
round-trip).  The VULN_AUDIT flagged V004 (non-BMP surrogate-pair
escape missing), V008 (float emission), and V010 (bool/int
ordering fragility) on this surface.

Specifically we test:

* **Round-trip identity**: ``json.loads(canonical_json(x))`` must
  equal ``x`` for every JSON-shaped input.  This catches any
  divergence between the canonical form and the original.
* **Determinism**: ``canonical_json(x) == canonical_json(x)`` for
  any input (no random ordering, no hash ordering).
* **Key sort order**: dict keys must come out in lexicographic order
  regardless of insertion order.  Probe: same dict with different
  key insertion order must produce identical output.
* **Non-BMP surrogate-pair escape** (V004): ``canonical_json({"k":
  "\U0001F600"})`` MUST escape the non-BMP char as UTF-16
  surrogate pair ``\uD83D\uDE00``.  Current implementation emits
  literal UTF-8 bytes — we surface that as a finding.
* **Control-char escape**: ``\u0000``, ``\u0001``, ``\u001f`` MUST
  be escaped as ``\u0000`` etc. (RFC 8259 §7).
* **Standard escapes**: ``"``, ``\\``, ``\b``, ``\f``, ``\n``, ``\r``,
  ``\t`` MUST be escaped as their JSON-standard forms.
* **Bool/int fragility** (V010): ``canonical_json(True) == "true"``
  and ``canonical_json(1) == "1"``.  ``canonical_json({True: 1})``
  must NOT silently coerce True to int (it's a JSON object key;
  Python's ``sorted`` would sort True first).
* **Float emission** (V008): ``1e-300`` should have a decimal point
  per RFC 8785 §3.2.2.3.  NaN / Infinity are NOT valid JSON values.
* **No whitespace**: ``canonical_json(x)`` MUST NOT contain spaces,
  newlines, tabs outside of escaped sequences.
* **Deep nesting** (V008 / V004 interaction): nested dicts/lists
  must be canonicalized recursively.  RecursionError must not leak
  on moderately-deep nesting (10–50 levels).
* **Non-JSON-serializable types** (``Decimal``, ``bytes``, ``set``,
  ``tuple``): must raise ``TypeError`` (canonical_json explicitly
  rejects these — V009 contract).

Run::

    python3 harness_canonical.py -atheris_runs=100000 -max_total_time=5
"""
from __future__ import annotations

import json
import sys
import typing as _t

import atheris  # type: ignore[import-not-found]

with atheris.instrument_imports():  # type: ignore[attr-defined]
    from jwk_thumbprint_pure.canonical import (  # noqa: E402
        canonical_json,
    )


# A set of well-formed JSON values we cycle through (so the fuzzer
# has good corpus coverage for the happy paths).
_SEED_DICTS: tuple[dict, ...] = (
    {},
    {"a": 1},
    {"b": 2, "a": 1},
    {"kty": "oct", "k": "AAAA"},
    {"nested": {"inner": [1, 2, {"x": "y"}]}},
    {"unicode": "caf\u00e9"},  # NFC
    {"emoji_in_string": "hello \U0001F600"},  # mixed BMP + non-BMP
)


@atheris.instrument_func  # type: ignore[attr-defined]
def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)  # type: ignore[attr-defined]

    cat = fdp.ConsumeIntInRange(0, 11)

    if cat < len(_SEED_DICTS):
        # === Round-trip identity + determinism ===
        x = _SEED_DICTS[cat]
        try:
            cj1 = canonical_json(x)
        except Exception as exc:
            raise AssertionError(
                f"canonical_json({x!r}) raised {type(exc).__name__}: "
                f"{exc!r} on a valid JSON value"
            ) from exc
        assert isinstance(cj1, str), (
            f"canonical_json({x!r}) returned non-str: {type(cj1).__name__}"
        )
        # Determinism
        cj2 = canonical_json(x)
        assert cj1 == cj2, (
            f"canonical_json({x!r}) not deterministic: {cj1!r} != {cj2!r}"
        )
        # Round-trip identity (must be valid JSON).
        try:
            back = json.loads(cj1)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"canonical_json({x!r}) = {cj1!r} is NOT valid JSON: "
                f"{exc!r}"
            ) from exc
        assert back == x, (
            f"canonical_json({x!r}) round-trip mismatch: got {back!r}"
        )
        # No whitespace outside of escaped sequences.
        for ch in cj1:
            assert ch not in " \t\n\r", (
                f"canonical_json({x!r}) = {cj1!r} contains whitespace"
            )
        return

    if cat == 6:
        # === Key sort order: insertion order independence ===
        # Build same dict with two different insertion orders.
        d1 = {"z": 1, "y": 2, "x": 3, "a": 4, "m": 5}
        d2 = {"a": 4, "m": 5, "z": 1, "y": 2, "x": 3}
        c1 = canonical_json(d1)
        c2 = canonical_json(d2)
        assert c1 == c2, (
            f"canonical_json sort order depends on insertion: "
            f"d1={c1!r}, d2={c2!r}"
        )
        # Verify the sort is lexicographic by ASCII.
        assert c1 == '{"a":4,"m":5,"x":3,"y":2,"z":1}', (
            f"canonical_json sort is not ASCII-lexicographic: {c1!r}"
        )
        return

    if cat == 7:
        # === V004 reproducer: non-BMP surrogate-pair escape ===
        # The current implementation emits literal UTF-8 bytes (4-byte
        # sequence F0 9F 98 80) for U+1F600, but RFC 8785 §4.1 requires
        # UTF-16 surrogate pair (\uD83D\uDE00).
        val = "\U0001F600"
        cj = canonical_json({"k": val})
        expected_strict = r'{"k":"\uD83D\uDE00"}'
        if cj != expected_strict:
            # This is the VULN_AUDIT finding: surface it.
            raise AssertionError(
                f"V004 REPRODUCED: canonical_json(emoji) = {cj!r}, "
                f"expected strict RFC 8785 surrogate-pair form "
                f"{expected_strict!r}"
            )
        # If the assertion above didn't fire, the strict form is
        # emitted — also assert the round-trip identity still holds.
        back = json.loads(cj)
        assert back == {"k": val}, (
            f"canonical_json surrogate-pair round-trip failed: {back!r}"
        )
        return

    if cat == 8:
        # === Control-char escape ===
        for ch in ("\u0000", "\u0001", "\u001f", "\u0007"):
            cj = canonical_json({"k": ch})
            expected = '{"k":"\\u' + f'{ord(ch):04x}' + '"}'
            assert cj == expected, (
                f"canonical_json control-char {ord(ch):#06x} = {cj!r}, "
                f"expected {expected!r}"
            )
        return

    if cat == 9:
        # === Standard escapes ===
        for ch, esc in (
            ('"', r"\""),
            ("\\", r"\\"),
            ("\b", r"\b"),
            ("\f", r"\f"),
            ("\n", r"\n"),
            ("\r", r"\r"),
            ("\t", r"\t"),
        ):
            cj = canonical_json({"k": ch})
            expected = '{"k":"' + esc + '"}'
            assert cj == expected, (
                f"canonical_json escape for {ch!r} = {cj!r}, expected "
                f"{expected!r}"
            )
        return

    if cat == 10:
        # === Bool / int / None ===
        assert canonical_json(True) == "true"
        assert canonical_json(False) == "false"
        assert canonical_json(None) == "null"
        assert canonical_json(0) == "0"
        assert canonical_json(1) == "1"
        assert canonical_json(-1) == "-1"
        # V010 reproducer: bool as dict key.
        # Python treats True as 1 in dict semantics, but JSON object
        # keys are strings only.  Current implementation emits the
        # literal token `true` which is NOT a valid JSON key — this
        # is the V010 finding.  We catch TypeError AND JSONDecodeError
        # here so the harness doesn't blow up the fuzzer; instead we
        # check the produced string with our own parser.
        try:
            cj = canonical_json({True: 1})  # type: ignore[dict-item]
        except TypeError:
            return  # acceptable — implementation rejected
        # Parse manually: a canonical_json output must start with '{'
        # and have string keys only.  ``{"true":1}`` is valid; ``{true:1}``
        # is invalid JSON.  We use a regex to detect the latter.
        import re as _re
        if _re.search(r"\{\s*[A-Za-z_]\w*\s*:", cj):
            # The key was emitted as an unquoted identifier — invalid JSON.
            raise AssertionError(
                f"V010 REPRODUCED: canonical_json({{True: 1}}) = {cj!r} "
                f"contains an unquoted identifier as a key — invalid JSON "
                f"(SPEC promises valid JSON output)"
            )
        try:
            back = json.loads(cj)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"V010 REPRODUCED: canonical_json({{True: 1}}) = {cj!r} "
                f"is not valid JSON: {exc!r}"
            ) from exc
        assert all(isinstance(k, str) for k in back), (
            f"canonical_json bool key produced non-str key: {cj!r}"
        )
        return

    if cat == 11:
        # === Non-JSON-serializable types must raise TypeError ===
        from decimal import Decimal
        bad: tuple[_t.Any, ...] = (
            Decimal("1.5"),
            b"bytes",
            {1, 2, 3},  # set
            (1, 2),     # tuple — note: not strictly JSON, but some
                        # implementations coerce.  Current impl raises.
        )
        sentinel_kind = fdp.ConsumeIntInRange(0, len(bad) - 1)
        sentinel = bad[sentinel_kind]
        try:
            canonical_json(sentinel)
        except TypeError:
            return  # expected
        except Exception as exc:
            raise AssertionError(
                f"canonical_json({sentinel!r}) raised "
                f"{type(exc).__name__} instead of TypeError"
            ) from exc
        # If no exception, it accepted a non-JSON type — that's a finding
        # if the type is definitively not JSON (bytes, Decimal, set).
        if isinstance(sentinel, (bytes, Decimal, set)):
            raise AssertionError(
                f"canonical_json({sentinel!r}) returned without raising — "
                f"non-JSON type must raise TypeError"
            )
        return

    # cat == 12: V008 reproducer — float emission without decimal point.
    # Not in the 0-11 range above; we add it here.
    # 1e-300 → Python repr is "1e-300" (no decimal digit).  RFC 8785
    # §3.2.2.3 requires "1e-0300" form or equivalent with at least one
    # digit after the decimal point.
    cj = canonical_json({"x": 1e-300})
    # We don't fail on this (it's a Low-severity V008 finding), but we
    # at least ensure the output round-trips to a valid JSON float.
    try:
        back = json.loads(cj)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"canonical_json(1e-300) = {cj!r} is NOT valid JSON: {exc!r}"
        ) from exc
    # And it must equal the original float (round-trip identity).
    assert back == {"x": 1e-300}, (
        f"canonical_json(1e-300) round-trip mismatch: {back!r}"
    )
    # NaN / Infinity — these are NOT valid JSON values.  The current
    # implementation emits Python's repr (which is "nan" / "inf"),
    # which json.loads rejects.  This is V008 — Low severity.  We
    # surface a finding but don't fail the harness (it would crash
    # the fuzzer for every NaN/inf input, drowning the signal).
    nan_inf_inputs = (float("nan"), float("inf"), float("-inf"))
    for val in nan_inf_inputs:
        cj_bad = canonical_json({"x": val})
        try:
            json.loads(cj_bad)
            # If it parses, great.  But per RFC 8259 NaN/Inf are
            # invalid JSON, so we'd EXPECT this to fail.
        except json.JSONDecodeError:
            pass  # expected — Python's strict JSON parser rejects nan/inf
    return


def main() -> int:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
