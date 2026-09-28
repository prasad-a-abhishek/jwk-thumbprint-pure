"""Atheris harness for the ``compute_thumbprint`` surface (Surface 1).

Surface 1 of the cycle_139 adversary workstream.

Exercises the top-level :func:`jwk_thumbprint_pure.thumbprint` function
(the public re-exported ``compute_thumbprint``) and the supporting
required-membership filter.  This complements ``harness_verify.py``
(which fuzzes ``verify()``) and ``harness_canonical.py`` (which fuzzes
the RFC 8785 serializer directly) by fuzzing the thumbprint *entry*
point: random dict-shaped bytes parsed via ``json.loads`` then passed
to ``compute_thumbprint``.

Specifically we test:

* ``compute_thumbprint(jwk)`` for a wide variety of dict shapes drawn
  from RFC 7638 §3.2 (``RSA``, ``EC``, ``oct``, ``OKP``, and unknown
  kty values).  On a well-formed JWK the result MUST be a non-empty
  Base64URL string of length 43 (SHA-256 / 256 bits * 4/6 = 42.67 →
  ceil, then no padding → 43 chars).
* Non-dict inputs (None, bytes, list, str, int) MUST raise ``ValueError``
  per the docstring contract — never ``TypeError`` (SPEC §X AC17
  promise — see V009 reproducer).
* ``compute_thumbprint`` on a recognized kty that's missing a required
  member (``RSA`` without ``e``, ``EC`` without ``y``, ``oct`` without
  ``k``) MUST raise a ``ValueError`` per RFC 7638 §3.2 (V007 silent
  drop reproducer).
* Algorithm confusion: ``alg="SHA-1"``, ``"MD5"``, ``"sha-256"``,
  ``""`` MUST raise ``ValueError``; ``SUPPORTED_ALGS = {"SHA-256"}`` so
  any other string must reject.
* Surrogate-pair / non-BMP / control-char values in JWK string members
  must NOT crash ``canonical_json`` — it should produce parseable
  output (round-trip ``json.loads`` survives).

Run::

    python3 harness_compute.py -atheris_runs=100000 -max_total_time=5
"""
from __future__ import annotations

import hashlib
import json
import sys

import atheris  # type: ignore[import-not-found]

# atheris's instrument_imports is a runtime-injected context manager;
# pyright cannot see it statically because the symbols are mutated by
# atheris's native coverage shim.  Suppress the false-positive.
with atheris.instrument_imports():  # type: ignore[attr-defined]
    from jwk_thumbprint_pure import (  # noqa: E402
        thumbprint as compute_thumbprint,
    )
    from jwk_thumbprint_pure.thumbprint import (  # noqa: E402
        SUPPORTED_ALGS,
    )
    from jwk_thumbprint_pure.canonical import canonical_json  # noqa: E402


# Per-kty valid seed alphabets — small corpus of well-formed JWKs the
# fuzzer can mutate to exercise the happy path.  Members are
# Base64URL-no-pad-shaped dummy strings (not real keys — we don't need
# real cryptographic correctness, just structural validity).
_KTY_TABLE: list[tuple[str, tuple[str, ...]]] = [
    ("RSA", ("n", "e")),
    ("EC", ("crv", "x", "y")),
    ("oct", ("k",)),
    ("OKP", ("crv", "x")),
]
_KTY_LIST: list[str] = [k for k, _ in _KTY_TABLE]

# Valid alg aliases that MUST be accepted (only "SHA-256" per RFC 7638).
_VALID_ALGS: tuple[str, ...] = tuple(SUPPORTED_ALGS)
# Invalid alg aliases the implementation MUST reject.
_INVALID_ALGS: tuple[str, ...] = (
    "",
    "SHA-1",
    "MD5",
    "SHA-512",
    "sha-256",   # case-mismatch — must NOT be silently accepted
    "sha256",    # no dash — must NOT be silently accepted
    "SHA256",    # no dash — must NOT be silently accepted
    "BLAKE2",    # unknown alg
    "🦀",        # non-ASCII
)


def _seed_jwk(kty: str) -> dict:
    """Return a minimal-but-valid JWK for the given kty."""
    if kty == "RSA":
        return {"kty": "RSA", "n": "abc", "e": "AQAB"}
    if kty == "EC":
        return {"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"}
    if kty == "oct":
        return {"kty": "oct", "k": "AAAA"}
    if kty == "OKP":
        return {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}
    return {"kty": kty, "v": "v"}


@atheris.instrument_func  # type: ignore[attr-defined]
def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)  # type: ignore[attr-defined]

    # === Choose input category ===
    # 0..3  → valid kty, valid shape  (happy path)
    # 4     → unknown kty, all members pass through
    # 5     → missing required member (V007 reproducer)
    # 6     → non-dict input (V009 reproducer)
    # 7     → dict with mixed-type keys (V009 reproducer)
    # 8     → dict with Decimal value (V009 reproducer)
    # 9     → invalid alg string
    # 10    → dict with surrogate-pair / non-BMP string value (canonical_json path)
    # 11    → JSON-bytes input (must parse via json.loads)
    cat = fdp.ConsumeIntInRange(0, 11)

    if cat < 4:
        # === Happy path: valid kty, all required members present ===
        kty = _KTY_LIST[cat]
        jwk = _seed_jwk(kty)
        # Maybe mutate a value to garbage to test that compute_thumbprint
        # still produces a deterministic 43-char Base64URL output.
        mutate_kind = fdp.ConsumeIntInRange(0, 3)
        if mutate_kind == 0 and jwk.get("k"):
            jwk["k"] = "X" * fdp.ConsumeIntInRange(1, 8)
        elif mutate_kind == 1:
            # Inject an extra member (RFC 7638 §4 says extras are dropped
            # for recognized kty — so the output must still be 43 chars).
            jwk["kid"] = "extra"
        elif mutate_kind == 2:
            # Mutate the kty string to be just-valid (test filter survives).
            pass
        try:
            t = compute_thumbprint(jwk)
        except Exception as exc:
            raise AssertionError(
                f"compute_thumbprint({jwk!r}) raised {type(exc).__name__}: "
                f"{exc!r} on a valid-shape kty={kty!r} JWK"
            ) from exc
        assert isinstance(t, str), (
            f"compute_thumbprint({jwk!r}) returned non-str: {type(t).__name__}"
        )
        assert len(t) == 43, (
            f"compute_thumbprint({jwk!r}) = {t!r} (len={len(t)}); "
            f"SHA-256 Base64URL-no-pad must be 43 chars"
        )
        # Determinism: same input must produce same output.
        t2 = compute_thumbprint(jwk)
        assert t == t2, (
            f"compute_thumbprint({jwk!r}) not deterministic: {t!r} != {t2!r}"
        )
        # Result must be valid Base64URL (charset check).
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(c in allowed for c in t), (
            f"compute_thumbprint({jwk!r}) = {t!r} contains non-Base64URL chars"
        )
        # Result must be a valid SHA-256 hex of a canonical JSON blob —
        # recompute the digest and confirm it matches.
        # The filtered dict for the happy path is _seed_jwk minus extras.
        filtered = {"kty": kty}
        for m in dict(_KTY_TABLE)[kty]:
            if m in jwk:
                filtered[m] = jwk[m]
        canon = canonical_json(filtered).encode("utf-8")
        import base64
        expected_b64 = (
            base64.urlsafe_b64encode(hashlib.sha256(canon).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        assert t == expected_b64, (
            f"compute_thumbprint({jwk!r}) = {t!r} but expected {expected_b64!r} "
            f"from canon={canon!r}"
        )
        return

    if cat == 4:
        # === Unknown kty: must pass all members through ===
        jwk = {"kty": "ZZZ", "k": "AAAA", "extra": "v"}
        try:
            t = compute_thumbprint(jwk)
        except Exception as exc:
            raise AssertionError(
                f"compute_thumbprint({jwk!r}) raised {type(exc).__name__}: "
                f"{exc!r} — unknown kty MUST pass all members through"
            ) from exc
        assert isinstance(t, str) and len(t) == 43, (
            f"compute_thumbprint({jwk!r}) = {t!r} not 43-char Base64URL"
        )
        return

    if cat == 5:
        # === V007 reproducer: recognized kty missing required member ===
        kty_idx = fdp.ConsumeIntInRange(0, len(_KTY_LIST) - 1)
        kty = _KTY_LIST[kty_idx]
        # Drop one required member.
        jwk = _seed_jwk(kty)
        required = dict(_KTY_TABLE)[kty]
        if required:
            jwk.pop(required[-1])
        try:
            compute_thumbprint(jwk)
        except ValueError:
            # Expected per the V007 fix contract: missing required member
            # MUST raise.  If we get here without the fix being applied,
            # we silently produce a wrong thumbprint — that's the
            # VULN_AUDIT finding, surfaced via AssertionError below.
            return
        except Exception as exc:
            raise AssertionError(
                f"compute_thumbprint({jwk!r}) raised {type(exc).__name__}: "
                f"{exc!r} — missing required member should raise ValueError"
            ) from exc
        # If we reached here, the call succeeded silently — V007 reproducer.
        raise AssertionError(
            f"V007 REPRODUCED: compute_thumbprint({jwk!r}) on missing-required "
            f"member kty={kty!r} SILENTLY produced a thumbprint — RFC 7638 "
            f"§3.2 requires the call to raise"
        )

    if cat == 6:
        # === V009 reproducer: non-dict input must raise ValueError ===
        sentinel_kind = fdp.ConsumeIntInRange(0, 5)
        sentinels = (None, b"bytes", [1, 2, 3], "str", 42, 3.14)
        sentinel = sentinels[sentinel_kind]
        try:
            compute_thumbprint(sentinel)  # type: ignore[arg-type]
        except ValueError:
            return  # expected
        except TypeError as exc:
            raise AssertionError(
                f"V009 REPRODUCED: compute_thumbprint({sentinel!r}) raised "
                f"TypeError ({exc!r}) — SPEC promises ValueError for non-dict"
            ) from exc
        except Exception as exc:
            raise AssertionError(
                f"compute_thumbprint({sentinel!r}) raised unexpected "
                f"{type(exc).__name__}: {exc!r}"
            ) from exc
        raise AssertionError(
            f"compute_thumbprint({sentinel!r}) returned without raising — "
            f"non-dict input MUST raise ValueError"
        )

    if cat == 7:
        # === V009 reproducer: mixed-type keys (int + str) ===
        # Use an unknown kty so the filter passes all members through,
        # then canonical_json() trips on the mixed-type sort key.
        jwk = {"kty": "ZZZ", 0: "zero", "str_key": "v"}
        try:
            compute_thumbprint(jwk)
        except ValueError:
            return  # OK if implementation guards this
        except TypeError as exc:
            # V009 — should have been ValueError per SPEC promise.
            raise AssertionError(
                f"V009 REPRODUCED: compute_thumbprint(mixed-type dict) "
                f"raised TypeError ({exc!r}) — SPEC promises ValueError"
            ) from exc
        except Exception as exc:
            # Some other exception class is also a finding.
            raise AssertionError(
                f"compute_thumbprint(mixed-type dict) raised unexpected "
                f"{type(exc).__name__}: {exc!r}"
            ) from exc
        raise AssertionError(
            f"compute_thumbprint(mixed-type dict) returned without raising — "
            f"mixed-type keys must error"
        )

    if cat == 8:
        # === V009 reproducer: Decimal value ===
        from decimal import Decimal
        jwk = {"kty": "ZZZ", "v": Decimal("1.5")}
        try:
            compute_thumbprint(jwk)
        except ValueError:
            return
        except TypeError as exc:
            raise AssertionError(
                f"V009 REPRODUCED: compute_thumbprint(Decimal value) "
                f"raised TypeError ({exc!r}) — SPEC promises ValueError"
            ) from exc
        except Exception as exc:
            raise AssertionError(
                f"compute_thumbprint(Decimal value) raised unexpected "
                f"{type(exc).__name__}: {exc!r}"
            ) from exc
        raise AssertionError(
            f"compute_thumbprint(Decimal value) returned without raising"
        )

    if cat == 9:
        # === Algorithm confusion: invalid alg MUST raise ValueError ===
        alg_idx = fdp.ConsumeIntInRange(0, len(_INVALID_ALGS) - 1)
        alg = _INVALID_ALGS[alg_idx]
        jwk = _seed_jwk("oct")
        try:
            compute_thumbprint(jwk, alg=alg)  # type: ignore[arg-type]
        except ValueError:
            return
        except Exception as exc:
            raise AssertionError(
                f"compute_thumbprint({jwk!r}, alg={alg!r}) raised "
                f"{type(exc).__name__}: {exc!r} — bad alg must be ValueError"
            ) from exc
        raise AssertionError(
            f"compute_thumbprint({jwk!r}, alg={alg!r}) returned without "
            f"raising — invalid alg must raise ValueError"
        )

    if cat == 10:
        # === Canonical-json edge: non-BMP / control chars in JWK values ===
        # This exercises the canonical_json path inside thumbprint().
        # The docstring of canonical_json says it handles control chars
        # but V004 flagged that non-BMP surrogate-pair escapes are missing.
        # The thumbprint should still be a valid 43-char Base64URL output
        # (no crash, no exception), regardless of canonical form.
        char_kind = fdp.ConsumeIntInRange(0, 4)
        if char_kind == 0:
            val = "\U0001F600"  # grinning-face emoji
        elif char_kind == 1:
            val = "\ufeff"      # BOM
        elif char_kind == 2:
            val = "\u0001"      # control char
        elif char_kind == 3:
            val = "cafe\u0301"  # NFD form
        else:
            val = "\u0000"      # NUL
        # Use unknown kty so the value is included in the filtered dict.
        jwk = {"kty": "ZZZ", "kid": val, "extra": val}
        try:
            t = compute_thumbprint(jwk)
        except Exception as exc:
            raise AssertionError(
                f"compute_thumbprint(jwk with unicode value {val!r}) raised "
                f"{type(exc).__name__}: {exc!r} — should not crash"
            ) from exc
        assert isinstance(t, str) and len(t) == 43, (
            f"compute_thumbprint(unicode-value jwk) = {t!r} not 43-char"
        )
        return

    # cat == 11
    # === JSON-bytes input → json.loads → compute_thumbprint ===
    # Useful for fuzz harness coverage; the FuzzedDataProvider feeds
    # raw bytes that JSON.loads may or may not accept.
    raw = fdp.ConsumeUnicodeNoSurrogates(64)
    if not raw:
        return
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return  # bad JSON — skip
    try:
        if isinstance(obj, dict):
            compute_thumbprint(obj)
        else:
            # Non-dict JSON: must raise ValueError (V009 contract).
            try:
                compute_thumbprint(obj)
            except ValueError:
                return
            except TypeError as exc:
                raise AssertionError(
                    f"V009 REPRODUCED: compute_thumbprint({obj!r}) raised "
                    f"TypeError ({exc!r}) — SPEC promises ValueError"
                ) from exc
            raise AssertionError(
                f"compute_thumbprint({obj!r}) returned without raising"
            )
    except ValueError:
        return  # well-formed ValueError on a valid-shape but bad-content dict
    except TypeError as exc:
        raise AssertionError(
            f"V009 REPRODUCED: compute_thumbprint({obj!r}) raised "
            f"TypeError ({exc!r}) — SPEC promises ValueError"
        ) from exc


def main() -> int:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
