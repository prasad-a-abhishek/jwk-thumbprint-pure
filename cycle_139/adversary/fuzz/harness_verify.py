"""Atheris harness for the ``verify()`` surface (Surface 2).

Surface 2 of the cycle_139 adversary workstream.

Exercises :func:`jwk_thumbprint_pure.verify` — the oracle that returns
``True`` iff the JWK's computed thumbprint matches ``expected``.
This surface is where the VULN_AUDIT findings V001 (not constant-time),
V002 (RecursionError propagation), and V003 (error-masking) live.

Specifically we test:

* ``verify(valid_jwk, correct_thumbprint) is True`` — round-trip must
  hold.
* ``verify(valid_jwk, wrong_thumbprint) is False`` — wrong thumbprint
  must NOT validate.
* ``verify(non_dict_jwk, anything) is False`` — non-dict input must
  NOT crash; ``verify`` may swallow exceptions (it currently does for
  ValueError/TypeError only).
* ``verify(deeply_nested_jwk, anything) is False`` — V002 reproducer:
  the ``verify()`` catch tuple is ``(ValueError, TypeError)`` so
  ``RecursionError`` MUST propagate.  This is the documented DoS.
* ``verify(jwk, None) is False`` — None expected thumbprint.
* Empty-string ``expected`` must return False (not True via length
  mismatch).
* Length-mismatched ``expected`` (40 / 50 / 100 chars) must return
  False without raising.
* Charset-mismatched ``expected`` (contains non-Base64URL chars) must
  return False without raising.
* Mixed-type / Decimal / bytes JWKs must return False (V009 reproducer
  — verify catches TypeError so this should be clean, but we want
  regression coverage).

Run::

    python3 harness_verify.py -atheris_runs=100000 -max_total_time=5
"""
from __future__ import annotations

import sys

import atheris  # type: ignore[import-not-found]

with atheris.instrument_imports():  # type: ignore[attr-defined]
    from jwk_thumbprint_pure import (  # noqa: E402
        thumbprint,
        verify,
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


_KTY_LIST = ("RSA", "EC", "oct", "OKP")


@atheris.instrument_func  # type: ignore[attr-defined]
def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)  # type: ignore[attr-defined]

    cat = fdp.ConsumeIntInRange(0, 7)

    if cat == 0:
        # === Round-trip: verify(valid_jwk, correct_thumb) is True ===
        kty = _KTY_LIST[fdp.ConsumeIntInRange(0, len(_KTY_LIST) - 1)]
        jwk = _seed_jwk(kty)
        try:
            expected = thumbprint(jwk)
        except Exception as exc:
            raise AssertionError(
                f"thumbprint({jwk!r}) raised {type(exc).__name__}: "
                f"{exc!r} on a valid-shape JWK"
            ) from exc
        try:
            ok = verify(jwk, expected)
        except Exception as exc:
            raise AssertionError(
                f"verify({jwk!r}, {expected!r}) raised "
                f"{type(exc).__name__}: {exc!r} — round-trip must not raise"
            ) from exc
        assert ok is True, (
            f"verify({jwk!r}, {expected!r}) = False — round-trip must be True"
        )

        # === Wrong thumbprint must be False ===
        wrong = "wrong-thumbprint-value"
        try:
            ok2 = verify(jwk, wrong)
        except Exception as exc:
            raise AssertionError(
                f"verify({jwk!r}, {wrong!r}) raised "
                f"{type(exc).__name__}: {exc!r} — wrong-thumbprint must "
                f"return False, not raise"
            ) from exc
        assert ok2 is False, (
            f"verify({jwk!r}, {wrong!r}) = True — wrong thumbprint must "
            f"return False"
        )

        # === Mutate one char of the correct thumbprint — must be False ===
        if expected:
            # Flip one bit of one character.
            pos = fdp.ConsumeIntInRange(0, len(expected) - 1)
            orig_c = expected[pos]
            new_c = "B" if orig_c != "B" else "A"
            mutated = expected[:pos] + new_c + expected[pos + 1:]
            assert mutated != expected
            ok3 = verify(jwk, mutated)
            assert ok3 is False, (
                f"verify({jwk!r}, {mutated!r}) = True — single-char-mutated "
                f"thumbprint must return False"
            )
        return

    if cat == 1:
        # === V002 reproducer: deeply-nested JWK must NOT propagate
        #     RecursionError out of verify().  Currently it DOES. ===
        depth = fdp.ConsumeIntInRange(350, 600)
        # Wrap a leaf value depth times in nested lists.
        leaf = "leaf"
        for _ in range(depth):
            leaf = [leaf]
        # Use an unknown kty so the filter passes all members through.
        jwk = {"kty": "ZZZ", "k": "AAAA", "wrap": leaf}
        try:
            ok = verify(jwk, "any")
        except RecursionError as exc:
            raise AssertionError(
                f"V002 REPRODUCED: verify(depth={depth}) leaked "
                f"RecursionError ({exc!r}) — verify() must catch "
                f"RecursionError and return False (DoS surface)"
            ) from exc
        except (ValueError, TypeError):
            return  # OK if verify() eventually rejects via that path
        except Exception as exc:
            # Some other exception class — also a finding, but a
            # different bug.  We allow it through atheris's exception
            # logging but DON'T raise (which would halt the fuzzer).
            # Re-raise to surface it.
            raise AssertionError(
                f"verify(depth={depth}) leaked {type(exc).__name__}: "
                f"{exc!r} — verify() must be exception-safe"
            ) from exc
        assert ok is False, (
            f"verify(depth={depth}) = True — deeply-nested JWK must "
            f"return False"
        )
        return

    if cat == 2:
        # === Non-dict JWK → False (verify() catches (ValueError, TypeError)) ===
        sentinel_kind = fdp.ConsumeIntInRange(0, 5)
        sentinels = (None, b"bytes", [1, 2, 3], "str", 42, 3.14)
        sentinel = sentinels[sentinel_kind]
        try:
            ok = verify(sentinel, "any")  # type: ignore[arg-type]
        except Exception as exc:
            raise AssertionError(
                f"verify({sentinel!r}, ...) raised {type(exc).__name__}: "
                f"{exc!r} — verify() must be exception-safe"
            ) from exc
        assert ok is False, (
            f"verify({sentinel!r}, ...) = True — non-dict must return False"
        )
        return

    if cat == 3:
        # === None expected thumbprint ===
        kty = _KTY_LIST[fdp.ConsumeIntInRange(0, len(_KTY_LIST) - 1)]
        jwk = _seed_jwk(kty)
        try:
            ok = verify(jwk, None)  # type: ignore[arg-type]
        except Exception as exc:
            raise AssertionError(
                f"verify({jwk!r}, None) raised {type(exc).__name__}: "
                f"{exc!r} — verify() must be exception-safe"
            ) from exc
        assert ok is False, (
            f"verify({jwk!r}, None) = True — None expected must be False"
        )
        return

    if cat == 4:
        # === Length-mismatched expected ===
        kty = _KTY_LIST[fdp.ConsumeIntInRange(0, len(_KTY_LIST) - 1)]
        jwk = _seed_jwk(kty)
        # Lengths other than 43.
        target_len = fdp.PickValueInList([0, 1, 5, 10, 20, 42, 44, 50, 100])
        expected_wrong = "A" * target_len
        try:
            ok = verify(jwk, expected_wrong)
        except Exception as exc:
            raise AssertionError(
                f"verify({jwk!r}, len={target_len}) raised "
                f"{type(exc).__name__}: {exc!r} — length-mismatched must "
                f"return False"
            ) from exc
        assert ok is False, (
            f"verify({jwk!r}, len={target_len}) = True — length mismatch "
            f"must return False"
        )
        return

    if cat == 5:
        # === Charset-mismatched expected (43 chars but non-Base64URL) ===
        kty = _KTY_LIST[fdp.ConsumeIntInRange(0, len(_KTY_LIST) - 1)]
        jwk = _seed_jwk(kty)
        # 43 chars with non-Base64URL content.
        weird = "!" * 43
        try:
            ok = verify(jwk, weird)
        except Exception as exc:
            raise AssertionError(
                f"verify({jwk!r}, charset-mismatched) raised "
                f"{type(exc).__name__}: {exc!r}"
            ) from exc
        assert ok is False, (
            f"verify({jwk!r}, charset-mismatched) = True"
        )
        return

    if cat == 6:
        # === V009 reproducer: mixed-type / Decimal / bytes JWK ===
        from decimal import Decimal
        kind = fdp.ConsumeIntInRange(0, 2)
        if kind == 0:
            jwk = {"kty": "ZZZ", 0: "zero", "k": "v"}
        elif kind == 1:
            jwk = {"kty": "ZZZ", "k": "v", "v": Decimal("1.5")}
        else:
            jwk = b"not-a-dict"  # type: ignore[dict-item]
        try:
            ok = verify(jwk, "any")  # type: ignore[arg-type]
        except Exception as exc:
            # V009: TypeError leaking from verify().  This is documented
            # as a Medium (V003) finding — verify() DOES catch TypeError
            # in the current implementation, so we should see False here.
            # If we see anything but False, surface it.
            raise AssertionError(
                f"verify() leaked {type(exc).__name__}: {exc!r} — must "
                f"return False for malformed JWKs"
            ) from exc
        assert ok is False
        return

    # cat == 7
    # === Algorithm confusion: bad alg → False (verify catches ValueError) ===
    jwk = _seed_jwk("oct")
    bad_algs = ("", "SHA-1", "MD5", "sha-256", "SHA256")
    alg = bad_algs[fdp.ConsumeIntInRange(0, len(bad_algs) - 1)]
    try:
        ok = verify(jwk, "any", alg=alg)  # type: ignore[arg-type]
    except Exception as exc:
        raise AssertionError(
            f"verify(bad alg={alg!r}) leaked {type(exc).__name__}: "
            f"{exc!r} — verify() must return False"
        ) from exc
    assert ok is False, (
        f"verify(jwk, ..., alg={alg!r}) = True — bad alg must be False"
    )


def main() -> int:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
