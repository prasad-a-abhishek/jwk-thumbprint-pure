"""
Regression tests for verify() RecursionError DoS surface (cycle_139 fix1).

The two High findings (F-003-V002 / F-004-V002-mutated) emitted by
@repo-adversary both share the same root cause: verify() only caught
(ValueError, TypeError), so a deeply-nested JWK dict would propagate
RecursionError out of canonical_json() and crash the calling process
(denial-of-service surface for callers that accept JWKs from untrusted
sources such as JWKS responses or signed JWT headers).

The contract fix is narrow: verify() now also catches RecursionError
and returns False (boolean contract: True iff thumbprint matches).
These tests assert verify(...) == False on three independent
adversarial inputs, never the absence of an exception (a pass-by-
mismatch guard).
"""

from jwk_thumbprint_pure import verify


def _build_deeply_nested_jwk(depth: int) -> dict:
    """Build a JWK whose ``wrap`` member is a list nested ``depth`` times."""
    leaf = "leaf"
    for _ in range(depth):
        leaf = [leaf]
    # Unknown kty so the filter (RFC 7638 §4) passes ``wrap`` through
    # unchanged into canonical_json(), which is where the stack blows.
    return {"kty": "ZZZ", "k": "AAAA", "wrap": leaf}


class TestVerifyRecursion:
    """verify() must return False (not RecursionError) on adversarial inputs."""

    def test_f003_depth_470_returns_false(self):
        """F-003-V002: depth=470 nested list — was RecursionError, must be False."""
        jwk = _build_deeply_nested_jwk(depth=470)
        result = verify(jwk, "any")
        assert result is False, (
            f"verify() returned {result!r}; expected False on deeply-nested input"
        )

    def test_f004_depth_350_mutated_returns_false(self):
        """F-004-V002-mutated: depth=350 nested list — was RecursionError, must be False."""
        jwk = _build_deeply_nested_jwk(depth=350)
        result = verify(jwk, "any")
        assert result is False, (
            f"verify() returned {result!r}; expected False on adversarial input"
        )

    def test_self_referencing_dict_returns_false(self):
        """Cycle guard: jwk['self'] = jwk is a canonical_json() infinite recursion."""
        jwk = {"kty": "ZZZ", "k": "AAAA"}
        jwk["self"] = jwk
        result = verify(jwk, "any")
        assert result is False, (
            f"verify() returned {result!r}; expected False on self-referencing input"
        )

    def test_rfc7638_rsa_vector_still_matches(self):
        """Sanity: legitimate JWK with the canonical RFC 7638 §3.1 vector still verifies."""
        rfc7638_jwk = {
            "kty": "RSA",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"
                "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi"
                "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6"
                "Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb"
                "9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFT"
                "WhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls"
                "1jF44-csFCur-kEgU8awapJzKnqDKgw"
            ),
            "e": "AQAB",
        }
        # Per RFC 7638 §3.1 example
        assert verify(rfc7638_jwk, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs") is True
        # Wrong expected value must still return False cleanly
        assert verify(rfc7638_jwk, "not-a-thumbprint") is False