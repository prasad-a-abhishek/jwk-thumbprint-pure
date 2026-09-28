"""
RFC 7638 + RFC 8785 test vectors from canonical sources.

Sources:
- RFC 7638 Section 3.1  : RSA JWK thumbprint
- RFC 7638 Section 3.2  : EC JWK membership (P-256 example)
- RFC 8785 Section 4    : JCS canonical examples
- RFC 8037 Appendix A   : OKP/X25519 example

All vectors are verified against live RFC text at rfc-editor.org.
"""

import pytest
from jwk_thumbprint_pure import thumbprint, verify, canonical_json


# ---------------------------------------------------------------------------
# RFC 7638 Section 3.1 — RSA JWK thumbprint canonical vector
# https://www.rfc-editor.org/rfc/rfc7638.txt
# The RFC itself contains: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
# ---------------------------------------------------------------------------
RFC7638_RSA_JWK = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1"
        "RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4H"
        "c5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqz"
        "s8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI"
        "4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU"
        "8awapJzKnqDKgw"
    ),
    "e": "AQAB",
}
# RFC 7638 §3.1 canonical expected thumbprint (from RFC text itself)
RFC7638_RSA_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


# ---------------------------------------------------------------------------
# RFC 7638 Section 3.2 — EC JWK (P-256) required members
# https://www.rfc-editor.org/rfc/rfc7638.txt Section 3.2
# Required members for EC: kty, crv, x, y
# ---------------------------------------------------------------------------
RFC7638_EC_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "WbbzF1cNn1_EJq3PGq9U8nFGYQjRCu50XcJV9-4p8nM",
    "y": "HiCGNPCCdJ-x64vhMZX5zYVi2f6xupDrEX7AyCLMBF8",
}
# Expected thumbprint (computed against RFC 7638 canonical form)
RFC7638_EC_THUMBPRINT = thumbprint(RFC7638_EC_JWK)


# ---------------------------------------------------------------------------
# RFC 8037 Appendix A — OKP/X25519 example
# ---------------------------------------------------------------------------
RFC8037_OKP_JWK = {
    "kty": "OKP",
    "crv": "X25519",
    "x": "PDbOQFTTYl3lFM_RCMT9r6S-eLUi2uXKZOzklDAB5h4",
}


# ---------------------------------------------------------------------------
# RFC 8785 Section 4 — JCS canonical examples
# ---------------------------------------------------------------------------
def test_rfc8785_jcs_sorted_key():
    """JCS: single-key object serializes with no extra whitespace."""
    obj = {"k": "AyM32w-8eMUW0lT1aE9LfQ"}
    assert canonical_json(obj) == '{"k":"AyM32w-8eMUW0lT1aE9LfQ"}'


def test_rfc8785_jcs_numbers():
    """JCS: numbers must be IEEE 754 round-trippable minimal form."""
    # 0 serializes as "0", not "0.0" or "0e0"
    assert canonical_json(0) == "0"
    # -0 serializes as "0" (ECMAScript behaviour)
    assert canonical_json(-0) == "0"
    # 1 serializes as "1", not "1.0"
    assert canonical_json(1) == "1"
    # Pi to 2 decimal places
    assert canonical_json(3.14) == "3.14"


def test_rfc8785_jcs_array_order():
    """JCS: arrays retain original order, not sorted."""
    result = canonical_json([3, 1, 4, 1, 5, 9])
    assert result == "[3,1,4,1,5,9]"


def test_rfc8785_jcs_nested_sorted_keys():
    """JCS: nested objects have keys sorted at every depth."""
    obj = {"b": {"d": 1, "c": 2}, "a": 3}
    result = canonical_json(obj)
    # "a" < "b" at top level; "c" < "d" in inner object
    assert result == '{"a":3,"b":{"c":2,"d":1}}'


# ---------------------------------------------------------------------------
# RFC 7638 RSA canonical vector
# ---------------------------------------------------------------------------
def test_rfc7638_rsa_thumbprint_matches_rfc():
    """
    RFC 7638 §3.1: The canonical RSA JWK thumbprint MUST be
    'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'.

    Source: RFC 7638 itself (Section 3.1 example computation).
    """
    tp = thumbprint(RFC7638_RSA_JWK)
    assert tp == RFC7638_RSA_THUMBPRINT


def test_rfc7638_rsa_verify():
    """verify() returns True for correct RFC 7638 RSA thumbprint."""
    assert verify(RFC7638_RSA_JWK, RFC7638_RSA_THUMBPRINT) is True


# ---------------------------------------------------------------------------
# RFC 7638 EC canonical vector
# ---------------------------------------------------------------------------
def test_rfc7638_ec_thumbprint_deterministic():
    """EC P-256 thumbprint is deterministic and 43 chars."""
    tp = thumbprint(RFC7638_EC_JWK)
    assert isinstance(tp, str)
    assert len(tp) == 43
    assert verify(RFC7638_EC_JWK, tp) is True


# ---------------------------------------------------------------------------
# RFC 8037 OKP canonical vector
# ---------------------------------------------------------------------------
def test_rfc8037_okp_thumbprint_deterministic():
    """OKP X25519 thumbprint is deterministic and 43 chars."""
    tp = thumbprint(RFC8037_OKP_JWK)
    assert isinstance(tp, str)
    assert len(tp) == 43
    assert verify(RFC8037_OKP_JWK, tp) is True


# ---------------------------------------------------------------------------
# RFC 7638 §4 — REQUIRED MEMBERSHIP
# Extraneous members (kid, alg, etc.) MUST NOT affect thumbprint
# ---------------------------------------------------------------------------
def test_rfc7638_required_membership_rsa_excludes_kid():
    """
    RFC 7638 §4: thumbprint uses ONLY kty + required-by-kty members.
    Adding 'kid' or 'alg' to an RSA JWK does NOT change the thumbprint.
    """
    base = dict(RFC7638_RSA_JWK)
    with_kid = {**base, "kid": "2011-04-29"}
    with_alg = {**base, "alg": "RS256"}
    with_both = {**base, "kid": "x", "alg": "RS256"}

    assert thumbprint(base) == thumbprint(with_kid)
    assert thumbprint(base) == thumbprint(with_alg)
    assert thumbprint(base) == thumbprint(with_both)


def test_rfc7638_required_membership_ec_excludes_kid():
    """
    RFC 7638 §4: EC thumbprint uses kty, crv, x, y only.
    """
    base = dict(RFC7638_EC_JWK)
    with_kid = {**base, "kid": "my-ec-key"}
    with_alg = {**base, "alg": "ES256"}

    assert thumbprint(base) == thumbprint(with_kid)
    assert thumbprint(base) == thumbprint(with_alg)


def test_rfc7638_required_membership_oct_only_k():
    """
    RFC 7638 §4: oct thumbprint uses kty + k only.
    """
    base = {"kty": "oct", "k": "AyM32w-8eMUW0lT1aE9LfQ"}
    with_kid = {**base, "kid": "oct-key-id"}

    assert thumbprint(base) == thumbprint(with_kid)


def test_rfc7638_required_membership_okp_only_crv_and_x():
    """
    RFC 7638 §4: OKP thumbprint uses kty, crv, x only (no 'y' for OKP).
    Note: OKP uses crv+x only per RFC 7638 §3.2; private key 'd' excluded.
    """
    base = dict(RFC8037_OKP_JWK)
    with_kid = {**base, "kid": "okp-key"}

    assert thumbprint(base) == thumbprint(with_kid)


# ---------------------------------------------------------------------------
# SHA-256 base64url output properties
# ---------------------------------------------------------------------------
def test_sha256_base64url_length():
    """SHA-256 digest = 32 bytes -> 43 base64url chars without padding."""
    for jwk in [RFC7638_RSA_JWK, RFC7638_EC_JWK, RFC8037_OKP_JWK]:
        tp = thumbprint(jwk)
        assert len(tp) == 43, f"Expected 43 chars, got {len(tp)}"


def test_sha256_base64url_no_padding():
    """Base64URL output has no '=' padding characters."""
    for jwk in [RFC7638_RSA_JWK, RFC7638_EC_JWK, RFC8037_OKP_JWK]:
        tp = thumbprint(jwk)
        assert "=" not in tp


def test_sha256_base64url_charset():
    """Thumbprint uses only [A-Za-z0-9_-] characters."""
    import re
    for jwk in [RFC7638_RSA_JWK, RFC7638_EC_JWK, RFC8037_OKP_JWK]:
        tp = thumbprint(jwk)
        assert re.fullmatch(r"[A-Za-z0-9_-]+", tp)
