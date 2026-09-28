"""
RFC 7638 — JWK Thumbprint computation.

The thumbprint of a JWK is the Base64URL-encoding of the
SHA-256 digest of the RFC 8785 canonical JSON serialization of the JWK.
"""

import hashlib
import base64
from dataclasses import dataclass
from typing import Optional

from jwk_thumbprint_pure.canonical import canonical_json


SUPPORTED_ALGS = {"SHA-256"}

# RFC 7638 Section 3.2 — required members per kty
# RSA: n, e  |  EC: crv, x, y  |  oct: k  |  OKP: crv, x
_REQUIRED_MEMBERS = {
    "RSA": ("n", "e"),
    "EC": ("crv", "x", "y"),
    "oct": ("k",),
    "OKP": ("crv", "x"),  # RFC 7638 §3.2: OKP uses crv+x only
    # RSA-OAEP (symmetric) and dir use only kty
}


@dataclass
class JWKThumbprint:
    """
    Result of a JWK thumbprint computation.

    Attributes:
        kty: The JWK "kty" (Key Type) parameter.
        thumbprint: The Base64URL-encoded thumbprint digest.
        alg: The hash algorithm used (currently only SHA-256).
    """
    kty: str
    thumbprint: str
    alg: str


def thumbprint(jwk: dict, alg: str = "SHA-256") -> str:
    """
    Compute the RFC 7638 JWK thumbprint.

    Args:
        jwk: A dict representation of a JSON Web Key.
             Must contain at minimum "kty".
             Other required members depend on kty (e.g., "n","e" for RSA;
             "crv","x","y" for EC; "k" for oct).
        alg: Hash algorithm name. Currently only "SHA-256" is defined by RFC 7638.

    Returns:
        Base64URL-encoded thumbprint with no padding (RFC 7638 Section 4).

    Raises:
        ValueError: If alg is not supported, jwk is not a dict, or jwk lacks kty.

    Examples:
        >>> jwk = {"kty":"RSA","n":"sXch4mfvVlMS-AzhmZ6P5w","e":"AQAB"}
        >>> t = thumbprint(jwk)
        >>> len(t) == 43  # SHA-256 Base64URL without padding
        True
        >>> t == thumbprint(jwk)  # deterministic
        True
    """
    if not isinstance(jwk, dict):
        raise ValueError("jwk must be a dict")
    if "kty" not in jwk:
        raise ValueError("JWK must contain 'kty' member")
    if alg not in SUPPORTED_ALGS:
        raise ValueError(f"Unsupported algorithm: {alg}. Supported: {sorted(SUPPORTED_ALGS)}")

    kty = jwk["kty"]

    # RFC 7638 §4: filter to kty + required-by-kty members.
    # For recognized kty values, only those required members are included.
    # For unrecognized kty values, pass through all members (RFC 7638
    # does not define required members for future kty values).
    if kty in _REQUIRED_MEMBERS:
        required = _REQUIRED_MEMBERS[kty]
        filtered = {"kty": kty}
        for member in required:
            if member in jwk:
                filtered[member] = jwk[member]
    else:
        # Unknown kty: include all members present in the JWK
        # (future spec must define required members for that kty)
        filtered = dict(jwk)

    # Canonical JSON per RFC 8785 — sorts object keys lexicographically
    canon = canonical_json(filtered)

    if alg == "SHA-256":
        digest = hashlib.sha256(canon.encode("utf-8")).digest()
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")

    # Base64URL encoding without padding (RFC 7638 Section 4)
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify(jwk: dict, expected: str, alg: str = "SHA-256") -> bool:
    """
    Verify a JWK thumbprint.

    Args:
        jwk: The JWK dict to verify.
        expected: Expected Base64URL thumbprint.
        alg: Hash algorithm (default SHA-256).

    Returns:
        True if the computed thumbprint equals expected (case-sensitive).
        False on any error (malformed jwk, unsupported alg, etc.).

    Examples:
        >>> jwk = {"kty":"EC","crv":"P-256","x":"WbbzF1cNn1_EJq3PGq9U8nFGYQjRCu50XcJV9-4p8nM","y":"HiCGNPCCdJ-x64vhMZX5zYVi2f6xupDrEX7AyCLMBF8"}
        >>> verify(jwk, "8gvatiX_LIBKyWtMaybQbDA54WNryx3TkpMSnbnlgmo")
        True
        >>> verify(jwk, "wrong")
        False
    """
    try:
        actual = thumbprint(jwk, alg)
        return actual == expected
    except (ValueError, TypeError):
        return False
