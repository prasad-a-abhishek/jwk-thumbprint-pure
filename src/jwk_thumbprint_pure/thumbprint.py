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
        >>> jwk = {"kty":"RSA","n":"0vx7agoebGcQ...","e":"AQAB"}
        >>> t = thumbprint(jwk)
        >>> t == "NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo"
        True
    """
    if not isinstance(jwk, dict):
        raise ValueError("jwk must be a dict")
    if "kty" not in jwk:
        raise ValueError("JWK must contain 'kty' member")
    if alg not in SUPPORTED_ALGS:
        raise ValueError(f"Unsupported algorithm: {alg}. Supported: {sorted(SUPPORTED_ALGS)}")

    # Canonical JSON per RFC 8785 — sorts object keys lexicographically
    canon = canonical_json(jwk)

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
        >>> verify(jwk, "FQ0DupwPUYM-4P3GfX9P7sArvqLlLVmcH6O1SWNLu_o")
        True
    """
    try:
        actual = thumbprint(jwk, alg)
        return actual == expected
    except (ValueError, TypeError):
        return False
