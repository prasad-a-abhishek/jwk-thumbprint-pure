#!/usr/bin/env python3
"""Minimized reproducer for F-002-V007.

VULN_AUDIT V007: compute_thumbprint() silently produces a
thumbprint for an RSA JWK missing the required 'e' member.
RFC 7638 §3.2 requires raising in this case.

Run:
    python3 minimized.py
Expected (after fix): ValueError (MISSING_REQUIRED_MEMBERS)
Actual (current bug): returns a thumbprint silently
"""
import sys
from jwk_thumbprint_pure import thumbprint as compute_thumbprint

jwk = {"kty": "RSA", "n": "abc"}  # missing required 'e'
try:
    t = compute_thumbprint(jwk)
except ValueError as exc:
    print(f"FIXED: ValueError raised ({exc!r})")
    sys.exit(0)
print(f"BUG REPRODUCED: silently produced thumbprint {t!r} "
      f"for malformed RSA JWK (missing required 'e')")
sys.exit(1)
