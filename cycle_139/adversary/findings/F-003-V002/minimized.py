#!/usr/bin/env python3
"""Minimized reproducer for F-003-V002 (depth=470).

VULN_AUDIT V002: verify() catches only (ValueError, TypeError).
RecursionError propagates to the caller — a denial-of-service
surface for callers that accept JWKs from untrusted sources.

Run:
    python3 minimized.py
Expected (after fix): False (no exception)
Actual (current bug): RecursionError leaks out
"""
import sys
from jwk_thumbprint_pure import verify

# Build a deeply-nested JWK with unknown kty so the filter
# passes all members through.
leaf = "leaf"
for _ in range(470):
    leaf = [leaf]
jwk = {"kty": "ZZZ", "k": "AAAA", "wrap": leaf}
try:
    ok = verify(jwk, "any")
except RecursionError as exc:
    print(f"BUG REPRODUCED: RecursionError leaked "
          f"(depth=470, {exc!r}); verify() must catch "
          f"and return False (DoS surface)")
    sys.exit(1)
except (ValueError, TypeError) as exc:
    print(f"FIXED: caught as ValueError/TypeError ({exc!r}) "
          f"and returned {ok}")
    sys.exit(0)
print(f"UNEXPECTED: returned {ok} without raising")
sys.exit(2)
