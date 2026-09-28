#!/usr/bin/env python3
"""Minimized reproducer for F-001-V009.

VULN_AUDIT V009: compute_thumbprint() raises TypeError for dict
inputs that contain mixed-type keys (int + str).  SPEC AC17
promises a clean ValueError.

Run:
    python3 minimized.py
Expected (after fix): ValueError
Actual (current bug): TypeError('<' not supported between
                      instances of 'int' and 'str')
"""
import sys
from jwk_thumbprint_pure import thumbprint as compute_thumbprint

# Unknown kty so the filter passes all members through.
jwk = {"kty": "ZZZ", 0: "zero", "str_key": "v"}
try:
    t = compute_thumbprint(jwk)
except TypeError as exc:
    print(f"BUG REPRODUCED: TypeError raised ({exc!r}); "
          f"SPEC promises ValueError for non-JSON-shape dict")
    sys.exit(1)
except ValueError as exc:
    print(f"FIXED: ValueError raised ({exc!r})")
    sys.exit(0)
print(f"UNEXPECTED: returned thumbprint {t!r} without raising")
sys.exit(2)
