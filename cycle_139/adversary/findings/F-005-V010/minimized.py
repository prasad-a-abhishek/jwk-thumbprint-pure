#!/usr/bin/env python3
"""Minimized reproducer for F-005-V010.

VULN_AUDIT V010: canonical_json({True: 1}) produces '{true:1}'
which is NOT valid JSON (unquoted identifier as key).  The
function promises valid RFC 8785 JSON output but emits the
Python `True` token literally.

Run:
    python3 minimized.py
Expected (after fix): either a ValueError, or a valid JSON
                       string with the bool coerced to a string key
Actual (current bug): '{true:1}' — invalid JSON
"""
import json
import sys
from jwk_thumbprint_pure import canonical_json

out = canonical_json({True: 1})
print(f"canonical_json({{True: 1}}) = {out!r}")
try:
    back = json.loads(out)
    print(f"Round-trip parsed: {back!r} (valid JSON)")
    sys.exit(0)
except json.JSONDecodeError as exc:
    print(f"BUG REPRODUCED: output is NOT valid JSON: {exc!r}")
    sys.exit(1)
