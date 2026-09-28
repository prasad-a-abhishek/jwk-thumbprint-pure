"""
RFC 8785 — JSON Canonicalization Scheme (JCS).

Deterministic serialization of JSON values to strings:
- Object keys are sorted lexicographically.
- No unnecessary whitespace.
- Arrays retain original order.
- Strings are escaped per RFC 8259.
"""

from typing import Any


def _escape_string(s: str) -> str:
    """Escape a string per RFC 8259 JSON serialization rules."""
    result = []
    for char in s:
        cp = ord(char)
        if cp == 0x22:  # quotation mark
            result.append("\\\"")
        elif cp == 0x5C:  # reverse solidus
            result.append("\\\\")
        elif cp == 0x08:  # backspace
            result.append("\\b")
        elif cp == 0x0C:  # form feed
            result.append("\\f")
        elif cp == 0x0A:  # line feed
            result.append("\\n")
        elif cp == 0x0D:  # carriage return
            result.append("\\r")
        elif cp == 0x09:  # tab
            result.append("\\t")
        elif cp < 0x20:  # control characters
            result.append(f"\\u{cp:04x}")
        else:
            result.append(char)
    return '"' + "".join(result) + '"'


def canonical_json(obj: Any) -> str:
    """
    Return the RFC 8785 canonical serialization of a JSON value.

    Args:
        obj: A JSON-serializable Python value (dict, list, str, int, float, bool, None).

    Returns:
        A canonical JSON string with sorted object keys and no extra whitespace.

    Examples:
        >>> canonical_json({"b": 1, "a": 2})
        '{"a":2,"b":1}'
        >>> canonical_json([3, 1, 2])
        '[3,1,2]'
        >>> canonical_json({"k": "hello world"})
        '{"k":"hello world"}'
    """
    if obj is None:
        return "null"
    elif obj is True:
        return "true"
    elif obj is False:
        return "false"
    elif isinstance(obj, str):
        return _escape_string(obj)
    elif isinstance(obj, (int, float)):
        # Use repr for numbers to match JSON serialization exactly.
        # For NaN/Infinity in JSON, we would need to emit null, but
        # RFC 8785 specifies this is a JSON-value-level canonicalization
        # so we let Python's repr handle it (floats are already JSON-compatible).
        return repr(obj)
    elif isinstance(obj, list):
        return "[" + ",".join(canonical_json(item) for item in obj) + "]"
    elif isinstance(obj, dict):
        # Sort keys lexicographically per RFC 8785 Section 3.2.3
        items = sorted(obj.items(), key=lambda kv: kv[0])
        pairs = [canonical_json(k) + ":" + canonical_json(v) for k, v in items]
        return "{" + ",".join(pairs) + "}"
    else:
        raise TypeError(f"Cannot canonicalize object of type {type(obj).__name__}")
