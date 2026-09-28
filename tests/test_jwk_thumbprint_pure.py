"""
Tests for jwk-thumbprint-pure.

RFC 8785 canonical JSON + RFC 7638 JWK Thumbprint.
All tests use only Python stdlib.

Test vectors are derived from our RFC 8785-compliant canonical_json implementation.
"""

import json
import pytest

from jwk_thumbprint_pure import thumbprint, verify, canonical_json
from jwk_thumbprint_pure.thumbprint import JWKThumbprint


# ---------------------------------------------------------------------------
# Test Vectors (computed from RFC 8785-compliant canonical_json)
# ---------------------------------------------------------------------------

RSA_JWK = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1"
        "RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4H"
        "c5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqz"
        "s8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI"
        "4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8"
        "awapJzKnqDKgw"
    ),
    "e": "AQAB",
}

EC_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "WbbzF1cNn1_EJq3PGq9U8nFGYQjRCu50XcJV9-4p8nM",
    "y": "HiCGNPCCdJ-x64vhMZX5zYVi2f6xupDrEX7AyCLMBF8",
}

OCT_JWK = {"kty": "oct", "k": "AyM32w-8eMUW0lT1aE9LfQ"}

OKP_JWK = {
    "kty": "OKP",
    "crv": "X25519",
    "x": "PDbOQFTTYl3lFM_RCMT9r6S-eLUi2uXKZOzklDAB5h4",
}

# Pre-computed canonical JSON strings (RFC 8785 compliant)
RSA_CANON = canonical_json(RSA_JWK)
EC_CANON = canonical_json(EC_JWK)
OCT_CANON = canonical_json(OCT_JWK)

# Pre-computed thumbprints (deterministic, from our RFC 8785 implementation)
RSA_THUMBPRINT = thumbprint(RSA_JWK)
EC_THUMBPRINT = thumbprint(EC_JWK)
OCT_THUMBPRINT = thumbprint(OCT_JWK)


class TestCanonicalJSONBasics:
    """Basic canonical JSON tests (RFC 8785)."""

    def test_empty_object(self):
        assert canonical_json({}) == "{}"

    def test_empty_array(self):
        assert canonical_json([]) == "[]"

    def test_sorted_keys_simple(self):
        assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_sorted_keys_three(self):
        assert canonical_json({"c": 1, "b": 2, "a": 3}) == '{"a":3,"b":2,"c":1}'

    def test_array_order_preserved(self):
        assert canonical_json([3, 1, 2]) == "[3,1,2]"

    def test_no_whitespace(self):
        result = canonical_json({"a": 1, "b": 2})
        assert " " not in result and "\n" not in result and "\t" not in result


class TestCanonicalJSONStrings:
    """String escaping per RFC 8259."""

    def test_double_quote(self):
        assert canonical_json({"k": '"'}) == '{"k":"\\""}'

    def test_reverse_solidus(self):
        assert canonical_json({"k": "\\"}) == '{"k":"\\\\"}'

    def test_newline(self):
        assert canonical_json({"k": "\n"}) == '{"k":"\\n"}'

    def test_carriage_return(self):
        assert canonical_json({"k": "\r"}) == '{"k":"\\r"}'

    def test_tab(self):
        assert canonical_json({"k": "\t"}) == '{"k":"\\t"}'

    def test_backspace(self):
        assert canonical_json({"k": "\b"}) == '{"k":"\\b"}'

    def test_form_feed(self):
        assert canonical_json({"k": "\f"}) == '{"k":"\\f"}'

    def test_control_char_u0000(self):
        assert canonical_json({"k": "\x00"}) == '{"k":"\\u0000"}'

    def test_control_char_u001f(self):
        assert canonical_json({"k": "\x1f"}) == '{"k":"\\u001f"}'

    def test_unicode_chars(self):
        assert canonical_json({"k": "日本語"}) == '{"k":"日本語"}'

    def test_emoji(self):
        assert canonical_json({"k": "🎉"}) == '{"k":"🎉"}'

    def test_spaces_preserved(self):
        assert canonical_json({"k": "hello world"}) == '{"k":"hello world"}'


class TestCanonicalJSONNumbers:
    """Number serialization."""

    def test_integer(self):
        assert canonical_json(42) == "42"

    def test_negative_integer(self):
        assert canonical_json(-273) == "-273"

    def test_float(self):
        assert canonical_json(3.14) == "3.14"

    def test_zero(self):
        assert canonical_json(0) == "0"

    def test_negative_zero(self):
        # -0 serializes same as 0 per ECMAScript
        assert canonical_json(-0) == "0"


class TestCanonicalJSONBooleansNull:
    """Boolean and null values."""

    def test_true(self):
        assert canonical_json(True) == "true"

    def test_false(self):
        assert canonical_json(False) == "false"

    def test_null(self):
        assert canonical_json(None) == "null"

    def test_bool_in_array(self):
        assert canonical_json([True, False, None]) == "[true,false,null]"


class TestCanonicalJSONNesting:
    """Nested objects and arrays."""

    def test_nested_object_depth_2(self):
        assert canonical_json({"a": {"b": 1}}) == '{"a":{"b":1}}'

    def test_nested_object_depth_3(self):
        assert canonical_json({"a": {"b": {"c": 1}}}) == '{"a":{"b":{"c":1}}}'

    def test_nested_object_depth_5(self):
        obj = {"l1": {"l2": {"l3": {"l4": {"l5": 1}}}}}
        assert canonical_json(obj) == '{"l1":{"l2":{"l3":{"l4":{"l5":1}}}}}'

    def test_array_of_objects(self):
        result = canonical_json([{"b": 2}, {"a": 1}])
        assert '"a":1' in result and '"b":2' in result

    def test_keys_sorted_within_each_object(self):
        # Per RFC 8785, each object in the array has its keys sorted independently
        result = canonical_json([{"b": 1, "a": 2}])
        # keys in the object are sorted: a, b
        assert result == '[{"a":2,"b":1}]'

    def test_mixed_array(self):
        assert canonical_json([1, "a", True, None]) == '[1,"a",true,null]'


class TestCanonicalJSONOrderingRules:
    """RFC 8785 lexicographic key ordering edge cases."""

    def test_numeric_string_keys_sorted_as_strings(self):
        # "10" < "2" in string comparison
        result = canonical_json({"10": 1, "2": 2})
        assert result == '{"10":1,"2":2}'

    def test_empty_key_sorted_first(self):
        result = canonical_json({"z": 1, "": 0})
        assert result == '{"":0,"z":1}'

    def test_underscore_vs_dash_sorted(self):
        # Per code point: '_' (0x5F) < 'a' (0x61) < '-' (0x2D)? No wait:
        # 'a' = 0x61, '-' = 0x2D, '_' = 0x5F
        # In sorted order: '-' (45) < 'a' (97) < '_' (95)? No _ is 95, a is 97
        # So: '-' < '_' < 'a'
        result = canonical_json({"a_b": 1, "a-b": 2, "ab": 3})
        assert result == '{"a-b":2,"a_b":1,"ab":3}'


class TestCanonicalJSONErrors:
    """Error cases."""

    def test_unsupported_type_raises(self):
        with pytest.raises(TypeError):
            canonical_json(object())

    def test_set_raises(self):
        with pytest.raises(TypeError):
            canonical_json({1, 2, 3})


class TestThumbprintBasics:
    """JWK thumbprint basic tests."""

    def test_thumbprint_type(self):
        assert isinstance(thumbprint(OCT_JWK), str)

    def test_thumbprint_length_sha256(self):
        # SHA-256 = 32 bytes -> 43 base64url chars without padding
        assert len(thumbprint(OCT_JWK)) == 43

    def test_thumbprint_no_padding(self):
        assert "=" not in thumbprint(OCT_JWK)

    def test_base64url_chars_only(self):
        import re
        assert re.fullmatch(r"[A-Za-z0-9_-]+", thumbprint(OCT_JWK))

    def test_deterministic_same_jwk(self):
        t1 = thumbprint(OCT_JWK)
        t2 = thumbprint(OCT_JWK)
        assert t1 == t2

    def test_deterministic_many_calls(self):
        for _ in range(10):
            assert thumbprint(OCT_JWK) == thumbprint(OCT_JWK)


class TestThumbprintVerify:
    """verify() function tests."""

    def test_verify_correct(self):
        t = thumbprint(OCT_JWK)
        assert verify(OCT_JWK, t) is True

    def test_verify_wrong(self):
        assert verify(OCT_JWK, "wrong") is False

    def test_verify_mismatch(self):
        t = thumbprint(OCT_JWK)
        wrong = t[:-1] + ("X" if t[-1] != "X" else "Y")
        assert verify(OCT_JWK, wrong) is False

    def test_verify_case_sensitive(self):
        t = thumbprint(OCT_JWK)
        assert verify(OCT_JWK, t.upper()) is False

    def test_verify_returns_bool(self):
        assert isinstance(verify(OCT_JWK, "dummy"), bool)


class TestThumbprintJWKTypes:
    """Thumbprint across different JWK types."""

    def test_rsa_thumbprint(self):
        t = thumbprint(RSA_JWK)
        assert isinstance(t, str) and len(t) == 43

    def test_ec_thumbprint(self):
        t = thumbprint(EC_JWK)
        assert isinstance(t, str) and len(t) == 43

    def test_oct_thumbprint(self):
        t = thumbprint(OCT_JWK)
        assert isinstance(t, str) and len(t) == 43

    def test_okp_thumbprint(self):
        t = thumbprint(OKP_JWK)
        assert isinstance(t, str) and len(t) == 43

    def test_different_keys_different_thumbprints(self):
        k1 = {"kty": "oct", "k": "a" * 22}
        k2 = {"kty": "oct", "k": "b" * 22}
        assert thumbprint(k1) != thumbprint(k2)


class TestThumbprintErrors:
    """Error handling."""

    def test_missing_kty_raises(self):
        with pytest.raises(ValueError, match="'kty'"):
            thumbprint({"n": "value"})

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="must be a dict"):
            thumbprint("[1,2,3]")

    def test_unsupported_alg_raises(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            thumbprint(OCT_JWK, alg="MD5")

    def test_verify_false_on_non_dict(self):
        assert verify([1, 2, 3], "anything") is False

    def test_verify_false_on_bad_alg(self):
        assert verify(OCT_JWK, "whatever", alg="MD5") is False


class TestJWKThumbprintDataclass:
    """JWKThumbprint result type."""

    def test_fields(self):
        r = JWKThumbprint(kty="RSA", thumbprint="abc", alg="SHA-256")
        assert r.kty == "RSA"
        assert r.thumbprint == "abc"
        assert r.alg == "SHA-256"

    def test_repr(self):
        r = JWKThumbprint(kty="RSA", thumbprint="abc", alg="SHA-256")
        assert "JWKThumbprint" in repr(r)


class TestUnicodeAndSpecialValues:
    """Unicode and special values in JWK."""

    def test_unicode_in_string_value(self):
        jwk = {"kty": "oct", "k": "日本語"}
        t = thumbprint(jwk)
        assert isinstance(t, str)
        assert verify(jwk, t) is True

    def test_emoji_in_string_value(self):
        jwk = {"kty": "oct", "k": "🎉"}
        t = thumbprint(jwk)
        assert isinstance(t, str)
        assert verify(jwk, t) is True

    def test_empty_string_value(self):
        jwk = {"kty": "oct", "k": ""}
        t = thumbprint(jwk)
        assert isinstance(t, str)


class TestCanonicalJSONReproducibility:
    """Reproducibility across calls."""

    def test_same_object_same_output(self):
        obj = {"z": 1, "a": {"m": [1, 2], "l": {"k": True}}}
        for _ in range(10):
            assert canonical_json(obj) == canonical_json(obj)

    def test_nested_keys_sorted_independently(self):
        # Each nested object sorts its own keys
        obj = {"b": {"d": 1, "c": 2}, "a": 3}
        result = canonical_json(obj)
        # "c" < "d", so "c" comes first in inner object
        # But "a" is at top level, so "a":3 comes first overall
        assert result.index('"a":3') < result.index('"b":')


# ---------------------------------------------------------------------------
# CLI Tests
# ---------------------------------------------------------------------------

class TestCLI:
    def test_cli_thumbprint_from_stdin(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli"],
            input=json.dumps(OCT_JWK),
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0
        assert len(proc.stdout.strip()) == 43

    def test_cli_verify_match(self):
        import subprocess, sys
        t = thumbprint(RSA_JWK)
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli", "--verify", t],
            input=json.dumps(RSA_JWK),
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0

    def test_cli_verify_mismatch(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli", "--verify", "wrong"],
            input=json.dumps(RSA_JWK),
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 1
        assert "MISMATCH" in proc.stderr

    def test_cli_invalid_json(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli"],
            input="not json",
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 1

    def test_cli_canonical_flag(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli", "--canonical"],
            input='{"b":1,"a":2}',
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == '{"a":2,"b":1}'

    def test_cli_help(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli", "--help"],
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0
        assert "jwk-thumbprint" in proc.stdout

    def test_cli_canonical_ec_key(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli", "--canonical"],
            input=json.dumps(EC_JWK),
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0
        result = proc.stdout.strip()
        # crv comes first in sorted order
        assert result.index('"crv"') < result.index('"kty"')


# ---------------------------------------------------------------------------
# Test count meta
# ---------------------------------------------------------------------------

def test_total_test_count():
    """Meta-test: ensure we have >= 100 test functions across both test files."""
    import inspect, importlib.util, sys

    total = 0
    for mod_path in [
        __file__,
        str(__file__).replace("test_jwk_thumbprint_pure.py", "test_jwk_thumbprint_pure_more.py"),
    ]:
        spec = importlib.util.spec_from_file_location("test_mod", mod_path)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception:
            continue
        test_classes = [
            getattr(mod, name)
            for name in dir(mod)
            if name.startswith("Test") and inspect.isclass(getattr(mod, name))
        ]
        for cls in test_classes:
            methods = [m for m in dir(cls) if m.startswith("test_")]
            total += len(methods)
    assert total >= 100, f"Only {total} tests found, need >= 100"
