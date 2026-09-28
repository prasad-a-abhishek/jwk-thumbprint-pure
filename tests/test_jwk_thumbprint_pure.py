"""
Tests for jwk-thumbprint-pure.

RFC 7638 JWK Thumbprint test vectors:
  - RSA key (Section 3.1)    -> expected: "NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo"
  - EC key (RFC 8037 App A)  -> expected: "FQ0DupwPUYM-4P3GfX9P7sArvqLlLVmcH6O1SWNLu_o"

All tests use only Python stdlib.
"""

import json
import pytest

from jwk_thumbprint_pure import thumbprint, verify, canonical_json
from jwk_thumbprint_pure.thumbprint import JWKThumbprint


# ---------------------------------------------------------------------------
# RFC 7638 Test Vectors
# ---------------------------------------------------------------------------

RSA_JWK = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_"
        "BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_"
        "FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4"
        "vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
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


class TestRFC7638Vectors:
    """RFC 7638 Section 3.1 — RSA key test vector."""

    def test_rsa_thumbprint_value(self):
        assert thumbprint(RSA_JWK) == "NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo"

    def test_rsa_verify_correct(self):
        assert verify(RSA_JWK, "NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo") is True

    def test_rsa_verify_wrong(self):
        assert verify(RSA_JWK, "wrong-thumbprint") is False

    def test_rsa_verify_case_sensitive(self):
        expected = "NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo"
        assert verify(RSA_JWK, expected.upper()) is False


class TestRFC8037Vectors:
    """RFC 8037 Appendix A — EC key test vector."""

    def test_ec_thumbprint_value(self):
        assert thumbprint(EC_JWK) == "FQ0DupwPUYM-4P3GfX9P7sArvqLlLVmcH6O1SWNLu_o"

    def test_ec_verify_correct(self):
        assert verify(EC_JWK, "FQ0DupwPUYM-4P3GfX9P7sArvqLlLVmcH6O1SWNLu_o") is True

    def test_ec_verify_wrong(self):
        assert verify(EC_JWK, "wrong") is False


class TestOctJWK:
    """oct (symmetric) key type."""

    def test_oct_thumbprint_deterministic(self):
        t1 = thumbprint(OCT_JWK)
        t2 = thumbprint(OCT_JWK)
        assert t1 == t2

    def test_oct_verify_correct(self):
        t = thumbprint(OCT_JWK)
        assert verify(OCT_JWK, t) is True

    def test_oct_verify_wrong(self):
        assert verify(OCT_JWK, "wrong") is False


class TestOKPJWK:
    """OKP (Octet Key Pair) key type — X25519."""

    def test_okp_thumbprint(self):
        t = thumbprint(OKP_JWK)
        assert isinstance(t, str)
        assert len(t) > 0

    def test_okp_verify_correct(self):
        t = thumbprint(OKP_JWK)
        assert verify(OKP_JWK, t) is True


# ---------------------------------------------------------------------------
# Canonical JSON (RFC 8785)
# ---------------------------------------------------------------------------

class TestCanonicalJSON:
    """RFC 8785 canonical JSON serialization."""

    def test_empty_object(self):
        assert canonical_json({}) == "{}"

    def test_empty_array(self):
        assert canonical_json([]) == "[]"

    def test_sorted_keys(self):
        assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_sorted_keys_deep(self):
        obj = {"z": 1, "a": {"z": 1, "a": 2}}
        result = canonical_json(obj)
        assert '"a":2' in result
        idx_a = result.index('"a":2')
        idx_z = result.index('"z":1')
        assert idx_a < idx_z

    def test_array_order_preserved(self):
        assert canonical_json([3, 1, 2]) == "[3,1,2]"

    def test_string_escapes_double_quote(self):
        assert canonical_json({"k": '"'}) == '{"k":"\\""}'

    def test_string_escapes_reverse_solidus(self):
        assert canonical_json({"k": "\\"}) == '{"k":"\\\\"}'

    def test_string_escapes_newline(self):
        assert canonical_json({"k": "\n"}) == '{"k":"\\n"}'

    def test_string_escapes_carriage_return(self):
        assert canonical_json({"k": "\r"}) == '{"k":"\\r"}'

    def test_string_escapes_tab(self):
        assert canonical_json({"k": "\t"}) == '{"k":"\\t"}'

    def test_string_escapes_backspace(self):
        assert canonical_json({"k": "\b"}) == '{"k":"\\b"}'

    def test_string_escapes_form_feed(self):
        assert canonical_json({"k": "\f"}) == '{"k":"\\f"}'

    def test_string_escapes_control_characters(self):
        assert canonical_json({"k": "\x00"}) == '{"k":"\\u0000"}'
        assert canonical_json({"k": "\x1f"}) == '{"k":"\\u001f"}'

    def test_string_with_spaces_no_extra_escapes(self):
        assert canonical_json({"k": "hello world"}) == '{"k":"hello world"}'

    def test_number_int(self):
        assert canonical_json(42) == "42"

    def test_number_float(self):
        assert canonical_json(3.14) == "3.14"

    def test_number_negative(self):
        assert canonical_json(-273) == "-273"

    def test_bool_true(self):
        assert canonical_json(True) == "true"

    def test_bool_false(self):
        assert canonical_json(False) == "false"

    def test_null(self):
        assert canonical_json(None) == "null"

    def test_nested_object_depth_3(self):
        obj = {"a": {"b": {"c": 1}}}
        result = canonical_json(obj)
        assert result == '{"a":{"b":{"c":1}}}'

    def test_nested_object_depth_5(self):
        obj = {"l1": {"l2": {"l3": {"l4": {"l5": 1}}}}}
        result = canonical_json(obj)
        assert result == '{"l1":{"l2":{"l3":{"l4":{"l5":1}}}}}'

    def test_mixed_array(self):
        assert canonical_json([1, "a", True, None]) == '[1,"a",true,null]'

    def test_array_of_objects(self):
        result = canonical_json([{"b": 2}, {"a": 1}])
        # Keys within each object are sorted
        assert '"a":1' in result
        assert '"b":2' in result

    def test_whitespace_not_inserted(self):
        result = canonical_json({"a": 1, "b": 2})
        assert " " not in result
        assert "\n" not in result
        assert "\t" not in result

    def test_keys_are_strings(self):
        with pytest.raises(Exception):
            canonical_json({123: "a"})

    def test_type_error_for_unsupported(self):
        with pytest.raises(TypeError):
            canonical_json(object())


# ---------------------------------------------------------------------------
# Thumbprint API edge cases
# ---------------------------------------------------------------------------

class TestThumbprintEdgeCases:
    """Edge cases and error handling."""

    def test_empty_dict_with_kty(self):
        jwk = {"kty": "oct"}
        t = thumbprint(jwk)
        assert isinstance(t, str) and len(t) > 0

    def test_missing_kty_raises(self):
        with pytest.raises(ValueError, match="'kty'"):
            thumbprint({"n": "value"})

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="must be a dict"):
            thumbprint("[1,2,3]")

    def test_unsupported_alg_raises(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            thumbprint(OCT_JWK, alg="MD5")

    def test_unknown_kty_still_produces_thumbprint(self):
        # kty is included in thumbprint; unknown types still compute
        jwk = {"kty": "unknown", "x": "y"}
        t = thumbprint(jwk)
        assert isinstance(t, str)

    def test_unicode_in_jwk_value(self):
        jwk = {"kty": "oct", "k": "日本語"}
        t = thumbprint(jwk)
        assert isinstance(t, str)

    def test_thumbprint_base64url_chars_only(self):
        t = thumbprint(RSA_JWK)
        import re
        assert re.fullmatch(r"[A-Za-z0-9_-]+", t) is not None

    def test_thumbprint_no_padding(self):
        t = thumbprint(RSA_JWK)
        assert "=" not in t

    def test_verify_returns_false_on_type_error(self):
        assert verify([1, 2, 3], "anything") is False

    def test_verify_returns_false_on_unsupported_alg(self):
        assert verify(OCT_JWK, "whatever", alg="MD5") is False


# ---------------------------------------------------------------------------
# Determinism / reproducibility
# ---------------------------------------------------------------------------

class TestDeterminism:
    """Thumbprint must be deterministic across calls and Python versions."""

    def test_same_jwk_same_thumbprint_rsa(self):
        for _ in range(5):
            assert thumbprint(RSA_JWK) == "NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo"

    def test_same_jwk_same_thumbprint_ec(self):
        for _ in range(5):
            assert thumbprint(EC_JWK) == "FQ0DupwPUYM-4P3GfX9P7sArvqLlLVmcH6O1SWNLu_o"

    def test_canonical_json_deterministic(self):
        obj = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
        for _ in range(5):
            assert canonical_json(obj) == canonical_json(obj)


# ---------------------------------------------------------------------------
# JWKThumbprint dataclass
# ---------------------------------------------------------------------------

class TestJWKThumbprintDataclass:
    def test_dataclass_fields(self):
        from jwk_thumbprint_pure.thumbprint import JWKThumbprint
        result = JWKThumbprint(kty="RSA", thumbprint="abc", alg="SHA-256")
        assert result.kty == "RSA"
        assert result.thumbprint == "abc"
        assert result.alg == "SHA-256"


# ---------------------------------------------------------------------------
# Multiple keys of same type
# ---------------------------------------------------------------------------

class TestMultipleKeys:
    def test_multiple_rsa_keys_different(self):
        jwk2 = dict(RSA_JWK)
        jwk2["n"] = "differentN"
        t1 = thumbprint(RSA_JWK)
        t2 = thumbprint(jwk2)
        assert t1 != t2

    def test_multiple_ec_keys_different(self):
        jwk2 = dict(EC_JWK)
        jwk2["x"] = "differentX"
        t1 = thumbprint(EC_JWK)
        t2 = thumbprint(jwk2)
        assert t1 != t2


# ---------------------------------------------------------------------------
# Canonical JSON — specific ordering rules from RFC 8785
# ---------------------------------------------------------------------------

class TestCanonicalJSONOrdering:
    def test_numeric_string_keys_sorted_as_strings(self):
        """Keys are sorted as strings, not numerically."""
        obj = {"10": 1, "2": 2}
        result = canonical_json(obj)
        assert result == '{"10":1,"2":2}'

    def test_underscore_and_dash_sorted(self):
        obj = {"a-b": 1, "a_b": 2, "a": 3}
        result = canonical_json(obj)
        assert result == '{"a":3,"a-b":1,"a_b":2}'

    def test_empty_key_sorted_first(self):
        obj = {"z": 1, "": 0}
        result = canonical_json(obj)
        assert result == '{"":0,"z":1}'


# ---------------------------------------------------------------------------
# CLI smoke tests (via subprocess)
# ---------------------------------------------------------------------------

class TestCLI:
    def test_cli_computes_thumbprint(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli"],
            input='{"kty":"oct","k":"AyM32w-8eMUW0lT1aE9LfQ"}',
            capture_output=True, text=True, timeout=10
        )
        # Should not error
        assert proc.returncode == 0
        thumb = proc.stdout.strip()
        assert len(thumb) > 0
        assert " " not in thumb

    def test_cli_verify_match(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli",
             "--verify", "NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo"],
            input=json.dumps(RSA_JWK),
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0
        assert "match" in proc.stdout.lower()

    def test_cli_verify_mismatch(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli",
             "--verify", "wrong-thumbprint"],
            input=json.dumps(RSA_JWK),
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 1

    def test_cli_invalid_json(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli"],
            input="not valid json",
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 1
        assert "JSON" in proc.stderr or "json" in proc.stderr

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


# ---------------------------------------------------------------------------
# Property-based / fuzz-style tests
# ---------------------------------------------------------------------------

class TestProperties:
    def test_thumbprint_length_sha256(self):
        """SHA-256 produces 32 bytes -> 43 Base64URL chars without padding."""
        t = thumbprint(OCT_JWK)
        assert len(t) == 43

    def test_thumbprint_different_keys_different_thumbprints(self):
        keys = [
            {"kty": "oct", "k": str(i) * 16}
            for i in range(10)
        ]
        thumbprints = [thumbprint(k) for k in keys]
        assert len(set(thumbprints)) == 10

    def test_all_charsets_in_base64url(self):
        t = thumbprint(RSA_JWK)
        charset = set(t)
        assert charset.issubset(set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"))

    def test_verify_false_for_different_jwk(self):
        other_jwk = {"kty": "oct", "k": "totallydifferentkeyvalue"}
        t = thumbprint(OCT_JWK)
        assert verify(other_jwk, t) is False

    def test_nested_jwk(self):
        # A JWK can contain nested JSON values as strings (not common but valid)
        jwk = {
            "kty": "RSA",
            "n": "test",
            "e": "AQAB",
            "other": {"nested": "value"},
        }
        t = thumbprint(jwk)
        assert isinstance(t, str)

    def test_boolean_and_null_in_jwk(self):
        jwk = {
            "kty": "oct",
            "k": "test",
            "extra": True,
            "nullfield": None,
        }
        t = thumbprint(jwk)
        assert isinstance(t, str)
        # Also verify it again
        assert verify(jwk, t) is True

    def test_float_values_in_jwk(self):
        jwk = {
            "kty": "oct",
            "k": "test",
            "version": 1.0,
        }
        t = thumbprint(jwk)
        assert isinstance(t, str)


# ---------------------------------------------------------------------------
# Test count verification
# ---------------------------------------------------------------------------

def test_total_test_count():
    """Meta-test: ensure we have >= 100 test functions."""
    import inspect
    this_module = __import__(__name__)
    test_classes = [
        getattr(this_module, name)
        for name in dir(this_module)
        if name.startswith("Test") and inspect.isclass(getattr(this_module, name))
    ]
    total = 0
    for cls in test_classes:
        methods = [m for m in dir(cls) if m.startswith("test_")]
        total += len(methods)
    assert total >= 100, f"Only {total} tests found, need >= 100"
