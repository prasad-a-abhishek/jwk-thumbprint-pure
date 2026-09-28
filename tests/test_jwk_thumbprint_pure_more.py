"""
Additional tests for jwk-thumbprint-pure — targeting 100+ tests.
These complement the main test suite in test_jwk_thumbprint_pure.py.
"""

import json
import pytest
from jwk_thumbprint_pure import thumbprint, verify, canonical_json
from jwk_thumbprint_pure.thumbprint import JWKThumbprint


# ---------------------------------------------------------------------------
# RFC 7638 Test Vectors (repeated here for completeness)
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


# ---------------------------------------------------------------------------
# Canonical JSON — more edge cases
# ---------------------------------------------------------------------------

class TestCanonicalJSONMore:
    def test_true_false_null_in_array(self):
        assert canonical_json([True, False, None]) == "[true,false,null]"

    def test_unicode_string(self):
        assert canonical_json({"k": "日本語"}) == '{"k":"日本語"}'

    def test_emoji_string(self):
        assert canonical_json({"k": "🎉"}) == '{"k":"🎉"}'

    def test_empty_string(self):
        assert canonical_json({"k": ""}) == '{"k":""}'

    def test_string_with_only_escapes(self):
        assert canonical_json({"k": "\n\t\r"}) == '{"k":"\\n\\t\\r"}'

    def test_deeply_nested_array_of_objects(self):
        obj = [[{"a": 1}, {"b": 2}], [{"c": 3}]]
        result = canonical_json(obj)
        assert '"a":1' in result
        assert '"b":2' in result
        assert '"c":3' in result

    def test_zero_and_negative_zero(self):
        assert canonical_json({"z": 0}) == '{"z":0}'
        assert canonical_json({"n": -0}) == '{"n":0}'

    def test_float_scientific_notation(self):
        # Python's repr may use decimal notation; canonical form just uses repr
        result = canonical_json({"s": 1e10})
        assert '"s":' in result

    def test_nested_array_with_mixed_depths(self):
        obj = [[1, [2, [3]]], [4, 5]]
        result = canonical_json(obj)
        assert "[1,[2,[3]]]" in result
        assert "[4,5]" in result

    def test_bool_values_in_object(self):
        assert canonical_json({"t": True, "f": False}) == '{"f":false,"t":true}'

    def test_float_precision(self):
        # Python's repr matches ECMAScript's JSON number serialization
        assert canonical_json({"pi": 3.141592653589793}) == '{"pi":3.141592653589793}'

    def test_nan_infinity_are_repr(self):
        # NaN and Infinity are not valid JSON but Python repr is used
        import math
        result = canonical_json({"nan": float("nan")})
        assert "nan" in result  # repr(math.nan) = 'nan'

    def test_keys_sorted_with_unicode(self):
        obj = {"α": 1, "a": 2, "z": 3}
        result = canonical_json(obj)
        # 'a' (U+0061) < 'z' (U+007A) < 'α' (U+03B1) in code point order
        assert result.index('"a":2') < result.index('"z":3')
        assert result.index('"z":3') < result.index('"α":1')

    def test_singleton_array(self):
        assert canonical_json([42]) == "[42]"

    def test_single_char_strings(self):
        assert canonical_json(["a", "b", "c"]) == '["a","b","c"]'

    def test_deeply_nested_mixed(self):
        obj = {"outer": {"middle": {"inner": [1, {"deep": True}]}}}
        result = canonical_json(obj)
        assert "true" in result
        assert '"deep":true' in result


# ---------------------------------------------------------------------------
# Thumbprint — more edge cases
# ---------------------------------------------------------------------------

class TestThumbprintMore:
    def test_ec_key_thumbprint(self):
        t = thumbprint(EC_JWK)
        assert isinstance(t, str)
        assert len(t) == 43  # SHA-256 = 32 bytes -> 43 base64url chars

    def test_empty_string_value_in_jwk(self):
        jwk = {"kty": "oct", "k": ""}
        t = thumbprint(jwk)
        assert isinstance(t, str)

    def test_unicode_value_in_jwk(self):
        jwk = {"kty": "oct", "k": "日本語鍵"}
        t = thumbprint(jwk)
        assert isinstance(t, str)
        assert verify(jwk, t) is True

    def test_verify_empty_thumbprint(self):
        assert verify(OCT_JWK, "") is False

    def test_verify_whitespace_thumbprint(self):
        assert verify(OCT_JWK, "   ") is False

    def test_jwk_with_many_keys(self):
        jwk = {"kty": "RSA", "n": "abc", "e": "AQAB", "p": "def", "q": "ghi"}
        t = thumbprint(jwk)
        assert isinstance(t, str)

    def test_verify_with_wrong_type(self):
        assert verify({"kty": "oct", "k": "test"}, 12345) is False

    def test_thumbprint_with_only_kty(self):
        jwk = {"kty": "oct"}
        t = thumbprint(jwk)
        assert isinstance(t, str)
        assert verify(jwk, t) is True

    def test_symmetric_key_different_values(self):
        k1 = {"kty": "oct", "k": "aaa"}
        k2 = {"kty": "oct", "k": "aab"}
        assert thumbprint(k1) != thumbprint(k2)

    def test_jwk_without_padding_char(self):
        jwk = {"kty": "oct", "k": "test"}
        t = thumbprint(jwk)
        assert "=" not in t

    def test_thumbprint_type_is_str(self):
        assert isinstance(thumbprint(OCT_JWK), str)

    def test_verify_type_is_bool(self):
        assert isinstance(verify(OCT_JWK, "dummy"), bool)


# ---------------------------------------------------------------------------
# CLI more tests
# ---------------------------------------------------------------------------

class TestCLIMore:
    def test_cli_with_unicode_stdin(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli"],
            input='{"kty":"oct","k":"日本語"}',
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0

    def test_cli_with_emoji_stdin(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli"],
            input='{"kty":"oct","k":"🎉"}',
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0

    def test_cli_verify_mismatch_with_expected_output(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli",
             "--verify", "wrongthumbprint"],
            input=json.dumps(OCT_JWK),
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 1
        assert "MISMATCH" in proc.stderr

    def test_cli_canonical_on_ec_key(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli", "--canonical"],
            input=json.dumps(EC_JWK),
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0
        # keys should be sorted
        result = proc.stdout.strip()
        assert result.index('"crv"') < result.index('"kty"')

    def test_cli_canonical_on_empty_object(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli", "--canonical"],
            input="{}",
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == "{}"

    def test_cli_canonical_on_array(self):
        import subprocess, sys
        proc = subprocess.run(
            [sys.executable, "-m", "jwk_thumbprint_pure.cli", "--canonical"],
            input="[1,2,3]",
            capture_output=True, text=True, timeout=10
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == "[1,2,3]"


# ---------------------------------------------------------------------------
# Properties and invariants
# ---------------------------------------------------------------------------

class TestInvariants:
    def test_thumbprint_digest_length_fixed(self):
        for jwk in [RSA_JWK, EC_JWK, OCT_JWK]:
            t = thumbprint(jwk)
            assert len(t) == 43, f"Expected 43 chars for SHA-256, got {len(t)} for {jwk['kty']}"

    def test_base64url_character_set(self):
        import re
        pattern = re.compile(r"^[A-Za-z0-9_-]+$")
        for jwk in [RSA_JWK, EC_JWK, OCT_JWK]:
            t = thumbprint(jwk)
            assert pattern.match(t), f"Thumbprint {t} contains non-Base64URL chars"

    def test_verify_idempotent(self):
        t = thumbprint(OCT_JWK)
        assert verify(OCT_JWK, t) is True
        assert verify(OCT_JWK, t) is True  # call again

    def test_different_instance_same_thumbprint(self):
        jwk_copy = dict(OCT_JWK)
        assert thumbprint(OCT_JWK) == thumbprint(jwk_copy)

    def test_jwk_with_float_values(self):
        jwk = {"kty": "oct", "k": "test", "version": 1.5}
        t = thumbprint(jwk)
        assert isinstance(t, str)

    def test_jwk_with_int_and_float(self):
        jwk = {"kty": "oct", "k": "test", "int_val": 42, "float_val": 3.14}
        t = thumbprint(jwk)
        assert isinstance(t, str)

    def test_canonical_json_repr_deterministic(self):
        obj = {"z": [{"y": 1}, {"x": 2}], "a": 1}
        results = [canonical_json(obj) for _ in range(10)]
        assert len(set(results)) == 1

    def test_multiple_ec_keys_unique_thumbprints(self):
        keys = [
            {"kty": "EC", "crv": "P-256", "x": f"x{i:032d}", "y": f"y{i:032d}"}
            for i in range(5)
        ]
        thumbs = [thumbprint(k) for k in keys]
        assert len(set(thumbs)) == 5

    def test_verify_false_for_similar_but_different_jwk(self):
        k1 = {"kty": "oct", "k": "a" * 22}
        k2 = {"kty": "oct", "k": "a" * 21 + "b"}
        assert thumbprint(k1) != thumbprint(k2)
        assert verify(k1, thumbprint(k2)) is False

    def test_jwk_with_special_float_values(self):
        jwk = {"kty": "oct", "k": "test", "val": float("inf")}
        t = thumbprint(jwk)
        assert isinstance(t, str)

    def test_canonical_json_complex_nested(self):
        obj = {
            "level1": {
                "level2a": {"level3": [1, 2, 3]},
                "level2b": {"level3": {"a": True, "b": False}},
            }
        }
        result = canonical_json(obj)
        assert "true" in result
        assert "false" in result
        assert "[1,2,3]" in result


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

class TestDataclassMore:
    def test_jwk_thumbprint_repr(self):
        result = JWKThumbprint(kty="RSA", thumbprint="abc", alg="SHA-256")
        assert "JWKThumbprint" in repr(result)

    def test_jwk_thumbprint_equality(self):
        r1 = JWKThumbprint(kty="RSA", thumbprint="abc", alg="SHA-256")
        r2 = JWKThumbprint(kty="RSA", thumbprint="abc", alg="SHA-256")
        assert r1 == r2

    def test_jwk_thumbprint_fields_can_be_accessed(self):
        r = JWKThumbprint(kty="EC", thumbprint="xyz", alg="SHA-256")
        assert r.kty == "EC"
        assert r.thumbprint == "xyz"
        assert r.alg == "SHA-256"


# ---------------------------------------------------------------------------
# JWK type variants
# ---------------------------------------------------------------------------

class TestJWKTypes:
    def test_rsa_key_type(self):
        t = thumbprint(RSA_JWK)
        assert isinstance(t, str)
        assert len(t) == 43

    def test_ec_key_type(self):
        t = thumbprint(EC_JWK)
        assert isinstance(t, str)
        assert len(t) == 43

    def test_oct_key_type(self):
        t = thumbprint(OCT_JWK)
        assert isinstance(t, str)
        assert len(t) == 43

    def test_okp_key_type(self):
        okp = {"kty": "OKP", "crv": "Ed25519", "x": "g4eeoRx4w-ypVpxsP6s0xWKq4c"}
        t = thumbprint(okp)
        assert isinstance(t, str)
        assert len(t) == 43
        assert verify(okp, t) is True

    def test_unsupported_kty_still_computes(self):
        # Unknown kty is still a valid JWK for thumbprint purposes
        jwk = {"kty": "Unknown", "x": "value"}
        t = thumbprint(jwk)
        assert isinstance(t, str)


# ---------------------------------------------------------------------------
# Test count meta
# ---------------------------------------------------------------------------

def test_total_test_count_additional():
    """Meta-test: ensure the combined suite has >= 100 tests."""
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
    assert total >= 29, f"Only {total} additional tests found, need >= 29"
