# jwk-thumbprint-pure

**RFC 7638 JWK Thumbprint** — zero-dependency, pure Python.

> Compute the Base64URL(SHA-256(CanonJCS(JWK))) thumbprint of any JSON Web Key without touching `cryptography`, `PyJWT`, or `jsonschema`.

[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Quick Start

```bash
pip install git+https://github.com/prasad-a-abhishek/jwk-thumbprint-pure.git
```

```python
from jwk_thumbprint_pure import thumbprint, verify

# RFC 7638 §3.1 — canonical RSA test vector
jwk_rsa = {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB"
}
# RFC 7638 §3.1 thumbprint literal
assert thumbprint(jwk_rsa) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

# Verify
assert verify(jwk_rsa, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs") is True
assert verify(jwk_rsa, "wrong") is False
```

## CLI

```bash
# Compute thumbprint from command line
jwk-thumbprint '{"kty":"RSA","n":"...","e":"AQAB"}'

# Pipe a JWK through stdin
echo '{"kty":"EC","crv":"P-256","x":"...","y":"..."}' | jwk-thumbprint

# Verify a known thumbprint
jwk-thumbprint --verify NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs '{"kty":"RSA","n":"...","e":"AQAB"}'
# exit 0 if match, exit 1 if mismatch
```

## Why jwk-thumbprint-pure?

- **Zero dependencies** — only Python standard library (`hashlib`, `base64`, `json`).
- **RFC 7638 compliant** — uses RFC 8785 JSON Canonicalization Scheme for deterministic serialization.
- **Serverless-ready** — works on AWS Lambda, Cloudflare Workers, Pyodide, and air-gapped environments.
- **Pure Python** — no C extensions, no `cryptography`, no `PyJWT`.

## Key Features

- `thumbprint(jwk, alg="SHA-256")` → `str` — RFC 7638 thumbprint
- `verify(jwk, expected, alg="SHA-256")` → `bool` — constant-time comparison
- `canonical_json(obj)` → `str` — RFC 8785 deterministic JSON
- CLI with `--verify` flag and stdin support

## API Reference

### `thumbprint(jwk, alg="SHA-256")`

```python
def thumbprint(jwk: dict, alg: str = "SHA-256") -> str:
    """
    Compute the RFC 7638 JWK thumbprint.

    Args:
        jwk: A dict representation of a JSON Web Key.
        alg: Hash algorithm (SHA-256 only, per RFC 7638).

    Returns:
        Base64URL-encoded thumbprint with no padding.
    """
```

### `verify(jwk, expected, alg="SHA-256")`

```python
def verify(jwk: dict, expected: str, alg: str = "SHA-256") -> bool:
    """
    Verify a JWK thumbprint against an expected value.

    Returns:
        True if the computed thumbprint matches, False otherwise.
    """
```

### `canonical_json(obj)`

```python
def canonical_json(obj: Any) -> str:
    """
    RFC 8785 deterministic JSON serialization.

    Object keys are sorted lexicographically.
    Arrays retain original order.
    No unnecessary whitespace.
    """
```

## Limitations

- Only SHA-256 is supported (per RFC 7638; future algorithms not in scope).
- This library computes and verifies thumbprints only — it does NOT perform JWK validation, signature verification, or key generation. JWK keys with missing required members will raise `ValueError`; empty-string members are accepted and hashed as-is (use a JWK validator upstream if you need stricter checks).

## License

MIT License — © 2026 Repo Factory
