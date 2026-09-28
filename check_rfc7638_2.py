"""Verify exact RSA JWK from RFC 7638."""
import hashlib, base64

# Exact copy from RFC 7638 Section 3.1 - let me get the raw hex
RSA_JWK = {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB",
}

# Double-check the n value ends correctly
print(f"n length: {len(RSA_JWK['n'])} chars")
print(f"n ends with: ...{RSA_JWK['n'][-50:]}")

# The problem must be in the canonical form
# RFC 7638 says: SHA256(CanonJCS(JWK))
# CanonJCS = JSON Canonicalization Scheme = RFC 8785
# RFC 8785 says: sort keys lexicographically

# Let me check if maybe the number encoding is different
# Python's json.dumps uses Python float repr which may differ from RFC 8785

# RFC 8785 Section 4.4 says: numbers should be serialized following ECMAScript's JSON.stringify
# For integers: no decimal point, no leading zeros
# For real numbers: use shortest representation

# But our JWK only has string values, so this shouldn't matter...

# Let me try one more thing: what if I use json.dumps without sort_keys?
import json
canon_original = json.dumps(RSA_JWK, separators=(",", ":"))  # original order
d_orig = hashlib.sha256(canon_original.encode()).digest()
t_orig = base64.urlsafe_b64encode(d_orig).rstrip(b"=").decode()
print(f"\nOriginal order: {t_orig}")

canon_sorted = json.dumps(RSA_JWK, separators=(",", ":"), sort_keys=True)  # sorted
d_sorted = hashlib.sha256(canon_sorted.encode()).digest()
t_sorted = base64.urlsafe_b64encode(d_sorted).rstrip(b"=").decode()
print(f"All sorted:     {t_sorted}")

print(f"\nExpected:      NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo")

# Let me check if the n value I'm using matches the RFC
# From RFC 7638, the base64url modulus value decodes to what?
n_bytes = base64.urlsafe_b64decode(RSA_JWK["n"] + "==")
print(f"\nn base64 decoded bytes length: {len(n_bytes)}")
print(f"n first few bytes (hex): {n_bytes[:8].hex()}")
# If this is wrong, the n value in the JWK is wrong
