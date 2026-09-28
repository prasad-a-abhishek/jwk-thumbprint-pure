"""Check the exact RSA JWK against RFC 7638 test vector."""
import hashlib, base64

# From RFC 7638 Section 3.1 - EXACT test vector
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
    "alg": "RS256",
}

# Using json.dumps with keys sorted - this is what RFC 7638 uses
import json
canon = json.dumps(RSA_JWK, separators=(",", ":"), sort_keys=True)
print("json.dumps sort_keys=True:")
print(repr(canon))
d = hashlib.sha256(canon.encode("utf-8")).digest()
t = base64.urlsafe_b64encode(d).rstrip(b"=").decode()
print("Thumbprint:", t)
print("Expected:   NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo")

# Now without alg (RFC 7638 says MUST NOT contain alg for thumbprint computation)
RSA_JWK_noalg = {k: v for k, v in RSA_JWK.items() if k != "alg"}
canon2 = json.dumps(RSA_JWK_noalg, separators=(",", ":"), sort_keys=True)
print()
print("Without alg, sort_keys=True:")
print(repr(canon2))
d2 = hashlib.sha256(canon2.encode("utf-8")).digest()
t2 = base64.urlsafe_b64encode(d2).rstrip(b"=").decode()
print("Thumbprint:", t2)
print("Expected:   NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo")
