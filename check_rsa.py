from jwk_thumbprint_pure.canonical import canonical_json

RSA_JWK = {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB",
}

result = canonical_json(RSA_JWK)
print(repr(result))

# Now try the "kty first" approach
def canon_with_kty_first(obj):
    if obj is None:
        return "null"
    elif obj is True:
        return "true"
    elif obj is False:
        return "false"
    elif isinstance(obj, str):
        result = []
        for char in obj:
            cp = ord(char)
            if cp == 0x22: result.append("\\\"")
            elif cp == 0x5C: result.append("\\\\")
            elif cp == 0x08: result.append("\\b")
            elif cp == 0x0C: result.append("\\f")
            elif cp == 0x0A: result.append("\\n")
            elif cp == 0x0D: result.append("\\r")
            elif cp == 0x09: result.append("\\t")
            elif cp < 0x20: result.append(f"\\u{cp:04x}")
            else: result.append(char)
        return '"' + "".join(result) + '"'
    elif isinstance(obj, (int, float)):
        return repr(obj)
    elif isinstance(obj, list):
        return "[" + ",".join(canon_with_kty_first(item) for item in obj) + "]"
    elif isinstance(obj, dict):
        if "kty" in obj:
            # kty first, rest sorted
            items = [("kty", obj["kty"])] + sorted(
                [(k, v) for k, v in obj.items() if k != "kty"],
                key=lambda kv: kv[0]
            )
        else:
            items = sorted(obj.items(), key=lambda kv: kv[0])
        pairs = [canon_with_kty_first(k) + ":" + canon_with_kty_first(v) for k, v in items]
        return "{" + ",".join(pairs) + "}"
    else:
        raise TypeError(f"Cannot canonicalize {type(obj).__name__}")

result2 = canon_with_kty_first(RSA_JWK)
print("kty-first:", repr(result2))

import hashlib, base64
d = hashlib.sha256(result.encode()).digest()
t = base64.urlsafe_b64encode(d).rstrip(b"=").decode()
print("thumbprint (all-sorted):", t)

d2 = hashlib.sha256(result2.encode()).digest()
t2 = base64.urlsafe_b64encode(d2).rstrip(b"=").decode()
print("thumbprint (kty-first):", t2)

print("Expected: NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo")
