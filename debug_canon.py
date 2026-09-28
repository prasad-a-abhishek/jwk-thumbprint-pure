import hashlib, base64, json

RSA_JWK = {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB",
}

def canon(obj):
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
        return "[" + ",".join(canon(item) for item in obj) + "]"
    elif isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: kv[0])
        pairs = [canon(k) + ":" + canon(v) for k, v in items]
        return "{" + ",".join(pairs) + "}"
    else:
        raise TypeError(f"Cannot canonicalize {type(obj).__name__}")

# Approach 1: all keys sorted lexicographically
c1 = canon(RSA_JWK)
d1 = hashlib.sha256(c1.encode()).digest()
t1 = base64.urlsafe_b64encode(d1).rstrip(b"=").decode()
print("All-sorted:", t1)

# Approach 2: original order via json.dumps
c2 = json.dumps(RSA_JWK, separators=(",", ":"))
d2 = hashlib.sha256(c2.encode()).digest()
t2 = base64.urlsafe_b64encode(d2).rstrip(b"=").decode()
print("json.dumps order:", t2)

# Approach 3: kty first, rest sorted
items = [("kty", RSA_JWK["kty"])] + sorted(
    [(k, v) for k, v in RSA_JWK.items() if k != "kty"],
    key=lambda kv: kv[0]
)
c3 = "{" + ",".join(canon(k) + ":" + canon(v) for k, v in items) + "}"
d3 = hashlib.sha256(c3.encode()).digest()
t3 = base64.urlsafe_b64encode(d3).rstrip(b"=").decode()
print("kty-first, rest sorted:", t3)

print("Expected:", "NzbaLsY3fZiaiqN5SGWCI6z3gmpN3K5b7Q5lF9tNseo")

# Print the canonical forms
print()
print("c1 (all-sorted):", repr(c1))
print()
print("c2 (json.dumps):", repr(c2))
print()
print("c3 (kty-first rest sorted):", repr(c3))
