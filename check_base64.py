import hashlib, base64

# Test base64 encoding
s = "hello"
d = hashlib.sha256(s.encode()).digest()
b = base64.urlsafe_b64encode(d).rstrip(b"=")
print(f"hello: {len(b)} chars: {b.decode()}")

# Now check what Python's base64 does
print()
print("Standard base64url (RFC 4648):")
print(base64.urlsafe_b64encode(d).decode())

# Is there a different encoding?
# Maybe we need standard base64 (not urlsafe)?
b64 = base64.b64encode(d).rstrip(b"=")
print(f"Standard base64: {len(b64)} chars: {b64.decode()}")
