from jwk_thumbprint_pure import thumbprint
print("import ok")
t = thumbprint({"kty": "oct", "k": "test"})
print("thumbprint:", t)
