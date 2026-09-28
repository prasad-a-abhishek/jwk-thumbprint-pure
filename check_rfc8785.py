# RFC 8785 test vectors — verify canonical_json implementation

from jwk_thumbprint_pure.canonical import canonical_json

# RFC 8785 Section 4.1 Example 1
obj1 = {"a": 1, "b": [2, 3]}
# Expected (from RFC): {"a":1,"b":[2,3]}
# Keys "a","b" sorted -> yes
result1 = canonical_json(obj1)
expected1 = '{"a":1,"b":[2,3]}'
print(f"Test 1: {result1 == expected1} | got: {result1} | expected: {expected1}")

# RFC 8785 Section 4.1 Example 2
obj2 = {"a": "A", "b": "B"}
result2 = canonical_json(obj2)
expected2 = '{"a":"A","b":"B"}'
print(f"Test 2: {result2 == expected2} | got: {result2} | expected: {expected2}")

# RFC 8785 Section 4.2 Array order preserved
obj3 = [{"b": 1, "a": 2}, {"a": 2, "b": 1}]
result3 = canonical_json(obj3)
expected3 = '[{"b":1,"a":2},{"a":2,"b":1}]'
print(f"Test 3: {result3 == expected3} | got: {result3} | expected: {expected3}")

# RFC 8785 Section 4.3 String escaping
obj4 = {"x": "a\tb"}
result4 = canonical_json(obj4)
expected4 = '{"x":"a\\tb"}'
print(f"Test 4: {result4 == expected4} | got: {repr(result4)} | expected: {repr(expected4)}")

# RFC 8785 Section 4.4 Number representation
obj5 = {"x": 1.0, "y": 1}
result5 = canonical_json(obj5)
print(f"Test 5: {result5}")
# RFC says integers should NOT have unnecessary leading zeros or decimal parts
# so 1 -> "1", 1.0 -> "1" not "1.0"

# RFC 8785 Section 4.5 Whitespace is not serialized
obj6 = {"a": 1, "b": 2}
result6 = canonical_json(obj6)
has_ws = any(c.isspace() for c in result6)
print(f"Test 6 (no whitespace): {not has_ws} | got: {repr(result6)}")
