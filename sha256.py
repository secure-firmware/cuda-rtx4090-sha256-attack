import hashlib

# String to hash
input_string = "aaaaaa"

# Calculate SHA-256 hash
sha256_hash = hashlib.sha256(input_string.encode()).hexdigest()

print(f"SHA-256 of '{input_string}': {sha256_hash}")
