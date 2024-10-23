import os
import hashlib
import random
import string

def generate_salt_password_pairs(num_pairs=100):
    characters = string.ascii_letters + string.digits

    # Generate a single random salt
    salt = os.urandom(8).hex()

    with open("in.txt", "w") as in_file, open("out.txt", "w") as out_file:
        for _ in range(num_pairs):
            # Generate a random password of 6 characters using only letters and digits
            password = ''.join(random.choice(characters) for _ in range(6))

            # Combine salt and password
            combined = salt + password

            # Hash the combined string using SHA-256
            sha256_hash = hashlib.sha256(combined.encode()).hexdigest()

            # Write to in.txt (salt and hash only)
            in_file.write(f"{salt}, {sha256_hash}\n")

            # Write only values (salt, password, hash) to out.txt
            out_file.write(f"{salt}, {password}, {sha256_hash}\n")

# Call the function
generate_salt_password_pairs()
