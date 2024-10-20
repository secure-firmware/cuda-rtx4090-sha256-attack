import secrets
import hashlib
import string

# Constants
NUM_PASSWORDS = 50
SALT_LENGTH = 8
PASSWORD_LENGTH = 6
ALPHABET = string.ascii_letters + string.digits

# File names
in_filename = 'in.txt'
out_filename = 'out.txt'

# Lists to hold the results
in_data = []
out_data = []

for _ in range(NUM_PASSWORDS):
    # Generate a secure salt
    salt = secrets.token_bytes(SALT_LENGTH)
    
    # Generate a random password
    password = "".join(secrets.choice(ALPHABET) for _ in range(PASSWORD_LENGTH))
    
    # Create SHA-256 hash of the salt + password
    hash_input = salt + password.encode('utf-8')
    
    # Print the hash_input to the console
    print(f"hash_input: {hash_input.hex()}")  # Print as hex for readability
    
    hash_output = hashlib.sha256(hash_input).hexdigest()
    
    # Store results
    in_data.append(f"{salt.hex()} {hash_output}")
    out_data.append(f"{salt.hex()} {hash_output} {password}")

# Write to in.txt
with open(in_filename, 'w') as in_file:
    in_file.write("\n".join(in_data) + "\n")

# Write to out.txt
with open(out_filename, 'w') as out_file:
    out_file.write("\n".join(out_data) + "\n")

print(f"Generated {NUM_PASSWORDS} passwords and saved to '{in_filename}' and '{out_filename}'")
