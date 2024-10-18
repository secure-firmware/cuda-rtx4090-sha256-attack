charset = "abcd"
base = len(charset)

def generate_password_from_id(id, length=3):
    password = []
    for _ in range(length):
        id, remainder = divmod(id, base)
        password.append(charset[remainder])
    return ''.join(reversed(password))

# Example usage
max_id = base ** 3  # Since the length of the password is 3
for id in range(max_id):
    password = generate_password_from_id(id)
    print(f"ID {id} -> Password: {password}")
