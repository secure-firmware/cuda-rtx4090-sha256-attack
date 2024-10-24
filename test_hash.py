import hashlib

def test_all_hash_combinations():
    salt_hex = "05252331f5545f0b"
    password = "k1GA44"
    target_hash = "cc84aac572dbc18adfd93d11dbc83d7c260aca2f6838a8dcdf45b083ae811e2d"
    
    # Test case 1: Direct salt bytes + password
    salt = bytes.fromhex(salt_hex)
    message1 = salt + password.encode()
    hash1 = hashlib.sha256(message1).hexdigest()
    print("1. Salt bytes + password:")
    print(f"Message: {message1.hex()}")
    print(f"Hash: {hash1}")
    print(f"Match: {hash1 == target_hash}\n")

    # Test case 2: Hex salt string + password
    message2 = salt_hex.encode() + password.encode()
    hash2 = hashlib.sha256(message2).hexdigest()
    print("2. Hex salt string + password:")
    print(f"Message: {message2.hex()}")
    print(f"Hash: {hash2}")
    print(f"Match: {hash2 == target_hash}\n")

    # Test case 3: Salt bytes + hex password
    message3 = salt + password.encode().hex().encode()
    hash3 = hashlib.sha256(message3).hexdigest()
    print("3. Salt bytes + hex password:")
    print(f"Message: {message3.hex()}")
    print(f"Hash: {hash3}")
    print(f"Match: {hash3 == target_hash}\n")

    # Test case 4: Salt bytes + separator + password
    separators = [':', '$', '.']
    for sep in separators:
        message = salt + sep.encode() + password.encode()
        hash_val = hashlib.sha256(message).hexdigest()
        print(f"4. Salt bytes + '{sep}' + password:")
        print(f"Message: {message.hex()}")
        print(f"Hash: {hash_val}")
        print(f"Match: {hash_val == target_hash}\n")

    # Test case 5: Password + salt
    message5 = password.encode() + salt
    hash5 = hashlib.sha256(message5).hexdigest()
    print("5. Password + salt bytes:")
    print(f"Message: {message5.hex()}")
    print(f"Hash: {hash5}")
    print(f"Match: {hash5 == target_hash}\n")

if __name__ == "__main__":
    test_all_hash_combinations()



# 5. Password + salt bytes:
# Message: 6b314741343405252331f5545f0b
# Hash: cc84aac572dbc18adfd93d11dbc83d7c260aca2f6838a8dcdf45b083ae811e2d
# Match: True