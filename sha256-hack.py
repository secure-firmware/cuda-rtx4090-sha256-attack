def right_rotate(value, amount):
    return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF

def sha256(message):
    # Initialize hash values
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Constants
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Preprocess the message (padding)
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    message += b'\x80'
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    message += original_bit_len.to_bytes(8, byteorder='big')

    # Process each 512-bit block
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        w = [int.from_bytes(block[j:j+4], byteorder='big') for j in range(0, 64, 4)]

        # Extend the first 16 words into the remaining 48 words
        for j in range(16, 64):
            s0 = right_rotate(w[j-15], 7) ^ right_rotate(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = right_rotate(w[j-2], 17) ^ right_rotate(w[j-2], 19) ^ (w[j-2] >> 10)
            w.append((w[j-16] + s0 + w[j-7] + s1) & 0xFFFFFFFF)

        # Initialize working variables
        a, b, c, d, e, f, g, h0 = h

        # Compression function main loop
        for j in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h0 + S1 + ch + k[j] + w[j]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h0 = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

            # Print intermediate states for verification
            print(f"Round {j}:")
            print(f"  a: {a:08x}, b: {b:08x}, c: {c:08x}, d: {d:08x}")
            print(f"  e: {e:08x}, f: {f:08x}, g: {g:08x}, h: {h0:08x}")

        # Add the compressed chunk to the current hash value
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, h0])]

    # Produce the final hash value (big-endian)
    return ''.join(f'{x:08x}' for x in h)

# Example usage
message = b'jNdRTA' + bytes.fromhex('0e8b22dfc589e87a')
final_hash = sha256(message)
print("Final SHA-256 Hash:", final_hash)

# // 7ef9f1d30238bff690b644c5fe686b74056522c01ef4d250164d356d39c0aa34:0e8b22dfc589e87a:ATHy11
# // 8205de54cb323e67fb2c6274a2ad4bd09cd81624a03b8482fb6192ee2216532d:0e8b22dfc589e87a:jNdRTA
# // 125b337ce16cd97a15ec5e8e652474adfc87b8f91a33b81f46a9b12e6ee2464b:0e8b22dfc589e87a:7B7nRA
# // 2a50c17ef05206e7b31b8cd97d8cd288883c3226a166a86d998af5a24d67b88f:0e8b22dfc589e87a:ATdoLO
# // 38246c857e8a21d9c76381b591fc57dba4cde0583e02321ba3994d67d54ed9de:0e8b22dfc589e87a:oXA1VO
# // char test_password[7] = "jNdRTA";  // Example password
# // debugHash(test_password, salt);
# //658aeb95e61237c4b3e37130bdf6047f57246058a44211c2f07fba4ba5898a04:0e8b22dfc589e87a:ATHy11
# //195e714b2e97c9f61c43cdcfbbdd55b6149b28c68c33ce5713c45f8d1cc1d5b6:0e8b22dfc589e87a:jNdRTA