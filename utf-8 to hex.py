# Convert the string to UTF-8 bytes
string_value = "8XNs2d"
utf8_bytes = string_value.encode('utf-8')

# Convert bytes to hex
hex_representation = utf8_bytes.hex()

print(hex_representation)  # Output
