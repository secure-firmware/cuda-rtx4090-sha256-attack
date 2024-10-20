# Convert the string to UTF-8 bytes
string_value = "gj4Fwh"
utf8_bytes = string_value.encode('utf-8')

# Convert bytes to hex
hex_representation = utf8_bytes.hex()

print(hex_representation)  # Output
