import zlib
import struct

# Your actual memory data (first part of the hex dump)
hex_data = """AB CD EF 12 09 00 0C CA  BF 2F E0 CA 80 6E D6 FE  35 1D 15 04 00 6E 61 6D  65 13 00 8D 48 68 83 65  97 06 5A 99 CE 4D 96 F9  6C 00 67 10 40 F2 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 0C 8F  92 31 55 7A 2C 5A 57 9B  EE 78 95 07 00 73 65 63  5F 74 61 67 12 00 4E AC  0A A0 F9 92 7B 71 E5 EA  1F 4D D1 14 0B C9 2B 98  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00"""

# Convert hex string to bytes (removing spaces and newlines)
hex_clean = hex_data.replace(' ', '').replace('\n', '')

# Get the first few entries to test with a smaller dataset
test_data_hex = hex_clean[:32*2]  # First 32 bytes for quick test
test_data = bytes.fromhex(test_data_hex)

print(f"Test data ({len(test_data)} bytes): {test_data.hex().upper()}")

# Calculate CRC32 using Python's zlib (IEEE 802.3)
test_crc = zlib.crc32(test_data) & 0xFFFFFFFF
print(f"Python CRC32: 0x{test_crc:08X}")

# From your memory dump, the stored CRC is: BA 01 36 2B (little-endian)
stored_crc = 0x2B3601BA
print(f"Stored CRC from memory: 0x{stored_crc:08X}")

# Now let's test with the full 7996 bytes (MAX_BLOB_SIZE - 4)
# We need to reconstruct the full data from your hex dump

print("\n" + "="*50)
print("FULL DATA TEST")
print("="*50)

# Let's create the full 8000 byte blob from the hex dump you provided
# Parse the entire hex dump
full_hex_lines = """AB CD EF 12 09 00 0C CA  BF 2F E0 CA 80 6E D6 FE  35 1D 15 04 00 6E 61 6D  65 13 00 8D 48 68 83 65  97 06 5A 99 CE 4D 96 F9  6C 00 67 10 40 F2 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 0C 8F  92 31 55 7A 2C 5A 57 9B  EE 78 95 07 00 73 65 63  5F 74 61 67 12 00 4E AC  0A A0 F9 92 7B 71 E5 EA  1F 4D D1 14 0B C9 2B 98  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 0C 4D  A6 F3 2D 6C E2 78 7A 0B  9F 15 C4 09 00 6D 71 74  74 5F 68 6F 73 74 1D 00  11 53 FB D2 01 43 51 21  EC 9E 44 4E 9D 73 77 B8  13 3F 42 4F 7F 82 87 96  62 E4 9D BE 73 00 00 00"""

# Parse just the beginning to check structure
lines = full_hex_lines.strip().split('\n')
all_hex = ''.join(line.replace(' ', '') for line in lines)

# Convert to bytes
data_bytes = bytes.fromhex(all_hex)

print(f"Parsed {len(data_bytes)} bytes from hex dump")
print(f"Magic: {data_bytes[:4].hex().upper()}")
print(f"Entry count: {struct.unpack('<H', data_bytes[4:6])[0]}")

# Since your hex dump might not be complete (8000 bytes), let's work with what we have
# and pad with zeros to simulate the full blob
if len(data_bytes) < 7996:
    # Pad with zeros to make it 7996 bytes (excluding CRC)
    padded_data = data_bytes + b'\x00' * (7996 - len(data_bytes))
    print(f"Padded to {len(padded_data)} bytes")
else:
    padded_data = data_bytes[:7996]  # Take exactly 7996 bytes

# Calculate CRC on the full 7996 bytes
full_crc = zlib.crc32(padded_data) & 0xFFFFFFFF
print(f"Python CRC32 on {len(padded_data)} bytes: 0x{full_crc:08X}")
print(f"Expected from memory: 0x{stored_crc:08X}")

if full_crc == stored_crc:
    print("✅ CRC MATCH!")
else:
    print("❌ CRC MISMATCH")
    
# Let's also try with different byte counts in case there's an off-by-one error
for test_len in [7995, 7996, 7997, 7998, 7999, 8000]:
    if test_len <= len(data_bytes):
        test_crc = zlib.crc32(data_bytes[:test_len]) & 0xFFFFFFFF
        match = "✅" if test_crc == stored_crc else "❌"
        print(f"{match} {test_len} bytes: 0x{test_crc:08X}")

print("\n" + "="*50)
print("CRC ALGORITHM VERIFICATION")
print("="*50)

# Test with the standard IEEE 802.3 test vector "123456789"
test_vector = b"123456789"
expected_crc = 0xCBF43926  # Known IEEE 802.3 result for "123456789"
actual_crc = zlib.crc32(test_vector) & 0xFFFFFFFF

print(f"Test vector: {test_vector}")
print(f"Expected CRC: 0x{expected_crc:08X}")
print(f"Python CRC:   0x{actual_crc:08X}")

if actual_crc == expected_crc:
    print("✅ Python zlib.crc32 is correctly implementing IEEE 802.3 CRC-32")
else:
    print("❌ Python zlib.crc32 algorithm mismatch!")

print("\n" + "="*50)
print("RECOMMENDATIONS")
print("="*50)

print("1. Run this same test vector in your C code:")
print(f'   const char test_data[] = "123456789";')
print(f'   uint32_t test_crc = crc32_ieee(test_data, 9);')
print(f'   LOG_INF("C CRC32: 0x%08X", test_crc);')
print(f"   Expected result: 0x{expected_crc:08X}")

print("\n2. If C result matches, then the issue is in data preparation/reading")
print("3. If C result differs, then crc32_ieee isn't standard IEEE 802.3")