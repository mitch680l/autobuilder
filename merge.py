from intelhex import IntelHex
import os
import random

# === CONFIGURATION ===
blob_address = 0xFDF00           # Flash address to write the blob
output_blob_hex = "blob.hex"     # Output hex file with the blob
merged_input_hex = "merged.hex"  # Input firmware hex file
final_output_hex = "final.hex"   # Final merged hex file
max_blob_size = 2048              # Max size of the flash blob area (in bytes)
magic_header = b'\xAB\xCD'       # 2-byte magic number at start

# === RANDOMIZED STRINGS TO FILL THE BLOB ===
sample_sentences = [
    "Hello from device provisioning!",
    "Quick brown fox jumps over lazy dog.",
    "Testing flash region before encryption.",
    "Embedded systems are fun to secure.",
    "Each sentence is for readback testing.",
    "MCUboot must not overwrite this area.",
    "Provisioning tool writes this data.",
    "Reading this validates our blob patch.",
    "TrustZone keeps secure world isolated.",
    "Patch this with encrypted keys later."
]


random.shuffle(sample_sentences)


blob_bytes = bytearray()
blob_bytes += magic_header 

for sentence in sample_sentences:
    encoded = sentence.encode('utf-8') + b'\n'
    if len(blob_bytes) + len(encoded) > max_blob_size:
        break
    blob_bytes += encoded


blob_bytes += b'\x00' * (max_blob_size - len(blob_bytes))

# === Create Intel HEX for blob ===
ih_blob = IntelHex()
ih_blob.frombytes(blob_bytes, offset=blob_address)
ih_blob.write_hex_file(output_blob_hex)
print(f"✅ Generated {output_blob_hex} with {len(blob_bytes)} bytes at 0x{blob_address:X}")

# === Merge with firmware hex ===
ih_merged = IntelHex()
ih_merged.loadfile(merged_input_hex, format='hex')
ih_blob = IntelHex(output_blob_hex)
ih_merged.merge(ih_blob, overlap='replace')
ih_merged.write_hex_file(final_output_hex)
print(f"✅ Merged into {final_output_hex}")

