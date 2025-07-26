from intelhex import IntelHex
import os

# === CONFIGURATION ===
blob_string = "Hello"  # String to inject into flash
blob_address = 0xFD000  # Flash address for blob
output_blob_hex = "blob.hex"
merged_input_hex = "merged.hex"  # Firmware hex to patch
final_output_hex = "final.hex"   # Final result

# === STEP 1: Convert string to bytes ===
blob_bytes = blob_string.encode("utf-8")

# === STEP 2: Create blob.hex file ===
ih_blob = IntelHex()
ih_blob.frombytes(blob_bytes, offset=blob_address)
ih_blob.write_hex_file(output_blob_hex)
print(f"Generated {output_blob_hex} from string: '{blob_string}' at 0x{blob_address:X}")

# === STEP 3: Merge blob.hex with existing firmware hex ===
ih_firmware = IntelHex()
ih_firmware.loadfile(merged_input_hex, format='hex')

ih_blob = IntelHex(output_blob_hex)
ih_firmware.merge(ih_blob, overlap='replace')

ih_firmware.write_hex_file(final_output_hex)
print(f"Merged {output_blob_hex} into {merged_input_hex} → {final_output_hex}")
