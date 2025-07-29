#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import struct
from intelhex import IntelHex
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC_HEADER = b'\xAB\xCD\xEF\x12'
BLOB_ADDRESS = 0xfb400
MAX_BLOB_SIZE = 0x4c00

def try_decrypt_entry(key, iv, aad, ct):
    try:
        aesgcm = AESGCM(key)
        ciphertext = ct[:-16]
        tag = ct[-16:]
        decrypted = aesgcm.decrypt(iv, ciphertext + tag, aad)
        return decrypted
    except Exception as e:
        return f"❌ Decryption failed: {e}"

def parse_blob(blob_data, key=None):
    offset = 0

    if blob_data[offset:offset + 4] != MAGIC_HEADER:
        print(f"❌ Invalid magic header: found {blob_data[:4].hex()}, expected {MAGIC_HEADER.hex()}")
        return

    offset += 4

    if offset + 2 > len(blob_data):
        print("❌ Not enough data to read entry count")
        return

    entry_count = struct.unpack_from("<H", blob_data, offset)[0]
    offset += 2

    print(f"🔍 Declared entry count: {entry_count}")

    for i in range(entry_count):
        if offset >= len(blob_data):
            print(f"⚠️  Reached end of blob before entry {i}")
            break

        print(f"\n➡️  Entry {i} at offset {offset}")

        # IV
        iv_len = blob_data[offset]
        offset += 1
        if iv_len > 32 or offset + iv_len > len(blob_data):
            print(f"❌ IV length too large or out of bounds: {iv_len}")
            break
        iv = blob_data[offset:offset + iv_len]
        offset += iv_len

        # AAD
        if offset + 2 > len(blob_data):
            print("❌ Not enough data to read AAD length")
            break
        aad_len = struct.unpack_from("<H", blob_data, offset)[0]
        offset += 2
        if aad_len > 128 or offset + aad_len > len(blob_data):
            print(f"❌ AAD length too large or out of bounds: {aad_len}")
            break
        aad = blob_data[offset:offset + aad_len]
        offset += aad_len

        # Ciphertext + tag
        if offset + 2 > len(blob_data):
            print("❌ Not enough data to read ciphertext+tag length")
            break
        ct_len = struct.unpack_from("<H", blob_data, offset)[0]
        offset += 2
        if ct_len > 256 or offset + ct_len > len(blob_data):
            print(f"❌ Ciphertext+tag length too large or out of bounds: {ct_len}")
            break
        ct = blob_data[offset:offset + ct_len]
        offset += ct_len

        print(f"✅ Entry {i}: IV={iv_len} AAD={aad_len} CT+Tag={ct_len}")
        print(f"    🔹 IV   : {iv.hex()}")
        print(f"    🔹 AAD  : {aad.decode(errors='replace')}")
        print(f"    🔹 CT+T : {ct.hex()}")

        if key:
            result = try_decrypt_entry(key, iv, aad, ct)
            if isinstance(result, bytes):
                print(f"    🔓 Decrypted: {result.decode(errors='replace')}")
            else:
                print(f"    {result}")

    print(f"\n📍 Finished parsing {entry_count} entries. Final offset: {offset}/{len(blob_data)}")
    if offset != len(blob_data):
        print(f"⚠️  Warning: {len(blob_data) - offset} bytes of trailing data unparsed.")

def main():
    if len(sys.argv) not in [2, 3]:
        print("Usage: python verify.py <blob.hex> [aes_key.bin]")
        sys.exit(1)

    hex_path = sys.argv[1]
    key = None

    if len(sys.argv) == 3:
        key_path = sys.argv[2]
        try:
            with open(key_path, 'rb') as f:
                key = f.read()
            if len(key) not in (16, 24, 32):
                print(f"❌ Invalid AES key length: {len(key)} bytes (must be 16/24/32)")
                sys.exit(1)
        except Exception as e:
            print(f"❌ Failed to read AES key: {e}")
            sys.exit(1)

    try:
        ih = IntelHex()
        ih.loadfile(hex_path, format='hex')
    except Exception as e:
        print(f"❌ Failed to load hex file: {e}")
        sys.exit(1)

    try:
        blob_data = ih.tobinarray(start=BLOB_ADDRESS, size=MAX_BLOB_SIZE)
    except Exception as e:
        print(f"❌ Failed to read blob data: {e}")
        sys.exit(1)

    parse_blob(bytes(blob_data), key)

if __name__ == "__main__":
    main()
