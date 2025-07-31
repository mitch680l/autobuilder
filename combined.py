import os
import sys
import shutil
import subprocess
import struct
import json
import time
import zlib
from zipfile import ZipFile
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from intelhex import IntelHex

AAD = b"hidden_config"
CONFIG_FILE = "config_settings.txt"
sdk_workspace = r"C:\ncs\v3.0.2"
sdk_version = "v3.0.2"
script_dir = os.path.dirname(os.path.realpath(__file__))
source_dir_1 = os.path.join(script_dir, "partition_kes")

BLOB_ADDRESS = 0xfb000
BLOB_ADDRESS1 = 0x000fe000  
MAX_BLOB_SIZE =  8192   
MAGIC_HEADER = b'\xAB\xCD\xEF\x12'  
ENTRY_SIZE = 128

def create_dual_blob_hex_files(blob_data, output_path_slot0, output_path_slot1, combined_output_path):
    """Create two Intel HEX files for Slot 0 and Slot 1 and a combined version"""
    ih_slot0 = IntelHex()
    ih_slot0.frombytes(blob_data, offset=BLOB_ADDRESS)
    ih_slot0.write_hex_file(output_path_slot0)
    print(f"✅ Created Slot 0 blob.hex")

    ih_slot1 = IntelHex()
    ih_slot1.frombytes(blob_data, offset=BLOB_ADDRESS1)
    ih_slot1.write_hex_file(output_path_slot1)
    print(f"✅ Created Slot 1 blob_backup.hex ")

    ih_slot0.merge(ih_slot1, overlap='replace')
    ih_slot0.write_hex_file(combined_output_path)
    print(f"✅ Created combined blob hex with both slots: {combined_output_path}")

def dfu_application(device_dir, binary_filename="zephyr_signed.bin", dfu_name="dfu_application.zip"):
    """
    Create a DFU package zip with a manifest.json and the signed binary inside.
    
    Args:
        device_dir (str): Path to device folder (e.g., .../bob/nrid001)
        binary_filename (str): Name of the signed .bin file (default: zephyr_signed.bin)
        dfu_name (str): Name of the final output zip file
    """

    bin_path = os.path.join(device_dir, binary_filename)
    temp_dfu_dir = os.path.join(device_dir, "dfu_tmp")
    manifest_path = os.path.join(temp_dfu_dir, "manifest.json")
    dfu_zip_path = os.path.join(device_dir, dfu_name)

    if not os.path.isfile(bin_path):
        raise FileNotFoundError(f"❌ Signed binary not found: {bin_path}")


    os.makedirs(temp_dfu_dir, exist_ok=True)


    bin_copy_path = os.path.join(temp_dfu_dir, binary_filename)
    shutil.copy(bin_path, bin_copy_path)


    modtime = int(os.path.getmtime(bin_copy_path))
    size = os.path.getsize(bin_copy_path)
    now = int(time.time())


    manifest = {
        "format-version": 1,
        "time": now,
        "files": [
            {
                "type": "application",
                "board": "kestrel",
                "soc": "nrf9151",
                "load_address": 0x48000, 
                "image_index": "0",
                "slot_index_primary": "1",
                "slot_index_secondary": "2",
                "version_MCUBOOT": "0.0.0+0",
                "size": size,
                "file": binary_filename,
                "modtime": modtime
            }
        ],
        "name": "partition_kes"
    }

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=4)

    print(f"📝 Created DFU manifest at {manifest_path}")

    with ZipFile(dfu_zip_path, 'w') as zf:
        zf.write(manifest_path, arcname="manifest.json")
        zf.write(bin_copy_path, arcname=binary_filename)

    print(f"✅ Created DFU package: {dfu_zip_path}")


    shutil.rmtree(temp_dfu_dir)
    print(f"🧹 Cleaned up temporary folder: {temp_dfu_dir}")

def parse_config_and_get_cert_paths(script_dir, config_filename="config_settings.txt"):
    config_path = os.path.join(script_dir, config_filename)

    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"Config file not found at: {config_path}")

    config_map = {}

    with open(config_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or ',' not in line:
                continue
            key, value = map(str.strip, line.split(",", 1))
            config_map[key] = value

    if "name" not in config_map or "sec_tag" not in config_map:
        raise ValueError("Config must contain both 'customer' and 'sec_tag' entries.")

    customer = config_map["name"]
    sec_tag = config_map["sec_tag"]

    server_auth_dir = os.path.join(script_dir, "server_auth", sec_tag)

    ca_path = os.path.join(server_auth_dir, "ca.crt")
    pub_path = os.path.join(server_auth_dir, "public.crt")
    priv_path = os.path.join(server_auth_dir, "private.key")

    return {
        "customer": customer,
        "sec_tag": sec_tag,
        "ca": ca_path,
        "pub": pub_path,
        "priv": priv_path
    }


def build_partition_kes(source_dir):
    build_dir = os.path.join(source_dir, "build")

    build_cmd = (
        f"west build --build-dir {build_dir} {source_dir} --pristine "
        f"--board kestrel/nrf9151/ns -- -DBOARD_ROOT={source_dir}"
    )

    try:
        subprocess.run([
            "nrfutil", "sdk-manager", "toolchain", "launch",
            "--ncs-version", sdk_version,
            "--",
            "cmd.exe", "/d", "/s", "/c",
            f"cd /d {sdk_workspace} && {build_cmd}"
        ], check=True)
        print(f"✅ Build succeeded for {source_dir}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed for {source_dir}")
        print(e)
        return False

def sign_application_image(customer, device_name, script_dir):
    """
    Signs zephyr.bin using imgtool and places zephyr_signed.bin in the device's output folder.
    """
    sdk_version = "v3.0.2"
    zephyr_bin_path = os.path.join(script_dir, "tfm_merged.hex")
    
    if not os.path.isfile(zephyr_bin_path):
        raise FileNotFoundError(f"Missing application binary: {zephyr_bin_path}")

    device_dir = os.path.join(script_dir, customer, device_name)
    priv_key_path = os.path.join(device_dir, f"{device_name}_boot.pem")
    signed_bin_path = os.path.join(device_dir, "zephyr_signed.bin")

    if not os.path.isfile(priv_key_path):
        raise FileNotFoundError(f"Private signing key not found: {priv_key_path}")

    full_cmd = (
    f'nrfutil sdk-manager toolchain launch '
    f'--ncs-version {sdk_version} '
    f'-- '
    f'cmd.exe /d /s /c '
    f'"cd /d {script_dir} && imgtool sign '
    f'-k \"{priv_key_path}\" '
    f'--header-size 0x200 '
    f'--align 4 '
    f'--version 0.0.0 '
    f'-S 0xCFC00 '
    f'--pad-header '
    f'\"{zephyr_bin_path}\" '
    f'\"{signed_bin_path}\""'
    )
    subprocess.run(full_cmd, shell=True, check=True)


def generate_keys(name, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    ecdsa_key = ECC.generate(curve='P-256')
    with open(os.path.join(output_dir, f"{name}_boot.pem"), "wt") as f:
        f.write(ecdsa_key.export_key(format="PEM"))

    with open(os.path.join(output_dir, f"{name}_boot_pub.pem"), "wt") as f:
        f.write(ecdsa_key.public_key().export_key(format="PEM"))

    aes_key = get_random_bytes(32)
    with open(os.path.join(output_dir, f"{name}_cipher.pem"), "wb") as f:
        f.write(aes_key)

    return aes_key

def verify_crc(blob: bytes):
    data = blob[:MAX_BLOB_SIZE - 4]
    stored = struct.unpack('<I', blob[MAX_BLOB_SIZE - 4:])[0]
    computed = compute_crc32(data)
    print(f"[Check] Stored CRC:   0x{stored:08X}")
    print(f"[Check] Computed CRC: 0x{computed:08X}")
    print("✅ Match!" if stored == computed else "❌ CRC mismatch")






def compute_crc32(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF

def create_encrypted_config_blob(aes_key, config_path, device_id):
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"'{CONFIG_FILE}' not found")

    with open(config_path, "r") as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    lines = []
    for idx, line in enumerate(raw_lines):
        parts = line.split(",", 1)
        if len(parts) != 2:
            raise ValueError(f"Line {idx+1} must contain a comma separating key and value: '{line}'")
        key, value = parts
        key = key.strip()
        value = value.strip()
        if not key or not value:
            raise ValueError(f"Line {idx+1} has empty key or value.")
        lines.append((key, value))

    blob_data = bytearray()
    #blob_data.extend(MAGIC_HEADER)
    #blob_data.extend(b'\x00\x00')  # Placeholder for entry count

    entry_structs = []

    for idx, (key, value) in enumerate(lines):
        aad = key.encode()
        plaintext = value.encode()
        iv = get_random_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        full_ciphertext = ciphertext + tag

        entry = (
            struct.pack('<B', len(iv)) +               # 1 byte IV length
            iv +                                       # IV (12 bytes)
            struct.pack('<H', len(aad)) +              # 2 bytes AAD length
            aad +                                      # AAD
            struct.pack('<H', len(full_ciphertext)) +  # 2 bytes ciphertext length
            full_ciphertext                            # ciphertext + tag
        )

        if len(entry) > ENTRY_SIZE:
            raise ValueError(f"Entry {idx} exceeds {ENTRY_SIZE} bytes ({len(entry)}). AAD='{key}', plaintext='{value}'")

        padded_entry = entry.ljust(ENTRY_SIZE, b'\x00')
        entry_structs.append(padded_entry)

    for entry in entry_structs:
        blob_data.extend(entry)

    # Patch entry count at offset 4
    struct.pack_into('<H', blob_data, 4, len(entry_structs))

    # === Step 1: Pad to MAX_BLOB_SIZE - 4 ===
    pad_len = MAX_BLOB_SIZE - 4 - len(blob_data)
    if pad_len < 0:
        raise ValueError(f"Encrypted blob exceeds {MAX_BLOB_SIZE - 4} bytes before CRC")
    blob_data.extend(b'\xFF' * pad_len)

    # === Step 2: Compute CRC over first MAX_BLOB_SIZE - 4 bytes ===
    crc = compute_crc32(blob_data[:MAX_BLOB_SIZE - 4])

    # === Step 3: Append CRC at offset MAX_BLOB_SIZE - 4 ===
    blob_data.extend(struct.pack('<I', crc))  # CRC in little endian

    assert len(blob_data) == MAX_BLOB_SIZE, "Final blob is not the expected size"

    # Summary
    print(f"🧩 Encrypted entries: {len(entry_structs)}")
    for i in range(len(entry_structs)):
        offset = 6 + i * ENTRY_SIZE
        print(f"   ➕ Entry {i} offset: {offset} (0x{offset:04X})")
    print(f"   🔒 CRC32 computed: 0x{crc:08X} at offset 0x{MAX_BLOB_SIZE - 4:04X}")
    print(f"   📦 Final blob size: {len(blob_data)} bytes")

    verify_crc(blob_data)
    return bytes(blob_data)





def create_blob_hex_file(blob_data, output_path):
    """Create Intel HEX file from blob data"""
    ih = IntelHex()
    ih.frombytes(blob_data, offset=BLOB_ADDRESS)
    ih.write_hex_file(output_path)
    print(f"✅ Created blob.hex with {len(blob_data)} bytes at address 0x{BLOB_ADDRESS:08X}")

def merge_hex_files(partition_hex_path, blob_hex_path, output_path):
    """Merge partition firmware with encrypted config blob"""
    try:
        # Load partition firmware hex
        ih_partition = IntelHex()
        ih_partition.loadfile(partition_hex_path, format='hex')
        
        # Load blob hex
        ih_blob = IntelHex()
        ih_blob.loadfile(blob_hex_path, format='hex')
        
        # Merge blob into partition firmware
        ih_partition.merge(ih_blob, overlap='replace')
        
        # Write merged result
        ih_partition.write_hex_file(output_path)
        print(f"✅ Merged firmware and config blob into {output_path}")
        
    except Exception as e:
        print(f"❌ Failed to merge hex files: {e}")
        raise

def write_key_to_c_array(key_bytes, var_name, c_path):
    array = ', '.join(f'0x{b:02x}' for b in key_bytes)
    content = "#include <stdint.h>\n\n"
    content += f"const uint8_t {var_name}[{len(key_bytes)}] = {{ {array} }};\n"
    with open(c_path, "w") as f:
        f.write(content)

def convert_pem_to_c_array(file_path, var_name, output_path):
    with open(file_path, "rb") as f:
        data = f.read()
    array = ', '.join(f'0x{b:02x}' for b in data)
    content = "#include <stdint.h>\n\n"
    content += f"const uint8_t {var_name}[{len(data)}] = {{ {array} }};\n"
    with open(output_path, "w") as f:
        f.write(content)

def export_keys_to_project(aes_key_path, script_dir, cert_info):
    aes_out_path = os.path.join(script_dir, "partition_kes", "src", "aes.c")
    ca_path = cert_info["ca"]
    pub_path = cert_info["pub"]
    priv_path = cert_info["priv"]
    os.makedirs(os.path.dirname(aes_out_path), exist_ok=True)

    with open(aes_key_path, "rb") as f:
        aes_key = f.read()
    write_key_to_c_array(aes_key, "aes_key", aes_out_path)

    convert_pem_to_c_array(ca_path, "ca_cert", os.path.join(script_dir, "partition_kes", "src", "ca.c"))
    convert_pem_to_c_array(pub_path, "public_cert", os.path.join(script_dir, "partition_kes", "src", "public.c"))
    convert_pem_to_c_array(priv_path, "private_key", os.path.join(script_dir, "partition_kes", "src", "private.c"))

def write_sysbuild_conf(script_dir, boot_pem_path):
    """Writes partition_kes/sysbuild.conf with secure-boot settings"""
    sysbuild_dir = os.path.join(script_dir, "partition_kes")
    os.makedirs(sysbuild_dir, exist_ok=True)
    conf_path = os.path.join(sysbuild_dir, "sysbuild.conf")

    win_path = boot_pem_path.replace(os.sep, "/")

    lines = [
        "SB_CONFIG_BOOTLOADER_MCUBOOT=y",
        f'SB_CONFIG_BOOT_SIGNATURE_KEY_FILE="{win_path}"',
        "SB_CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y",
        f'SB_CONFIG_SECURE_BOOT_SIGNING_KEY_FILE="{win_path}"',
        "SB_CONFIG_SECURE_BOOT_SIGNATURE_TYPE_ECDSA=y",
        ""
    ]

    with open(conf_path, "w") as f:
        f.write("\n".join(lines))

    print(f"🛠 Updated secure-boot config: {conf_path}")

def clean_build_dirs(script_dir):
    build_path = os.path.join(script_dir, "partition_kes", "build")
    
    if os.path.isdir(build_path):
        try:
            shutil.rmtree(build_path)
            print(f"Deleted build directory: {build_path}")
        except Exception as e:
            print(f"❌ Failed to delete {build_path}: {e}")
    else:
        print(f"Build directory does not exist: {build_path}")

def copy_partition_hex(script_dir, output_dir):
    """Copy the built partition hex file to the device output directory"""
    source_hex = os.path.join(script_dir, "partition_kes", "build", "merged.hex")
    dest_hex = os.path.join(output_dir, "partition.hex")
    
    if not os.path.isfile(source_hex):
        raise FileNotFoundError(f"Built partition hex file not found: {source_hex}")
    
    shutil.copy(source_hex, dest_hex)
    print(f"✅ Copied partition firmware to: {dest_hex}")
    return dest_hex

def main(number_str):
    config_path = os.path.join(script_dir, CONFIG_FILE)

    if not os.path.isfile(config_path):
        print(f"❌ '{CONFIG_FILE}' not found in script directory.")
        sys.exit(1)

    cert_info = parse_config_and_get_cert_paths(script_dir)
    customer = cert_info["customer"]

    device_name = f"nrid{number_str.zfill(3)}"
    customer_dir = os.path.join(script_dir, customer)
    output_dir = os.path.join(customer_dir, device_name)
    os.makedirs(output_dir, exist_ok=True)

    shutil.copy(config_path, os.path.join(output_dir, CONFIG_FILE))


    print(f"Generating keys for {device_name}...")
    aes_key = generate_keys(device_name, output_dir)


    aes_key_path = os.path.join(output_dir, f"{device_name}_cipher.pem")
    export_keys_to_project(aes_key_path, script_dir, cert_info)


    boot_pem = os.path.join(output_dir, f"{device_name}_boot.pem")
    write_sysbuild_conf(script_dir, boot_pem)


    print("Cleaning build directories...")
    clean_build_dirs(script_dir)
    
    print("Building partition_kes...")
    if not build_partition_kes(source_dir_1):
        print("Build failed. Exiting.")
        sys.exit(1)


    partition_hex_path = copy_partition_hex(script_dir, output_dir)

    print("Creating encrypted config blob...")
    blob_data = create_encrypted_config_blob(aes_key, config_path, device_name)

    blob_hex_slot0 = os.path.join(output_dir, "blob_slot0.hex")
    blob_hex_slot1 = os.path.join(output_dir, "blob_slot1.hex")
    combined_blob_hex = os.path.join(output_dir, "blob_combined.hex")

    create_dual_blob_hex_files(blob_data, blob_hex_slot0, blob_hex_slot1, combined_blob_hex)

    merged_hex_path = os.path.join(output_dir, "merged.hex")
    merge_hex_files(partition_hex_path, combined_blob_hex, merged_hex_path)

    print(" Signing application binary...")
    sign_application_image(customer, device_name, script_dir)

    dfu_application(output_dir)

    print(f"✅ {device_name} generated successfully!")
    print(f"✅Output directory: {output_dir}")
    print(f"✅Files created:")
    print(f"   - partition.hex (base firmware)")
    print(f"   - blob.hex (encrypted config)")
    print(f"   - merged.hex (final firmware with config)")
    print(f" Config blob info:")
    print(f"   - Address: 0x{BLOB_ADDRESS:08X}")
    print(f"   - Size: {len(blob_data)} bytes")
    print(f"   - Magic: {MAGIC_HEADER.hex()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_config_bundle.py <nrid_number>")
        print("Example: python generate_config_bundle.py 001")
        sys.exit(1)

    main(sys.argv[1])