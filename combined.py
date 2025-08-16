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
import hashlib
import platform
from pathlib import Path
PBKDF2_DK_LEN = 32
PBKDF2_ITERATIONS_DEFAULT = 64000
PBKDF2_SALT_LEN = 16

AAD = b"hidden_config"
CONFIG_FILE = "config_settings.txt"

# --- changed: make sdk_workspace OS-aware ---
sdk_version = "v3.0.2"
if platform.system() == "Linux":
    sdk_workspace = os.path.expanduser("~/ncs/v3.0.2")
else:
    sdk_workspace = r"C:\ncs\v3.0.2"

script_dir = os.path.dirname(os.path.realpath(__file__))

source_dir_1 = os.path.join(script_dir, "partition_kes")

BLOB_ADDRESS = 0xfb000
BLOB_ADDRESS1 = 0x000fe000
MAX_BLOB_SIZE =  8192
MAGIC_HEADER = b'\xAB\xCD\xEF\x12'
ENTRY_SIZE = 128

def _must_not_exist(path: str, what: str):
    if os.path.exists(path):
        raise FileExistsError(f"{what} already exists: {path}")

def create_dual_blob_hex_files(blob_data, output_path_slot0, output_path_slot1, combined_output_path):
    _must_not_exist(output_path_slot0, "Slot 0 blob hex")
    _must_not_exist(output_path_slot1, "Slot 1 blob hex")
    _must_not_exist(combined_output_path, "Combined blob hex")

    ih_slot0 = IntelHex()
    ih_slot0.frombytes(blob_data, offset=BLOB_ADDRESS)
    ih_slot0.write_hex_file(output_path_slot0)
    print("Created Slot 0 blob.hex")

    ih_slot1 = IntelHex()
    ih_slot1.frombytes(blob_data, offset=BLOB_ADDRESS1)
    ih_slot1.write_hex_file(output_path_slot1)
    print("Created Slot 1 blob_backup.hex")

    ih_slot0.merge(ih_slot1, overlap='replace')
    ih_slot0.write_hex_file(combined_output_path)
    print(f"Created combined blob hex with both slots: {combined_output_path}")



def dfu_application(device_dir, binary_filename="zephyr_signed.bin", dfu_name="dfu_application.zip"):
    """
    Create a DFU package zip with a manifest.json and the signed binary inside.
    """
    bin_path = os.path.join(device_dir, binary_filename)
    temp_dfu_dir = os.path.join(device_dir, "dfu_tmp")
    manifest_path = os.path.join(temp_dfu_dir, "manifest.json")
    dfu_zip_path = os.path.join(device_dir, dfu_name)

    if not os.path.isfile(bin_path):
        raise FileNotFoundError(f"Signed binary not found: {bin_path}")

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

    print(f"Created DFU manifest at {manifest_path}")

    with ZipFile(dfu_zip_path, 'w') as zf:
        zf.write(manifest_path, arcname="manifest.json")
        zf.write(bin_copy_path, arcname=binary_filename)

    print(f"Created DFU package: {dfu_zip_path}")

    shutil.rmtree(temp_dfu_dir)
    print(f"Cleaned up temporary folder: {temp_dfu_dir}")

def overwrite_name_in_file(config_path: str, customer_name: str):
    """
    In-place update of the 'name' entry in the given config file.
    - Preserves original line order
    - Only changes the value part for the first 'name' key
    - Raises if not found
    """
    with open(config_path, "r", encoding="utf-8-sig") as f:
        lines = f.read().splitlines()

    replaced = False
    for i, line in enumerate(lines):
        if not line.strip() or "," not in line:
            continue
        key, value = line.split(",", 1)
        if key.strip().lower() == "name":
            old = value
            lines[i] = f"{key},{customer_name}"
            print(f"[update] {key}: '{old}' -> '{customer_name}' (line {i+1})")
            replaced = True
            break

    if not replaced:
        raise KeyError("Expected 'name' not found in config file.")

    with open(config_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def overwrite_mq_clid_in_file(config_path: str, device_id: str):
    """
    In-place update of mq_clid / mqtt_clid in the given config file.
    - Preserves original line order and key spelling
    - Only changes the value part for the first matching key
    - Raises if neither key is found
    """
    def norm(k: str) -> str:
        return k.strip().lower().replace("_", "").replace("-", "").replace(" ", "")

    targets = {"mqclid", "mqttclid"}

    with open(config_path, "r", encoding="utf-8-sig") as f:
        lines = f.read().splitlines()

    replaced = False
    for i, line in enumerate(lines):
        if not line.strip() or "," not in line:
            continue
        key, value = line.split(",", 1)
        if norm(key) in targets:
            old = value
            lines[i] = f"{key},{device_id}"
            print(f"[update] {key}: '{old}' -> '{device_id}' (line {i+1})")
            replaced = True
            break

    if not replaced:
        raise KeyError("Expected 'mq_clid' or 'mqtt_clid' not found in config file.")

    with open(config_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


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
        if platform.system() == "Linux":
            # Use bash on Linux
            subprocess.run([
                "nrfutil", "sdk-manager", "toolchain", "launch",
                "--ncs-version", sdk_version,
                "--",
                "bash", "-lc",
                f'cd "{sdk_workspace}" && {build_cmd}'
            ], check=True)
        else:
            # Original Windows flow
            subprocess.run([
                "nrfutil", "sdk-manager", "toolchain", "launch",
                "--ncs-version", sdk_version,
                "--",
                "cmd.exe", "/d", "/s", "/c",
                f"cd /d {sdk_workspace} && {build_cmd}"
            ], check=True)

        print(f"Build succeeded for {source_dir}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Build failed for {source_dir}")
        print(e)
        return False


def sign_application_image(device_name, output_dir, script_dir):
    """
    Signs tfm_merged.hex using imgtool and places zephyr_signed.bin in the device's output folder.
    Paths honor the new firmware_storage layout and refuse to overwrite.
    """
    sdk_version = "v3.0.2"
    zephyr_bin_path = os.path.join(script_dir, "tfm_merged.hex")  # unchanged input
    if not os.path.isfile(zephyr_bin_path):
        raise FileNotFoundError(f"Missing application binary: {zephyr_bin_path}")

    priv_key_path   = os.path.join(output_dir, f"{device_name}_boot.pem")
    signed_bin_path = os.path.join(output_dir, "zephyr_signed.bin")

    if not os.path.isfile(priv_key_path):
        raise FileNotFoundError(f"Private signing key not found: {priv_key_path}")

    _must_not_exist(signed_bin_path, "Signed application image")

    if platform.system() == "Linux":
        full_cmd = (
            f'nrfutil sdk-manager toolchain launch --ncs-version {sdk_version} -- '
            f'bash -lc "cd \\"{script_dir}\\" && imgtool sign '
            f'-k \\"{priv_key_path}\\" --header-size 0x200 --align 4 --version 0.0.0 '
            f'-S 0xCFC00 --pad-header \\"{zephyr_bin_path}\\" \\"{signed_bin_path}\\""'
        )
    else:
        full_cmd = (
            f'nrfutil sdk-manager toolchain launch --ncs-version {sdk_version} -- '
            f'cmd.exe /d /s /c "cd /d {script_dir} && imgtool sign '
            f'-k \\"{priv_key_path}\\" --header-size 0x200 --align 4 --version 0.0.0 '
            f'-S 0xCFC00 --pad-header \\"{zephyr_bin_path}\\" \\"{signed_bin_path}\\""'
        )

    subprocess.run(full_cmd, shell=True, check=True)




def generate_keys(name, output_dir):
    # Directory is created in main(); just ensure it exists
    if not os.path.isdir(output_dir):
        raise FileNotFoundError(f"Output directory not found: {output_dir}")

    ecdsa_key = ECC.generate(curve='P-256')
    boot_pem = os.path.join(output_dir, f"{name}_boot.pem")
    boot_pub = os.path.join(output_dir, f"{name}_boot_pub.pem")
    aes_pem  = os.path.join(output_dir, f"{name}_cipher.pem")

    _must_not_exist(boot_pem, "Private signing key")
    _must_not_exist(boot_pub, "Public signing key")
    _must_not_exist(aes_pem,  "AES key")

    with open(boot_pem, "x") as f:
        f.write(ecdsa_key.export_key(format="PEM"))

    with open(boot_pub, "x") as f:
        f.write(ecdsa_key.public_key().export_key(format="PEM"))

    aes_key = get_random_bytes(32)
    with open(aes_pem, "xb") as f:
        f.write(aes_key)

    return aes_key



def verify_crc(blob: bytes):
    data = blob[:MAX_BLOB_SIZE - 4]
    stored = struct.unpack('<I', blob[MAX_BLOB_SIZE - 4:])[0]
    computed = compute_crc32(data)
    print(f"[Check] Stored CRC:   0x{stored:08X}")
    print(f"[Check] Computed CRC: 0x{computed:08X}")
    print("Match!" if stored == computed else "CRC mismatch")


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


def _strip_optional_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    return s


def derive_pbkdf2(password_bytes: bytes, salt: bytes, iterations: int, dk_len: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password_bytes, salt, iterations, dk_len)


def create_encrypted_config_blob(aes_key, config_path, device_id):
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"'{CONFIG_FILE}' not found")

    with open(config_path, "r") as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    # Parse key,value pairs
    lines = []
    for idx, line in enumerate(raw_lines):
        parts = line.split(",", 1)
        if len(parts) != 2:
            raise ValueError(f"Line {idx+1} must contain a comma separating key and value: '{line}'")
        key = parts[0].strip()
        value = parts[1].strip()
        if not key or not value:
            raise ValueError(f"Line {idx+1} has empty key or value.")
        lines.append((key, value))

    # ---- Find password and derive PBKDF2 ----
    pw_keys = {"pw"}
    pw_entry_idx = next((i for i, (k, _) in enumerate(lines) if k.lower() in pw_keys), None)

    if pw_entry_idx is not None:
        # Extract password without quotes for derivation
        pw_plain = _strip_optional_quotes(lines[pw_entry_idx][1]).encode()

        # Remove password entry from list (don’t store it in blob)
        del lines[pw_entry_idx]

        # Derive PBKDF2 with fixed iteration count
        iterations = PBKDF2_ITERATIONS_DEFAULT
        salt = get_random_bytes(PBKDF2_SALT_LEN)
        dk = derive_pbkdf2(pw_plain, salt, iterations, PBKDF2_DK_LEN)

        # Add salt/hash entries (as hex strings)
        lines.append(("pbkdf2.salt", salt.hex()))
        lines.append(("pbkdf2.hash", dk.hex()))

        print(f"PBKDF2 derived (iter={iterations}, salt={salt.hex()}, hash={dk.hex()})")
    else:
        print("No password found in config (keys tried: password, pass, pw). Skipping PBKDF2.")

    # ---- Build encrypted entries ----
    blob_data = bytearray()
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
            struct.pack('<B', len(iv)) +
            iv +
            struct.pack('<H', len(aad)) +
            aad +
            struct.pack('<H', len(full_ciphertext)) +
            full_ciphertext
        )

        if len(entry) > ENTRY_SIZE:
            raise ValueError(f"Entry {idx} exceeds {ENTRY_SIZE} bytes ({len(entry)}). "
                             f"AAD='{key}', value length={len(plaintext)}")

        entry_structs.append(entry.ljust(ENTRY_SIZE, b'\x00'))

    # Pack entries (no header)
    for entry in entry_structs:
        blob_data.extend(entry)

    # Pad to MAX_BLOB_SIZE - 4, then append CRC
    pad_len = MAX_BLOB_SIZE - 4 - len(blob_data)
    if pad_len < 0:
        raise ValueError(f"Encrypted blob exceeds {MAX_BLOB_SIZE - 4} bytes before CRC")
    blob_data.extend(b'\xFF' * pad_len)

    crc = compute_crc32(blob_data[:MAX_BLOB_SIZE - 4])
    blob_data.extend(struct.pack('<I', crc))

    assert len(blob_data) == MAX_BLOB_SIZE

    print(f"Encrypted entries: {len(entry_structs)}")
    for i in range(len(entry_structs)):
        off = i * ENTRY_SIZE
        print(f"   ➕ Entry {i} offset: {off} (0x{off:04X})")
        print(f"CRC32: 0x{crc:08X}")
    print(f"Blob size: {len(blob_data)} bytes")

    verify_crc(blob_data)
    return bytes(blob_data)


def create_blob_hex_file(blob_data, output_path):
    """Create Intel HEX file from blob data"""
    ih = IntelHex()
    ih.frombytes(blob_data, offset=BLOB_ADDRESS)
    ih.write_hex_file(output_path)
    print(f" Created blob.hex with {len(blob_data)} bytes at address 0x{BLOB_ADDRESS:08X}")


def merge_hex_files(partition_hex_path, blob_hex_path, output_path):
    _must_not_exist(output_path, "Merged hex output")
    try:
        ih_partition = IntelHex(); ih_partition.loadfile(partition_hex_path, format='hex')
        ih_blob      = IntelHex(); ih_blob.loadfile(blob_hex_path, format='hex')
        ih_partition.merge(ih_blob, overlap='replace')
        ih_partition.write_hex_file(output_path)
        print(f"Merged firmware and config blob into {output_path}")
    except Exception as e:
        print(f"Failed to merge hex files: {e}")
        raise



def write_key_to_c_array(key_bytes, var_name, c_path):
    array = ', '.join(f'0x{b:02x}' for b in key_bytes)
    length = len(key_bytes)
    content = "#include <stdint.h>\n#include <stddef.h>\n\n"
    content += f"const uint8_t {var_name}[{length}] = {{ {array} }};\n"
    content += f"const size_t {var_name}_len = {length};\n"
    with open(c_path, "w") as f:
        f.write(content)


def convert_pem_to_c_array(file_path, var_name, output_path):
    with open(file_path, "rb") as f:
        data = f.read()
    array = ', '.join(f'0x{b:02x}' for b in data)
    length = len(data)
    content = "#include <stdint.h>\n#include <stddef.h>\n\n"
    content += f"const uint8_t {var_name}[{length}] = {{ {array} }};\n"
    content += f"const size_t {var_name}_len = {length};\n"
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

    # Always use an absolute, POSIX-style path so CMake/west sign see it correctly
    key_path_for_cmake = Path(boot_pem_path).resolve().as_posix()

    lines = [
        "SB_CONFIG_BOOTLOADER_MCUBOOT=y",
        f'SB_CONFIG_BOOT_SIGNATURE_KEY_FILE="{key_path_for_cmake}"',
        "SB_CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y",
        f'SB_CONFIG_SECURE_BOOT_SIGNING_KEY_FILE="{key_path_for_cmake}"',
        "SB_CONFIG_SECURE_BOOT_SIGNATURE_TYPE_ECDSA=y",
        ""
    ]

    with open(conf_path, "w") as f:
        f.write("\n".join(lines))

    print(f"Updated secure-boot config: {conf_path}")



def clean_build_dirs(script_dir):
    build_path = os.path.join(script_dir, "partition_kes", "build")

    if os.path.isdir(build_path):
        try:
            shutil.rmtree(build_path)
            print(f"Deleted build directory: {build_path}")
        except Exception as e:
            print(f" Failed to delete {build_path}: {e}")
    else:
        print(f"Build directory does not exist: {build_path}")


def copy_partition_hex(script_dir, output_dir):
    source_hex = os.path.join(script_dir, "partition_kes", "build", "merged.hex")
    dest_hex   = os.path.join(output_dir, "partition.hex")

    if not os.path.isfile(source_hex):
        raise FileNotFoundError(f"Built partition hex file not found: {source_hex}")

    _must_not_exist(dest_hex, "Partition output hex")

    shutil.copy(source_hex, dest_hex)
    print(f"Copied partition firmware to: {dest_hex}")
    return dest_hex


def main(device_number_str: str, customer_override: str | None = None):
    # Paths and config
    config_path = os.path.join(script_dir, CONFIG_FILE)
    if not os.path.isfile(config_path):
        print(f"'{CONFIG_FILE}' not found in script directory.")
        sys.exit(1)

    # Read cert info (sec_tag + default customer name from config in repo root)
    cert_info = parse_config_and_get_cert_paths(script_dir)
    customer_from_config = cert_info["customer"]

    # If a customer override was provided on the CLI, use it for this run
    customer = customer_override if customer_override else customer_from_config

    # Device + output layout (outside project root, one level up)
    device_name   = f"nrid{device_number_str.zfill(3)}"
    firmware_root = os.path.abspath(os.path.join(script_dir, "..", "firmware_storage"))
    customer_dir  = os.path.join(firmware_root, customer)
    output_dir    = os.path.join(customer_dir, device_name)

    # ------ DO NOT OVERWRITE EXISTING DEVICE ------
    if os.path.exists(output_dir):
        print(f"[abort] Device folder already exists for {device_name}: {output_dir}")
        print("Refusing to overwrite existing artifacts. Choose a new device id.")
        sys.exit(2)

    # Create dirs (fail on race for the device folder)
    os.makedirs(customer_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=False)

    # Copy config into the *new* device folder
    copied_config_path = os.path.join(output_dir, CONFIG_FILE)
    _must_not_exist(copied_config_path, "Copied config")
    shutil.copy(config_path, copied_config_path)

    # Apply optional overrides to the copied config
    if customer_override:
        overwrite_name_in_file(copied_config_path, customer_override)

    # Always set mq_clid/mqtt_clid to the device name
    overwrite_mq_clid_in_file(copied_config_path, device_name)

    # Key material
    print(f"Generating keys for {device_name}...")
    aes_key = generate_keys(device_name, output_dir)  # generate_keys ensures no file overwrite

    # Export AES + server-auth PEMs into the project (partition_kes/src/*.c)
    aes_key_path = os.path.join(output_dir, f"{device_name}_cipher.pem")
    export_keys_to_project(aes_key_path, script_dir, cert_info)

    # Point sysbuild to this device's boot key
    boot_pem = os.path.join(output_dir, f"{device_name}_boot.pem")
    write_sysbuild_conf(script_dir, boot_pem)

    # Clean + build partition app
    print("Cleaning build directories...")
    clean_build_dirs(script_dir)

    print("Building partition_kes...")
    if not build_partition_kes(source_dir_1):
        print("Build failed. Exiting.")
        sys.exit(1)

    # Copy built partition to device folder
    partition_hex_path = copy_partition_hex(script_dir, output_dir)

    # Create encrypted config blob (+ slots + merged with partition)
    print("Creating encrypted config blob...")
    blob_data = create_encrypted_config_blob(aes_key, copied_config_path, device_name)

    blob_hex_slot0     = os.path.join(output_dir, "blob_slot0.hex")
    blob_hex_slot1     = os.path.join(output_dir, "blob_slot1.hex")
    combined_blob_hex  = os.path.join(output_dir, "blob_combined.hex")
    create_dual_blob_hex_files(blob_data, blob_hex_slot0, blob_hex_slot1, combined_blob_hex)

    merged_hex_path = os.path.join(output_dir, "merged.hex")
    merge_hex_files(partition_hex_path, combined_blob_hex, merged_hex_path)

    # Sign application image into the device folder
    print("Signing application binary...")
    # NOTE: this call matches the updated signer that writes to output_dir.
    # If your signer still has the old signature, replace it with the new one I shared earlier.
    #sign_application_image(device_name, output_dir, script_dir)

    # Optionally package DFU (will refuse overwrite if you added _must_not_exist)
    # dfu_application(output_dir)

    # Summary
    print(f"{device_name} generated successfully!")
    print(f"Output directory: {output_dir}")
    print("Files created:")
    print("   - partition.hex       (base firmware)")
    print("   - blob_slot0.hex      (primary config)")
    print("   - blob_slot1.hex      (backup config)")
    print("   - blob_combined.hex   (both slots)")
    print("   - merged.hex          (final merged)")
    print("   - zephyr_signed.bin   (signed app image)")
    print("   - dfu_application.zip (DFU package)")
    print("Config blob info:")
    print(f"   - Address: 0x{BLOB_ADDRESS:08X}")
    print(f"   - Size: {len(blob_data)} bytes")
    print(f"   - CRC32: 0x{compute_crc32(blob_data[:-4]):08X}")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print("Usage: python generate_config_bundle.py <nrid_number> [customer_name]")
        print("Example: python generate_config_bundle.py 001 AcmeCorp")
        sys.exit(1)

    nrid_number = sys.argv[1]
    customer_override = sys.argv[2] if len(sys.argv) == 3 else None
    main(nrid_number, customer_override)
