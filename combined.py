import os
import sys
import shutil
import subprocess
import struct
import json
import time
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

# Hex blob configuration
BLOB_ADDRESS = 0xfb400  # Flash address to write the encrypted config blob
MAX_BLOB_SIZE =  19456    # Maximum size of the flash blob area
MAGIC_HEADER = b'\xAB\xCD\xEF\x12'  # 4-byte magic number for identification


def dfu_application(device_dir, binary_filename="zephyr_signed.bin", dfu_name="dfu_application.zip"):
    """
    Create a DFU package zip with a manifest.json and the signed binary inside.
    
    Args:
        device_dir (str): Path to device folder (e.g., .../bob/nrid001)
        binary_filename (str): Name of the signed .bin file (default: zephyr_signed.bin)
        dfu_name (str): Name of the final output zip file
    """
    # Paths
    bin_path = os.path.join(device_dir, binary_filename)
    temp_dfu_dir = os.path.join(device_dir, "dfu_tmp")
    manifest_path = os.path.join(temp_dfu_dir, "manifest.json")
    dfu_zip_path = os.path.join(device_dir, dfu_name)

    # Ensure signed bin exists
    if not os.path.isfile(bin_path):
        raise FileNotFoundError(f"❌ Signed binary not found: {bin_path}")

    # Create temp DFU directory
    os.makedirs(temp_dfu_dir, exist_ok=True)

    # Copy binary to DFU folder
    bin_copy_path = os.path.join(temp_dfu_dir, binary_filename)
    shutil.copy(bin_path, bin_copy_path)

    # Gather metadata
    modtime = int(os.path.getmtime(bin_copy_path))
    size = os.path.getsize(bin_copy_path)
    now = int(time.time())

    # Build manifest
    manifest = {
        "format-version": 1,
        "time": now,
        "files": [
            {
                "type": "application",
                "board": "kestrel",
                "soc": "nrf9151",
                "load_address": 0x48000,  # Adjust if needed
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

    # Write manifest
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=4)

    print(f"📝 Created DFU manifest at {manifest_path}")

    # Zip it
    with ZipFile(dfu_zip_path, 'w') as zf:
        zf.write(manifest_path, arcname="manifest.json")
        zf.write(bin_copy_path, arcname=binary_filename)

    print(f"✅ Created DFU package: {dfu_zip_path}")

    # Cleanup temp directory
    shutil.rmtree(temp_dfu_dir)
    print(f"🧹 Cleaned up temporary folder: {temp_dfu_dir}")

def parse_config_and_get_cert_paths(script_dir, config_filename="config_settings.txt"):
    config_path = os.path.join(script_dir, config_filename)

    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"Config file not found at: {config_path}")

    with open(config_path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    if len(lines) < 2:
        raise ValueError("Config file must contain at least two non-empty lines (customer and security tag).")

    customer = lines[0]
    sec_tag = lines[1]

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
    sdk_version = "v3.0.2"  # Ensure this matches your system
    zephyr_bin_path = os.path.join(script_dir, "zephyr.bin")
    
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
    f'--version 1.0.0 '
    f'-S 0xCFE00 '
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

def create_encrypted_config_blob(aes_key, config_path, device_id):
    """Create a structured blob containing encrypted config data"""
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"'{CONFIG_FILE}' not found")

    with open(config_path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    # Prepend device ID
    device_line = f"{device_id}"
    lines.insert(0, device_line)

    blob_data = bytearray()
    entry_offsets = []  # For logging/debugging
    entry_structs = []

    # Add magic header (4 bytes)
    blob_data.extend(MAGIC_HEADER)

    # Placeholder for entry count (2 bytes)
    blob_data.extend(b'\x00\x00')  # Will be overwritten after loop

    for line in lines:
        entry_offset = len(blob_data)
        entry_offsets.append(entry_offset)

        iv = get_random_bytes(12)  # 12-byte IV
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        cipher.update(AAD)
        ciphertext, tag = cipher.encrypt_and_digest(line.encode())
        full_ciphertext = ciphertext + tag

        entry_struct = (
            struct.pack('<B', len(iv)) +     # IV length
            iv +                              # IV
            struct.pack('<H', len(AAD)) +     # AAD length
            AAD +                             # AAD
            struct.pack('<H', len(full_ciphertext)) +  # Cipher+tag length
            full_ciphertext                   # Ciphertext + tag
        )
        entry_structs.append(entry_struct)

    # Now finalize blob by appending all structured entries
    for entry in entry_structs:
        blob_data.extend(entry)

    # Now patch the real entry count
    struct.pack_into('<H', blob_data, 4, len(entry_structs))

    # Ensure blob fits
    if len(blob_data) > MAX_BLOB_SIZE:
        raise ValueError(f"Encrypted config blob ({len(blob_data)} bytes) exceeds maximum size ({MAX_BLOB_SIZE} bytes)")

    # Pad with zeros
    blob_data.extend(b'\x00' * (MAX_BLOB_SIZE - len(blob_data)))

    # Optional debug log
    print(f"🧩 Encrypted entries: {len(lines)}")
    for i, offset in enumerate(entry_offsets):
        print(f"   ➕ Entry {i} offset: {offset}")

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
            print(f"🧹 Deleted build directory: {build_path}")
        except Exception as e:
            print(f"❌ Failed to delete {build_path}: {e}")
    else:
        print(f"ℹ️ Build directory does not exist: {build_path}")

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

    # Copy config file to device directory
    shutil.copy(config_path, os.path.join(output_dir, CONFIG_FILE))

    # Generate cryptographic keys
    print(f"🔑 Generating keys for {device_name}...")
    aes_key = generate_keys(device_name, output_dir)

    # Export keys to partition_kes project
    aes_key_path = os.path.join(output_dir, f"{device_name}_cipher.pem")
    export_keys_to_project(aes_key_path, script_dir, cert_info)

    # Configure secure boot
    boot_pem = os.path.join(output_dir, f"{device_name}_boot.pem")
    write_sysbuild_conf(script_dir, boot_pem)

    # Clean and build partition_kes
    print("🧹 Cleaning build directories...")
    clean_build_dirs(script_dir)
    
    print("🔨 Building partition_kes...")
    if not build_partition_kes(source_dir_1):
        print("❌ Build failed. Exiting.")
        sys.exit(1)

    # Copy partition hex to device directory
    partition_hex_path = copy_partition_hex(script_dir, output_dir)

    # Create encrypted config blob
    print("🔐 Creating encrypted config blob...")
    blob_data = create_encrypted_config_blob(aes_key, config_path, device_name)
    
    # Create blob hex file
    blob_hex_path = os.path.join(output_dir, "blob.hex")
    create_blob_hex_file(blob_data, blob_hex_path)

    # Merge partition firmware with config blob
    merged_hex_path = os.path.join(output_dir, "merged.hex")
    merge_hex_files(partition_hex_path, blob_hex_path, merged_hex_path)

    print("✍️ Signing application binary...")
    sign_application_image(customer, device_name, script_dir)

    dfu_application(output_dir)

    print(f"✅ {device_name} generated successfully!")
    print(f"📁 Output directory: {output_dir}")
    print(f"📄 Files created:")
    print(f"   - partition.hex (base firmware)")
    print(f"   - blob.hex (encrypted config)")
    print(f"   - merged.hex (final firmware with config)")
    print(f"🔧 Config blob info:")
    print(f"   - Address: 0x{BLOB_ADDRESS:08X}")
    print(f"   - Size: {len(blob_data)} bytes")
    print(f"   - Magic: {MAGIC_HEADER.hex()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_config_bundle.py <nrid_number>")
        print("Example: python generate_config_bundle.py 001")
        sys.exit(1)

    main(sys.argv[1])