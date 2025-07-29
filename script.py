import os
import sys
import shutil
import subprocess
import multiprocessing
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

AAD = b"Field_mqtt_hostname"
CONFIG_FILE = "config_settings.txt"
sdk_workspace = r"C:\ncs\v3.0.2"
sdk_version = "v3.0.2"
script_dir = os.path.dirname(os.path.realpath(__file__))
source_dir_1 = os.path.join(script_dir, "partition_kes")
source_dir_2 = os.path.join(script_dir, "thingy")


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

def build_with_correct_flow(source_dir):
    
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
        print(f"✅ Build succeeded for {source_dir} via nrfutil and correct workspace.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed for {source_dir}.")
        print(e)
        return False


def run_parallel_builds(source_dirs):
    """Run builds in parallel using multiprocessing"""
    with multiprocessing.Pool(processes=len(source_dirs)) as pool:
        print(f" Starting parallel builds for {len(source_dirs)} projects...")
        results = pool.map(build_with_correct_flow, source_dirs)
    
    for i, (source_dir, success) in enumerate(zip(source_dirs, results)):
        if success:
            print(f"✅ Build {i+1} completed successfully: {os.path.basename(source_dir)}")
        else:
            print(f"❌ Build {i+1} failed: {os.path.basename(source_dir)}")
    
    all_successful = all(results)
    if all_successful:
        print(" All parallel builds completed successfully!")
    else:
        print(" Some builds failed. Check the output above for details.")
    
    return all_successful


def format_c_array(name, data):
    hex_bytes = ', '.join(f"0x{b:02x}" for b in data)
    return f"uint8_t {name}[{len(data)}] = {{{hex_bytes}}};\n\n"

def generate_keys(name, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    ecdsa_key = ECC.generate(curve='P-256')
    with open(os.path.join(output_dir, f"{name}_boot_private.pem"), "wt") as f:
        f.write(ecdsa_key.export_key(format="PEM"))
    
    with open(os.path.join(output_dir, f"{name}_boot.pem"), "wt") as f:
        f.write(ecdsa_key.public_key().export_key(format="PEM"))

    aes_key = get_random_bytes(32)
    with open(os.path.join(output_dir, f"{name}_cipher.pem"), "wb") as f:
        f.write(aes_key)

    return aes_key

def encrypt_lines(aes_key, config_path, output_c_path):
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"'{CONFIG_FILE}' not found in script directory")

    with open(config_path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    c_output = "#include <stdint.h>\n#include <inttypes.h>\n\n"

    for idx, line in enumerate(lines, 1):
        iv = get_random_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        cipher.update(AAD)
        ciphertext, tag = cipher.encrypt_and_digest(line.encode())
        full_ciphertext = ciphertext + tag

        c_output += format_c_array(f"config_iv_{idx}", iv)
        c_output += format_c_array(f"encrypted_config_{idx}", full_ciphertext)
        c_output += format_c_array(f"additional_auth_data_{idx}", AAD)

    with open(output_c_path, "w") as f:
        f.write(c_output)

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
    ca_path   = cert_info["ca"]
    pub_path  = cert_info["pub"]
    priv_path = cert_info["priv"]
    os.makedirs(os.path.dirname(aes_out_path), exist_ok=True)


    with open(aes_key_path, "rb") as f:
        aes_key = f.read()
    write_key_to_c_array(aes_key, "aes_key", aes_out_path)

    convert_pem_to_c_array(ca_path,   "ca_cert",     os.path.join(script_dir, "partition_kes", "src", "ca.c"))
    convert_pem_to_c_array(pub_path,  "public_cert", os.path.join(script_dir, "partition_kes", "src", "public.c"))
    convert_pem_to_c_array(priv_path, "private_key", os.path.join(script_dir, "partition_kes", "src", "private.c"))

def write_sysbuild_conf(script_dir, boot_pem_path):
    """
    Writes partition_kes/sysbuild.conf with the secure‑boot settings, pointing
    at the generated boot.pem file.
    """
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

def write_sysbuild_conf_for_thingy(boot_key_path, script_dir):
    boot_key_path = os.path.abspath(boot_key_path).replace("\\", "/")

    content = (
        "SB_CONFIG_BOOTLOADER_MCUBOOT=y\n"
        f'SB_CONFIG_BOOT_SIGNATURE_KEY_FILE="{boot_key_path}"\n'
        "SB_CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y\n"
        f'SB_CONFIG_SECURE_BOOT_SIGNING_KEY_FILE="{boot_key_path}"\n'
        "SB_CONFIG_SECURE_BOOT_SIGNATURE_TYPE_ECDSA=y\n"
    )

    thingy_sysbuild_path = os.path.join(script_dir, "thingy", "sysbuild.conf")
    os.makedirs(os.path.dirname(thingy_sysbuild_path), exist_ok=True)

    with open(thingy_sysbuild_path, "w") as f:
        f.write(content)

    print(f"✅ sysbuild.conf written to: thingy/sysbuild.conf")

def copy_dfu_zip(script_dir, output_dir=None):
    dfu_zip_path = os.path.join(script_dir, "thingy", "build", "dfu_application.zip")

    if not os.path.isfile(dfu_zip_path):
        print("❌ dfu_application.zip not found.")
        return

    if output_dir is None:
        output_dir = script_dir

    out_path = os.path.join(output_dir, "app.zip")
    shutil.copy(dfu_zip_path, out_path)
    print(f"✅ dfu_application.zip copied to: {out_path}")



def copy_merged_hex(script_dir, output_dir=None):
    merged_hex_path = os.path.join(script_dir, "partition_kes", "build", "merged.hex")
    
    if not os.path.isfile(merged_hex_path):
        print("❌ merged.hex not found.")
        return

    if output_dir is None:
        output_dir = script_dir

    out_path = os.path.join(output_dir, "partition.hex")
    shutil.copy(merged_hex_path, out_path)
    print(f"✅ merged.hex copied to: {out_path}")


def clean_build_dirs(script_dir):
    build_paths = [
        os.path.join(script_dir, "thingy", "build"),
        os.path.join(script_dir, "partition_kes", "build"),
    ]

    for path in build_paths:
        if os.path.isdir(path):
            try:
                shutil.rmtree(path)
                print(f"🧹 Deleted build directory: {path}")
            except Exception as e:
                print(f"❌ Failed to delete {path}: {e}")
        else:
            print(f"ℹBuild directory does not exist: {path}")

def main(number_str):
    config_path = os.path.join(script_dir, CONFIG_FILE)

    if not os.path.isfile(config_path):
        print(f"❌ '{CONFIG_FILE}' not found in script directory.")
        sys.exit(1)

    cert_info = parse_config_and_get_cert_paths(script_dir)
    customer = cert_info["customer"]
    sec_tag = cert_info["sec_tag"]

    device_name = f"nrid{number_str.zfill(3)}"
    customer_dir = os.path.join(script_dir, customer)
    output_dir = os.path.join(customer_dir, device_name)
    os.makedirs(output_dir, exist_ok=True)
    boot_key_path = os.path.join(output_dir, f"{device_name}_boot.pem")

    shutil.copy(config_path, os.path.join(output_dir, CONFIG_FILE))


    aes_key = generate_keys(device_name, output_dir)

    output_c_file = os.path.join(output_dir, "encrypted_config.c")


    encrypt_lines(aes_key, config_path, output_c_file)


    thingy_dir = os.path.join(script_dir, "thingy", "src")
    os.makedirs(thingy_dir, exist_ok=True)
    shutil.copy(output_c_file, os.path.join(thingy_dir, "encrypted_config.c"))
    print(f" Copied encrypted_config.c to: thingy/src/")

    print(f"✅ {device_name} generated in '{customer}/'")
    print(f" Folder: {output_dir}")

    aes_key_path = os.path.join(output_dir, f"{device_name}_cipher.pem")
    export_keys_to_project(aes_key_path, script_dir, cert_info)

    boot_pem = os.path.join(output_dir, f"{device_name}_boot.pem")
    write_sysbuild_conf(script_dir, boot_pem)


    write_sysbuild_conf_for_thingy(boot_key_path, script_dir)

    clean_build_dirs(script_dir)
    clean_build_dirs(script_dir)
    
    # Run builds in parallel
    source_dirs = [source_dir_1, source_dir_2]
    build_success = run_parallel_builds(source_dirs)
    
    if not build_success:
        print("❌ One or more builds failed. Exiting.")
        sys.exit(1)

    copy_dfu_zip(script_dir, output_dir)
    copy_merged_hex(script_dir, output_dir)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    
    if len(sys.argv) != 2:
        print("Usage: python generate_config_bundle.py <nrid_number>")
        print("Example: python generate_config_bundle.py 001")
        sys.exit(1)

    main(sys.argv[1])

