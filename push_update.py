#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import platform
from pathlib import Path

# ---------- Defaults / Config ----------
DEFAULT_NCS_VERSION = "v3.0.2"
DEFAULT_INPUT_IMAGE = "tfm_merged.hex"   # resolved relative to this script by default
DEFAULT_VERSION_TXT = "version.txt"      # resolved relative to this script by default

FIRMWARE_STORAGE_DIRNAME = "firmware_storage"  # under repo/.. and under /var/www/html
WEB_ROOT = "/var/www/html"
WEB_FW_ROOT_SUBDIR = FIRMWARE_STORAGE_DIRNAME   # /var/www/html/firmware_storage
WEB_UNSIGNED_SUBDIR = "unsigned_firmware"       # /var/www/html/unsigned_firmware

# imgtool signing parameters (match your current workflow)
IMG_HEADER_SIZE = "0x200"
IMG_ALIGN = "4"
IMG_VERSION = "0.0.0"
IMG_MAX_SIZE = "0xCFC00"  # -S value


def usage_and_exit():
    print(
        "Usage:\n"
        "  push_update.py all [--image PATH] [--version PATH] [--ncs-version V]\n"
        "  push_update.py <customer_name> [--image PATH] [--version PATH] [--ncs-version V]\n\n"
        "Examples:\n"
        "  push_update.py all\n"
        "  push_update.py AcmeCorp --image /home/ubuntu/autobuilder/tfm_merged.hex --version ./version.txt\n"
        "  push_update.py BetaCo --ncs-version v3.0.2\n"
    )
    sys.exit(1)


def parse_args(argv):
    if len(argv) < 2:
        usage_and_exit()

    customer_sel = argv[1]
    image_path = None
    version_path = None
    ncs_version = DEFAULT_NCS_VERSION

    i = 2
    while i < len(argv):
        arg = argv[i]
        if arg == "--image":
            i += 1
            if i >= len(argv): usage_and_exit()
            image_path = argv[i]
        elif arg == "--version":
            i += 1
            if i >= len(argv): usage_and_exit()
            version_path = argv[i]
        elif arg == "--ncs-version":
            i += 1
            if i >= len(argv): usage_and_exit()
            ncs_version = argv[i]
        else:
            print(f"Unknown argument: {arg}")
            usage_and_exit()
        i += 1

    script_dir = os.path.dirname(os.path.realpath(__file__))
    if image_path is None:
        image_path = os.path.join(script_dir, DEFAULT_INPUT_IMAGE)
    if version_path is None:
        version_path = os.path.join(script_dir, DEFAULT_VERSION_TXT)

    return customer_sel, os.path.abspath(image_path), os.path.abspath(version_path), ncs_version, script_dir


def ensure_file_exists(path, what):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"{what} not found: {path}")


def run_imgtool_sign_linux(ncs_version, working_dir, key_path, in_image, out_image):
    cmd = [
        "nrfutil", "sdk-manager", "toolchain", "launch",
        "--ncs-version", ncs_version,
        "--",
        "bash", "-lc",
        (
            f'cd "{working_dir}" && '
            f'imgtool sign '
            f'-k "{key_path}" '
            f'--header-size {IMG_HEADER_SIZE} '
            f'--align {IMG_ALIGN} '
            f'--version {IMG_VERSION} '
            f'-S {IMG_MAX_SIZE} '
            f'--pad-header '
            f'"{in_image}" "{out_image}"'
        )
    ]
    subprocess.run(cmd, check=True)


def run_imgtool_sign_windows(ncs_version, working_dir, key_path, in_image, out_image):
    cmd = [
        "nrfutil", "sdk-manager", "toolchain", "launch",
        "--ncs-version", ncs_version,
        "--",
        "cmd.exe", "/d", "/s", "/c",
        (
            f'cd /d "{working_dir}" && '
            f'imgtool sign '
            f'-k "{key_path}" '
            f'--header-size {IMG_HEADER_SIZE} '
            f'--align {IMG_ALIGN} '
            f'--version {IMG_VERSION} '
            f'-S {IMG_MAX_SIZE} '
            f'--pad-header '
            f'"{in_image}" "{out_image}"'
        )
    ]
    subprocess.run(cmd, check=True)


def sign_image(ncs_version, key_path, input_image, output_image):
    os.makedirs(os.path.dirname(output_image), exist_ok=True)
    key_path = os.path.abspath(key_path)
    input_image = os.path.abspath(input_image)
    output_image = os.path.abspath(output_image)
    working_dir = os.path.dirname(input_image) or "."

    if platform.system() == "Windows":
        run_imgtool_sign_windows(ncs_version, working_dir, key_path, input_image, output_image)
    else:
        run_imgtool_sign_linux(ncs_version, working_dir, key_path, input_image, output_image)


def is_device_dir(path):
    # A device directory is recognized if it contains a file that ends with "_boot.pem"
    try:
        for entry in os.listdir(path):
            if entry.endswith("_boot.pem") and os.path.isfile(os.path.join(path, entry)):
                return True
    except Exception:
        pass
    return False


def find_device_key(path):
    # Return (device_name, key_path) if found
    for entry in os.listdir(path):
        if entry.endswith("_boot.pem"):
            device_name = entry[:-len("_boot.pem")]
            key_path = os.path.join(path, entry)
            return device_name, key_path
    return None, None


def discover_targets(firmware_root, customer_sel):
    """
    Returns:
      customers: set[str] of customer names we will process
      devices: dict[customer] -> list[ (device_dir_abs, device_name, key_path_abs) ]
    """
    customers = set()
    devices = {}

    if not os.path.isdir(firmware_root):
        print(f"[warn] Firmware storage not found: {firmware_root}")
        return customers, devices

    for customer in os.listdir(firmware_root):
        customer_path = os.path.join(firmware_root, customer)
        if not os.path.isdir(customer_path):
            continue
        if customer_sel.lower() != "all" and customer != customer_sel:
            continue

        for root, dirs, files in os.walk(customer_path):
            if is_device_dir(root):
                device_name, key_path = find_device_key(root)
                if device_name and key_path:
                    customers.add(customer)
                    devices.setdefault(customer, []).append((os.path.abspath(root), device_name, os.path.abspath(key_path)))

    return customers, devices


def main():
    customer_sel, image_path, version_path, ncs_version, script_dir = parse_args(sys.argv)

    # Source locations
    firmware_root = os.path.abspath(os.path.join(script_dir, "..", FIRMWARE_STORAGE_DIRNAME))

    # Web output locations
    web_fw_root = os.path.join(WEB_ROOT, WEB_FW_ROOT_SUBDIR)
    web_unsigned_root = os.path.join(WEB_ROOT, WEB_UNSIGNED_SUBDIR)

    # Validate inputs
    ensure_file_exists(image_path, "Input image (tfm_merged.hex)")
    ensure_file_exists(version_path, "Version file (version.txt)")

    # Discover customers/devices
    customers, devices = discover_targets(firmware_root, customer_sel)

    if not customers:
        if customer_sel.lower() == "all":
            print(f"[info] No customers found in {firmware_root}")
        else:
            print(f"[info] Customer '{customer_sel}' not found or has no devices in {firmware_root}")
        sys.exit(0)

    print(f"[plan] NCS={ncs_version}")
    print(f"[plan] Input image: {image_path}")
    print(f"[plan] Version file: {version_path}")
    print(f"[plan] Firmware storage: {firmware_root}")
    print(f"[plan] Web (signed out): {web_fw_root}")
    print(f"[plan] Web (unsigned archive): {web_unsigned_root}")
    print(f"[plan] Customers to process: {', '.join(sorted(customers))}")

    # Read version string once (global) and archive unsigned image exactly once as <version>.hex
    try:
        with open(version_path, "r", encoding="utf-8") as vf:
            version_str = vf.read().strip()
        if not version_str:
            raise ValueError("version.txt is empty")
    except Exception as e:
        print(f"[warn] Could not read version string: {e}")
        version_str = "unknown"

    os.makedirs(web_unsigned_root, exist_ok=True)
    dest_unsigned_hex = os.path.join(web_unsigned_root, f"{version_str}.hex")

    if os.path.exists(dest_unsigned_hex):
        print(f"[skip] Unsigned archive already exists: {dest_unsigned_hex} (preserving history)")
    else:
        try:
            shutil.copy(image_path, dest_unsigned_hex)
            print(f"[ok]   Archived unsigned image -> {dest_unsigned_hex}")
        except Exception as e:
            print(f"[fail] Could not archive unsigned image: {e}")

    # Copy version.txt per customer
    for customer in sorted(customers):
        dest_customer_dir = os.path.join(web_fw_root, customer)
        os.makedirs(dest_customer_dir, exist_ok=True)
        dest_version = os.path.join(dest_customer_dir, "version.txt")
        try:
            shutil.copy(version_path, dest_version)
            print(f"[ok]   Wrote version.txt -> {dest_version}")
        except Exception as e:
            print(f"[fail] Could not write version.txt for {customer}: {e}")

    # Sign per device -> /var/www/html/firmware_storage/{customer}/{device}/zephyr_signed.bin
    total = 0
    signed = 0
    skipped = 0
    failures = 0

    for customer in sorted(customers):
        for device_dir, device_name, key_path in sorted(devices.get(customer, [])):
            total += 1
            dest_device_dir = os.path.join(web_fw_root, customer, device_name)
            dest_signed_path = os.path.join(dest_device_dir, "zephyr_signed.bin")

            os.makedirs(dest_device_dir, exist_ok=True)

            try:
                print(f"[sign] {customer}/{device_name}  key={key_path}")
                sign_image(ncs_version, key_path, image_path, dest_signed_path)
                print(f"[ok]   -> {dest_signed_path}")
                signed += 1
            except FileNotFoundError as e:
                print(f"[skip] {customer}/{device_name}: {e}")
                skipped += 1
            except subprocess.CalledProcessError as e:
                print(f"[fail] {customer}/{device_name}: imgtool/nrfutil failed (exit {e.returncode})")
                failures += 1
            except Exception as e:
                print(f"[fail] {customer}/{device_name}: {e}")
                failures += 1

    print("\n===== Summary =====")
    print(f"Targets: {total}")
    print(f" Signed: {signed}")
    print(f" Skipped (missing files): {skipped}")
    print(f" Failures: {failures}")
    if failures > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

