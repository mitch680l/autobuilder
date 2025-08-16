#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import platform
import re

sdk_version = "v3.0.2"
if platform.system() == "Linux":
    sdk_workspace = os.path.expanduser("~/ncs/v3.0.2")
else:
    sdk_workspace = r"C:\ncs\v3.0.2"

BOARD = "kestrel/nrf9151/ns"

script_dir = os.path.dirname(os.path.realpath(__file__))
source_dir = os.path.join(script_dir, "thingy")
build_dir = os.path.join(source_dir, "build", "thingy")
artifact = os.path.join(build_dir, "thingy", "zephyr", "tfm_merged.hex")
dest_hex = os.path.join(script_dir, "tfm_merged.hex")
version_txt = os.path.join(script_dir, "version.txt")

VERSION_PREFIX = "kestrel_app_v"
VERSION_RE = re.compile(rf"^{re.escape(VERSION_PREFIX)}(\d+)\.(\d+)\.(\d{{2}})$")

def read_version(path: str) -> str:
    default = f"{VERSION_PREFIX}0.0.00"
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            s = f.read().strip()
        if VERSION_RE.match(s):
            return s
        else:
            return default
    except:
        return default

def write_version(path: str, version: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(version + "\n")

def bump_version(current: str, level: str) -> str:
    m = VERSION_RE.match(current)
    if not m:
        major, minor, patch = 0, 0, 0
    else:
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3))
    if level == "major":
        major += 1
        minor = 0
        patch = 0
    elif level == "minor":
        minor += 1
        patch = 0
    else:
        patch += 1
        if patch > 99:
            patch = 0
            minor += 1
    return f"{VERSION_PREFIX}{major}.{minor}.{patch:02d}"

def build_thingy(source_dir):
    build_cmd = (
        f"west build --build-dir {build_dir} {source_dir} --pristine "
        f"--board {BOARD} -- -DBOARD_ROOT={source_dir}"
    )
    try:
        if platform.system() == "Linux":
            subprocess.run([
                "nrfutil", "sdk-manager", "toolchain", "launch",
                "--ncs-version", sdk_version,
                "--",
                "bash", "-lc",
                f'cd "{sdk_workspace}" && {build_cmd}'
            ], check=True)
        else:
            subprocess.run([
                "nrfutil", "sdk-manager", "toolchain", "launch",
                "--ncs-version", sdk_version,
                "--",
                "cmd.exe", "/d", "/s", "/c",
                f"cd /d {sdk_workspace} && {build_cmd}"
            ], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def replace_tfm_hex():
    if os.path.isfile(dest_hex):
        try:
            os.remove(dest_hex)
        except:
            pass
    if not os.path.isfile(artifact):
        sys.exit(1)
    shutil.copy2(artifact, dest_hex)

def main():
    level = "patch"
    if len(sys.argv) >= 2:
        arg = sys.argv[1].strip().lower()
        if arg in ("major", "minor", "patch"):
            level = arg
        else:
            sys.exit(2)
    current = read_version(version_txt)
    if not os.path.isdir(source_dir):
        sys.exit(1)
    if build_thingy(source_dir):
        replace_tfm_hex()
        new_version = bump_version(current, level)
        write_version(version_txt, new_version)
        print(new_version)
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
