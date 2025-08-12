import os
import sys
import shutil
import subprocess

# --- Match your working pattern ---
sdk_workspace = r"C:\ncs\v3.0.2"
sdk_version   = "v3.0.2"
BOARD         = "kestrel/nrf9151/ns"   # adjust if needed

script_dir = os.path.dirname(os.path.realpath(__file__))

# New project directory under this repo:
source_dir = os.path.join(script_dir, "thingy")                 # e.g. C:\...\autobuilder\thingy
build_dir  = os.path.join(source_dir, "build", "thingy")        # e.g. C:\...\autobuilder\thingy\build\thingy
artifact   = os.path.join(build_dir, "thingy", "zephyr", "tfm_merged.hex")
dest_hex   = os.path.join(script_dir, "tfm_merged.hex")

def build_thingy(source_dir):
    # EXACT style as your working example: no extra quoting trickery
    build_cmd = (
        f"west build --build-dir {build_dir} {source_dir} --pristine "
        f"--board {BOARD} -- -DBOARD_ROOT={source_dir}"
    )

    try:
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

def replace_tfm_hex():
    # remove old tfm_merged.hex (if present)
    if os.path.isfile(dest_hex):
        try:
            os.remove(dest_hex)
            print(f"🗑 Removed old {dest_hex}")
        except Exception as ex:
            print(f"Warning: couldn't remove old {dest_hex}: {ex}")

    # copy new artifact from build
    if not os.path.isfile(artifact):
        print(f"New tfm_merged.hex not found at {artifact}")
        sys.exit(1)

    shutil.copy2(artifact, dest_hex)
    print(f"Copied new tfm_merged.hex to {dest_hex}")

if __name__ == "__main__":
    if not os.path.isdir(source_dir):
        print(f"Project not found at: {source_dir}")
        sys.exit(1)

    if build_thingy(source_dir):
        replace_tfm_hex()

