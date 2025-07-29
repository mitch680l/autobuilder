from intelhex import IntelHex
import sys
import os

FLASH_BASE_ADDRESS = 0x30000


FLASH_COMPARE_LIMIT = 0xFB400

def convert_hex_to_bin(hex_file, bin_file):
    ih = IntelHex(hex_file)
    ih.tofile(bin_file, format='bin')
    print(f"[✓] Converted {hex_file} → {bin_file}")

def compare_bins(bin1_path, bin2_path, max_diff=20):
    differences = []
    with open(bin1_path, 'rb') as f1, open(bin2_path, 'rb') as f2:
        offset = 0
        while True:
            b1 = f1.read(1)
            b2 = f2.read(1)

            if not b1 and not b2:
                break 

            flash_addr = FLASH_BASE_ADDRESS + offset
            if flash_addr >= FLASH_COMPARE_LIMIT:
                break  

            if b1 != b2:
                differences.append((offset, flash_addr, b1.hex(), b2.hex()))
                if len(differences) >= max_diff:
                    break

            offset += 1

    return differences

def main():
    if len(sys.argv) != 3:
        print("Usage:\n  python compare_hex.py <original.hex> <merged.hex>")
        sys.exit(1)

    hex1 = sys.argv[1]
    hex2 = sys.argv[2]

    bin1 = os.path.splitext(hex1)[0] + ".bin"
    bin2 = os.path.splitext(hex2)[0] + ".bin"

    print(f"\n[🔁] Converting HEX files to BIN:")
    convert_hex_to_bin(hex1, bin1)
    convert_hex_to_bin(hex2, bin2)

    print(f"\n[🔍] Comparing contents up to 0x{FLASH_COMPARE_LIMIT:X}:")

    differences = compare_bins(bin1, bin2)

    if not differences:
        print(f"\n✅ No differences found before 0x{FLASH_COMPARE_LIMIT:X}. Merged image is safe.\n")
    else:
        print(f"\n❌ {len(differences)} difference(s) found before 0x{FLASH_COMPARE_LIMIT:X}:\n")
        print(f"{'Offset':>10}  {'Flash Addr':>10}  {'File1':>6}  {'File2':>6}")
        print("-" * 40)
        for offset, addr, b1, b2 in differences:
            print(f"0x{offset:06X}  0x{addr:08X}     {b1}     {b2}")
        print("\n These differences may cause signature verification to fail.\n")

if __name__ == "__main__":
    main()
