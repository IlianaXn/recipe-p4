import csv

def mix32(x: int) -> int:
    x &= 0xFFFFFFFF
    x ^= x >> 16
    x = (x * 0x7FEB352D) & 0xFFFFFFFF
    x ^= x >> 15
    x = (x * 0x846CA68B) & 0xFFFFFFFF
    x ^= x >> 16
    return x

def recipe_hash_v4(pktid: int, hopid: int) -> int:
    pid = mix32(pktid & 0xFFFFFFFF)
    combined = (
        pid
        ^ ((hopid * 0x9E3779B9) & 0xFFFFFFFF)
        ^ 0xA5A5A5A5
    ) & 0xFFFFFFFF
    return mix32(combined)

def main():
    output_file = "recipe_hash_2000x256.csv"

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)

        # rows = pktid (1..2000)
        # cols = hopid (0..255)
        for pktid in range(1, 2000 + 1):
            row = [recipe_hash_v4(pktid, hopid)&0xFFFFFFFF for hopid in range(0, 255 + 1) ]
            writer.writerow(row)

    print(f"Wrote {output_file} (2000 rows × 256 columns)")

if __name__ == "__main__":
    main()