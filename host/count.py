import csv
from pathlib import Path
from collections import defaultdict

def collect_xor_stats(folder: str, max_files: int = 1000):
    folder_path = Path(folder)
    xor_counts = defaultdict(int)

    for i in range(1, max_files + 1):
        csv_path = folder_path / f"packet_{i}.csv"
        if not csv_path.exists():
            print(f"[warn] {csv_path} not found, skipping")
            continue

        # Read the last row
        try:
            with csv_path.open() as f:
                reader = csv.DictReader(f)
                last_row = None
                for row in reader:
                    last_row = row

                if last_row is None:
                    print(f"[warn] {csv_path} is empty")
                    continue

                xor_deg = last_row.get("xor_degree")
                if xor_deg is None:
                    print(f"[warn] xor_degree missing in {csv_path}")
                    continue

                # Convert to int
                xor_deg = int(xor_deg)
                if xor_deg == 0:
                    print(i)
                xor_counts[xor_deg] += 1

        except Exception as e:
            print(f"[error] Failed to process {csv_path}: {e}")

    return xor_counts


if __name__ == "__main__":
    stats = collect_xor_stats("./output/", 2500)   # or replace with your directory
    print("XOR degree counts:")
    for deg, count in sorted(stats.items()):
        print(f"xor_degree {deg}: {count}")
