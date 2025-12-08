#!/usr/bin/env python3
import argparse
import struct
import zlib
from dataclasses import dataclass
from typing import List
from collections import defaultdict

# -------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------

MAX_DEGREE_DEFAULT = 32


# -------------------------------------------------------------------
# Double-CRC hash for (pktid, hopid)
# -------------------------------------------------------------------
def mix32(x: int) -> int:
    """
    Simple 32-bit mixing function (inspired by Murmur/Smear).
    Takes a 32-bit integer and returns a well-mixed 32-bit value.
    """
    x &= 0xFFFFFFFF
    x ^= x >> 16
    x = (x * 0x7FEB352D) & 0xFFFFFFFF
    x ^= x >> 15
    x = (x * 0x846CA68B) & 0xFFFFFFFF
    x ^= x >> 16
    return x
def recipe_hash_v4(pktid: int, hopid: int) -> int:
    # Extra hash of pktid
    pid = mix32(pktid & 0xFFFFFFFF)

    # Combine with hopid and some constants
    combined = (pid ^ ((hopid * 0x9E3779B9) & 0xFFFFFFFF) ^ 0xA5A5A5A5) & 0xFFFFFFFF

    # Final mix
    return mix32(combined)


# -------------------------------------------------------------------
# APA (Action Probability Array) loading
# Format per line (for each hop):
#   t_add_deg0, t_rep_deg0, t_add_deg1, t_rep_deg1, ...
# Values are probabilities in [0,1], we scale them to [0, 2^32).
# -------------------------------------------------------------------

@dataclass
class APA:
    max_hops: int
    max_degree: int
    add_thresh: List[int]      # idx = hop * max_degree + degree
    replace_thresh: List[int]  # idx = hop * max_degree + degree


def load_apa(robust_path: str,
             max_degree: int = MAX_DEGREE_DEFAULT) -> APA:
    lines: List[str] = []
    with open(robust_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            lines.append(line)

    max_hops = len(lines)
    add_thresh = [0] * (max_hops * max_degree)
    replace_thresh = [0] * (max_hops * max_degree)

    for hop_idx, line in enumerate(lines):
        parts = [p.strip() for p in line.split(",") if p.strip() != ""]
        if len(parts) % 2 != 0:
            raise ValueError(
                f"Line {hop_idx} in {robust_path} has odd number of columns: {len(parts)}"
            )
        num_degrees = len(parts) // 2
        if num_degrees > max_degree:
            raise ValueError(
                f"Line {hop_idx} has {num_degrees} degrees, but max_degree={max_degree}"
            )

        for d in range(num_degrees):
            raw_add = float(parts[2 * d])
            raw_rep = float(parts[2 * d + 1])

            idx = hop_idx * max_degree + d

            # Scale probabilities to 32-bit threshold space
            add_thresh[idx] = int(raw_add * (2**32)) & 0xFFFFFFFF
            replace_thresh[idx] = int(raw_rep * (2**32)) & 0xFFFFFFFF

    return APA(
        max_hops=max_hops,
        max_degree=max_degree,
        add_thresh=add_thresh,
        replace_thresh=replace_thresh,
    )


# -------------------------------------------------------------------
# Simulation: RECIPE encoding, XOR degree distribution
# -------------------------------------------------------------------

def simulate_xor_degree_distribution(
    num_packets: int,
    apa: APA,
    num_hops: int,
    max_degree: int,
) -> None:
    xor_dist = defaultdict(int)

    for pktid in range(num_packets):
        xor_degree = 0
        xor_set = set()

        for hopid in range(num_hops):
            idx = hopid * max_degree + xor_degree
            if idx >= len(apa.add_thresh):
                break

            add_thr = apa.add_thresh[idx]
            rep_thr = apa.replace_thresh[idx]

            hash_id = recipe_hash_v4(pktid=pktid, hopid=hopid) & 0xFFFFFFFF

            
            if hash_id < add_thr:
                # ADD
                xor_set.add(hopid)
                xor_degree = xor_degree + 1
            elif hash_id > rep_thr:
                # REPLACE
                xor_set = {hopid}
                xor_degree = 1
            else:
                # SKIP
                pass

        final_degree = len(xor_set)
        xor_dist[final_degree] += 1

    # Print distribution
    print("\n=== Simulated XOR degree distribution ===")
    total = sum(xor_dist.values())
    for degree in sorted(xor_dist.keys()):
        count = xor_dist[degree]
        frac = count / total if total > 0 else 0.0
        print(f"degree={degree:2d}: {count:7d} packets ({frac:6.2%})")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Simulate RECIPE encoding: given APA, #packets, and #hops, "
            "run the protocol and print final XOR degree distribution."
        )
    )
    parser.add_argument(
        "--robust",
        required=True,
        help="Path to robust32_*.txt (probability matrix / APA)",
    )
    parser.add_argument(
        "--num-hops",
        type=int,
        required=True,
        help="Number of PINT hops (path length k)",
    )
    parser.add_argument(
        "--num-packets",
        "-n",
        type=int,
        default=10000,
        help="Number of packets to simulate (default: 10000)",
    )
    parser.add_argument(
        "--max-degree",
        type=int,
        default=MAX_DEGREE_DEFAULT,
        help=f"Max XOR degree (default: {MAX_DEGREE_DEFAULT})",
    )
    args = parser.parse_args()

    # 1) Load APA
    apa = load_apa(args.robust, max_degree=args.max_degree)
    print(f"[info] Loaded APA from {args.robust}: "
          f"{apa.max_hops} hops, max_degree={apa.max_degree}")

    # 2) Decide num_hops
    if args.num_hops > apa.max_hops:
        print(f"[warn] Requested num_hops={args.num_hops} > APA.max_hops={apa.max_hops}, "
              f"clamping to {apa.max_hops}")
        num_hops = apa.max_hops
    else:
        num_hops = args.num_hops

    print(f"[info] Simulating {args.num_packets} packets over num_hops={num_hops}")

    # 3) Run simulation
    simulate_xor_degree_distribution(
        num_packets=args.num_packets,
        apa=apa,
        num_hops=num_hops,
        max_degree=apa.max_degree,
    )

    

if __name__ == "__main__":
    main()