#!/usr/bin/env python3
import argparse
import struct
import zlib
import random
from dataclasses import dataclass
from typing import List, Set, Optional
from collections import defaultdict

MAX_DEGREE_DEFAULT = 32


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
    """
    Murmur-like hash for (pktid, hopid).
    """
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
# Packet equations (for decoding)
# -------------------------------------------------------------------

@dataclass
class PacketEquation:
    pktid: int
    final_pint: int
    xor_set: Set[int]      # hop indices included in XOR


# -------------------------------------------------------------------
# LT-style decoding: solve for per-hop switch IDs
# -------------------------------------------------------------------

def solve_switch_ids(
    eqs: List[PacketEquation],
    num_hops: int,
    id_bits: int = 16,
) -> Optional[List[int]]:
    """
    Solve XOR-equations:
        XOR_{i in xor_set_j} M[i] = final_pint_j
    for M[0..num_hops-1], each M[i] is 'id_bits'-wide.
    Uses Gaussian elimination over GF(2), bit-by-bit.
    Returns list of switch_ids (length num_hops) or None if unsolvable.
    """
    m = len(eqs)
    k = num_hops
    if m == 0:
        return None

    # Represent each equation's xor_set as a k-bit mask
    masks = []
    for eq in eqs:
        mask = 0
        for i in eq.xor_set:
            if 0 <= i < k:
                mask |= (1 << i)
        masks.append(mask)

    switch_ids = [0] * k

    for bit in range(id_bits):
        # Build system A x = y over GF(2)
        A = masks[:]  # row masks
        y = [(eq.final_pint >> bit) & 1 for eq in eqs]

        # Gaussian elimination (row-echelon form)
        pivot_row_for_col = [-1] * k
        row = 0
        for col in range(k):
            # Find pivot row with A[row][col] == 1
            pivot = None
            for r in range(row, m):
                if (A[r] >> col) & 1:
                    pivot = r
                    break
            if pivot is None:
                continue  # no pivot in this column
            # Swap into position
            A[row], A[pivot] = A[pivot], A[row]
            y[row], y[pivot] = y[pivot], y[row]
            pivot_row_for_col[col] = row

            # Eliminate this bit from all other rows
            for r in range(m):
                if r != row and ((A[r] >> col) & 1):
                    A[r] ^= A[row]
                    y[r] ^= y[row]

            row += 1
            if row == m:
                break

        # Check for inconsistency (0 = 1)
        for r in range(m):
            if A[r] == 0 and y[r] == 1:
                print(f"[warn] System inconsistent at bit {bit}, no solution.")
                return None

        # Back-substitution: for each pivot column, we can read x[col] = y[row]
        x_bits = [0] * k
        for col in range(k):
            r = pivot_row_for_col[col]
            if r != -1:
                x_bits[col] = y[r] & 1

        # Accumulate this bit into switch_ids
        for i in range(k):
            if x_bits[i]:
                switch_ids[i] |= (1 << bit)

    return switch_ids


# -------------------------------------------------------------------
# Simulation: RECIPE encoding, including PINT XOR actions
# -------------------------------------------------------------------

def simulate_xor_degree_distribution(
    num_packets: int,
    apa: APA,
    num_hops: int,
    max_degree: int,
    id_bits: int,
):
    xor_dist = defaultdict(int)

    # Assign a synthetic switch_id per hop (id_bits wide, fixed for entire run)
    rng = random.Random(0xC0FFEE)
    switch_id = [rng.getrandbits(id_bits) for _ in range(num_hops)]

    equations: List[PacketEquation] = []
    examples = []

    for pktid in range(num_packets):
        xor_degree = 0
        xor_set: Set[int] = set()
        pint = 0  

        for hopid in range(num_hops):
            idx = hopid * max_degree + xor_degree
            if idx >= len(apa.add_thresh):
                break

            add_thr = apa.add_thresh[idx]
            rep_thr = apa.replace_thresh[idx]

            hash_id = recipe_hash_v4(pktid=pktid, hopid=hopid) & 0xFFFFFFFF

            if hash_id < add_thr:
                # ADD: include this hop in the XOR set and XOR its switch_id into PINT
                xor_set.add(hopid)
                pint ^= switch_id[hopid]
                xor_degree = xor_degree + 1
            elif hash_id > rep_thr:
                # REPLACE: reset to just this hop
                xor_set = {hopid}
                pint = switch_id[hopid]
                xor_degree = 1
            else:
                # SKIP: do nothing
                pass

        final_degree = len(xor_set)
        xor_dist[final_degree] += 1

        equations.append(PacketEquation(pktid=pktid, final_pint=pint, xor_set=set(xor_set)))

        # Store a few examples (first 10 packets)
        if pktid < 10:
            examples.append((pktid, pint, sorted(xor_set)))

    # Print degree distribution
    print("\n=== Simulated XOR degree distribution ===")
    total = sum(xor_dist.values())
    for degree in sorted(xor_dist.keys()):
        count = xor_dist[degree]
        frac = count / total if total > 0 else 0.0
        print(f"degree={degree:2d}: {count:7d} packets ({frac:6.2%})")

    # Print a few example PINT values and their xor_sets
    print("\n=== Sample PINT outcomes (first 10 packets) ===")
    for pktid, pint, hops in examples:
        print(f"pktid={pktid:5d}  pint=0x{pint:04x}  xor_set={hops}")

    return xor_dist, equations, switch_id


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Simulate RECIPE encoding: given APA, #packets, and #hops, "
            "run the protocol, print final XOR degree distribution, "
            "and attempt to reconstruct the path via decoding."
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
    parser.add_argument(
        "--id-bits",
        type=int,
        default=16,
        help="Bit width of switch_id / PINT values (default: 16)",
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

    # 3) Run simulation (encode)
    xor_dist, equations, true_switch_ids = simulate_xor_degree_distribution(
        num_packets=args.num_packets,
        apa=apa,
        num_hops=num_hops,
        max_degree=apa.max_degree,
        id_bits=args.id_bits,
    )

    # 4) Decode (peel) to reconstruct per-hop switch IDs
    print("\n[info] Attempting to reconstruct switch_ids from equations...")
    switch_ids = solve_switch_ids(equations, num_hops=num_hops, id_bits=args.id_bits)
    if switch_ids is None:
        print("\n[info] Could not uniquely solve switch_ids (insufficient / inconsistent equations).")
        return

    print("\n=== Reconstructed path (per-hop switch_id) ===")
    for hop in range(num_hops):
        print(f"hop {hop:2d}: switch_id = 0x{switch_ids[hop]:04x}")

    print("\n[info] Path reconstruction complete.")

    # Optional: compare to ground truth
    print("\n=== Ground truth vs reconstructed (first few hops) ===")
    for hop in range(min(num_hops, 16)):
        print(
            f"hop {hop:2d}: true=0x{true_switch_ids[hop]:04x}  "
            f"recon=0x{switch_ids[hop]:04x}"
        )


if __name__ == "__main__":
    main()