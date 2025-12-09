#!/usr/bin/env python3
import argparse
import csv
import glob
import os
import struct
import zlib
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional

# -------------------------------------------------------------------
# Constants (match your experiment)
# -------------------------------------------------------------------

MAX_DEGREE_DEFAULT = 256
SRC_IP = "10.0.0.1"
DST_IP = "10.0.0.2"
IP_PROTO_RECIPE = 146  # from headers.p4


# -------------------------------------------------------------------
# Helper: parse IPv4 dotted string to uint32 (network byte order)
# -------------------------------------------------------------------

def ipv4_to_u32(ip: str) -> int:
    return struct.unpack("!I", struct.pack("!BBBB", *[int(x) for x in ip.split(".")]))[0]


SRC_IP_U32 = ipv4_to_u32(SRC_IP)
DST_IP_U32 = ipv4_to_u32(DST_IP)


# -------------------------------------------------------------------
# CRC32 hash (approximation of HashAlgorithm_t.CRC32)
# -------------------------------------------------------------------

def recipe_hash_v4(pktid: int, hopid: int) -> int:
    """
    Reproduce the P4 hash input:
        { ipv4.src_addr, ipv4.dst_addr, ipv4.protocol,
          ipv4.identification, meta.hop_count }
    """
    proto = IP_PROTO_RECIPE
    identification = pktid  # same value used in host_loop for IP ID
    data = struct.pack("!IIBHB", SRC_IP_U32, DST_IP_U32, proto,
                       identification, hopid)
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return crc


# -------------------------------------------------------------------
# Load APA (probabilities) from robust file
# Format per line (for each hop):
#   a0, r0, a1, r1, ...
# where a_d = p_add(hop, degree=d), r_d = p_add + p_replace.
# -------------------------------------------------------------------

@dataclass
class APA:
    max_hops: int
    max_degree: int
    probs_a: List[int]   # flattened: idx = hop * max_degree + degree
    probs_cum: List[int]


def load_apa(robust_path: str,
             max_degree: int = MAX_DEGREE_DEFAULT) -> APA:
    probs_a: List[int] = []
    probs_cum: List[int] = []
    lines: List[str] = []

    with open(robust_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            lines.append(line)

    max_hops = len(lines)
    probs_a = [0] * (max_hops * max_degree)
    probs_cum = [0] * (max_hops * max_degree)

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
            p_add = float(parts[2 * d])
            p_cum = float(parts[2 * d + 1])
            idx = hop_idx * max_degree + d
            # Same fixed-point encoding as controller
            probs_a[idx] = int(p_add * (2**32)) & 0xFFFFFFFF
            probs_cum[idx] = int(p_cum * (2**32)) & 0xFFFFFFFF

    return APA(max_hops=max_hops, max_degree=max_degree,
               probs_a=probs_a, probs_cum=probs_cum)


# -------------------------------------------------------------------
# P4-style signed comparison emulation
# -------------------------------------------------------------------

def _sign_bit(x: int) -> int:
    return (x >> 31) & 1


def _p4_add_decision(hash_id: int, a_prob: int) -> bool:
    """
    Implements the 'add' branch condition from the P4 code.
    """
    h = hash_id & 0xFFFFFFFF
    a = a_prob & 0xFFFFFFFF

    res = (h - a) & 0xFFFFFFFF
    h_sign = _sign_bit(h)
    a_sign = _sign_bit(a)
    res_sign = _sign_bit(res)

    msb = 1 if ((h_sign == 0 and a_sign == 0) or (h_sign == 1 and a_sign == 1)) else 0

    cond = ((h_sign == 0 and a_sign == 1) or (msb == 1 and res_sign == 1))
    return cond


def _p4_replace_decision(hash_id: int, cum_prob: int) -> bool:
    """
    Implements the 'replace' branch condition from the P4 code.
    """
    h = hash_id & 0xFFFFFFFF
    c = cum_prob & 0xFFFFFFFF

    res = (c - h) & 0xFFFFFFFF
    h_sign = _sign_bit(h)
    c_sign = _sign_bit(c)

    msb_r = 1 if ((c_sign == 0 and h_sign == 0) or (c_sign == 1 and h_sign == 1)) else 0

    cond = ((h_sign == 0 and c_sign == 0) or (msb_r == 1 and c_sign == 1))
    return cond


# -------------------------------------------------------------------
# Packet log parsing (output/packet_X.csv)
# -------------------------------------------------------------------

@dataclass
class PacketLog:
    pktid: int
    rows: List[Tuple[int, int, int, int]]  # (hopid, ttl, pint, xor_degree)

    @property
    def final_pint(self) -> int:
        return self.rows[-1][2]

    @property
    def final_xor_degree(self) -> int:
        return self.rows[-1][3]

    @property
    def max_hopid(self) -> int:
        return max(r[0] for r in self.rows)


def load_packet_logs(output_dir: str) -> Dict[int, PacketLog]:
    """
    Reads files named 'packet_<pktid>.csv' in output_dir.
    Header: hopid,ttl,pint,xor_degree
    """
    pattern = os.path.join(output_dir, "packet_*.csv")
    logs: Dict[int, PacketLog] = {}

    for path in glob.glob(pattern):
        basename = os.path.basename(path)
        name, _ = os.path.splitext(basename)
        _, pktid_str = name.split("_", 1)
        pktid = int(pktid_str)

        rows: List[Tuple[int, int, int, int]] = []
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                hopid = int(row["hopid"])
                ttl = int(row["ttl"])
                pint = int(row["pint"])
                xor_deg = int(row["xor_degree"])
                rows.append((hopid, ttl, pint, xor_deg))

        if rows:
            logs[pktid] = PacketLog(pktid=pktid, rows=rows)

    return logs


# -------------------------------------------------------------------
# Reconstruct XOR-set S_pkt for each packet
# -------------------------------------------------------------------

@dataclass
class PacketEquation:
    pktid: int
    final_pint: int
    xor_set: Set[int]      # hop indices included in XOR
    simulated_degree: int  # final xor_degree from simulation


def reconstruct_xor_sets(
    logs: Dict[int, PacketLog],
    apa: APA,
    num_hops: int,
    max_degree: int,
) -> List[PacketEquation]:
    equations: List[PacketEquation] = []

    for pktid, plog in sorted(logs.items()):
        xor_degree = 0
        xor_set: Set[int] = set()

        for hopid in range(num_hops):
            idx = hopid * max_degree + xor_degree
            if idx >= len(apa.probs_a):
                break

            a_prob = apa.probs_a[idx]
            cum_prob = apa.probs_cum[idx]

            hash_id = recipe_hash_v4(pktid=pktid, hopid=hopid)

            if _p4_add_decision(hash_id, a_prob):
                # ADD
                if hopid in xor_set:
                    xor_set.remove(hopid)
                else:
                    xor_set.add(hopid)
                xor_degree = (xor_degree + 1) % max_degree
            else:
                if _p4_replace_decision(hash_id, cum_prob):
                    # REPLACE
                    xor_set = {hopid}
                    xor_degree = 1
                else:
                    # SKIP
                    pass

        equations.append(
            PacketEquation(
                pktid=pktid,
                final_pint=plog.final_pint,
                xor_set=xor_set,
                simulated_degree=xor_degree,
            )
        )

    return equations


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
        # For non-pivot columns, we leave bit=0 (one valid solution).
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
# Main
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Reconstruct XOR-sets per packet for RECIPE/PINT from "
            "output/packet_*.csv and robust probs file, then decode path."
        )
    )
    parser.add_argument(
        "--robust",
        required=True,
        help="Path to robust32_*.txt (probability matrix)",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory containing packet_*.csv logs (default: output)",
    )
    parser.add_argument(
        "--num-hops",
        type=int,
        default=None,
        help="Number of PINT hops (default: min(APA.max_hops, max observed hopid+1))",
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
        help="Bit width of switch_id (default: 16)",
    )
    args = parser.parse_args()

    # 1) Load APA
    apa = load_apa(args.robust, max_degree=args.max_degree)
    print(f"[info] Loaded APA from {args.robust}: "
          f"{apa.max_hops} hops, max_degree={apa.max_degree}")

    # 2) Load packet logs
    logs = load_packet_logs(args.output_dir)
    if not logs:
        print(f"[error] No packet_*.csv files found in {args.output_dir}")
        return

    max_observed_hopid = max(plog.max_hopid for plog in logs.values())
    default_num_hops = min(apa.max_hops, max_observed_hopid + 1)
    num_hops = args.num_hops if args.num_hops is not None else default_num_hops
    print(f"[info] Using num_hops={num_hops} "
          f"(APA has {apa.max_hops}, max observed hopid={max_observed_hopid})")

    # 3) Reconstruct XOR-sets
    equations = reconstruct_xor_sets(
        logs=logs,
        apa=apa,
        num_hops=num_hops,
        max_degree=apa.max_degree,
    )

    print("\n=== Reconstructed XOR-sets per packet ===")
    for eq in equations:
        hops_sorted = sorted(eq.xor_set)
        print(
            f"pktid={eq.pktid}  final_pint=0x{eq.final_pint:04x}  "
            f"xor_degree_sim={eq.simulated_degree}  "
            f"xor_set={hops_sorted}"
        )

    # 4) Solve for per-hop switch IDs (the "path")
    switch_ids = solve_switch_ids(equations, num_hops=num_hops, id_bits=args.id_bits)
    if switch_ids is None:
        print("\n[info] Could not uniquely solve switch_ids (insufficient / inconsistent equations).")
        return

    print("\n=== Reconstructed path (per-hop switch_id) ===")
    for hop in range(num_hops):
        print(f"hop {hop:2d}: switch_id = 0x{switch_ids[hop]:04x}")

    print("\n[info] Path reconstruction complete.")


if __name__ == "__main__":
    main()