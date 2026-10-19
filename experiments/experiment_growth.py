#!/usr/bin/env python3
"""Experiment 2: how FPR changes as the number of inserted items grows.

Uses the existing BloomFilter implementation. The filter's m and k are taken
from a previously built full-dataset filter; a fresh empty filter with those
same parameters is then filled incrementally.
"""
from __future__ import annotations

import argparse
import csv
import random
import string
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bloom_filter import BloomFilter  # noqa: E402


def load_unique_passwords(path: Path) -> tuple[set[str], float]:
    start = time.perf_counter()
    words: set[str] = set()
    with path.open("r", encoding="latin-1") as f:
        for line in f:
            word = line.rstrip("\r\n")
            if word:
                words.add(word)
    return words, time.perf_counter() - start


def make_absent_probes(passwords: set[str], count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    alphabet = string.ascii_letters + string.digits
    probes: list[str] = []
    seen: set[str] = set()
    while len(probes) < count:
        suffix = "".join(rng.choices(alphabet, k=24))
        candidate = "__bloom_growth_probe__" + suffix
        if candidate not in passwords and candidate not in seen:
            probes.append(candidate)
            seen.add(candidate)
    return probes


def measure_fpr(bf: BloomFilter, probes: list[str]) -> tuple[int, float, float]:
    start = time.perf_counter()
    false_positives = sum(1 for probe in probes if bf.contains(probe))
    elapsed = time.perf_counter() - start
    return false_positives, false_positives / len(probes), elapsed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure FPR while incrementally inserting more RockYou passwords."
    )
    parser.add_argument("dataset", type=Path, help="Path to RockYou text file")
    parser.add_argument("full_filter", type=Path,
                        help="Bloom filter built from the full dataset; supplies fixed m and k")
    parser.add_argument("--probes", type=int, default=100_000,
                        help="Number of absent test strings per checkpoint (default: 100000)")
    parser.add_argument("--seed", type=int, default=20261019,
                        help="Seed for reproducible absent probes")
    parser.add_argument("--checkpoints", default="1,5,10,25,50,75,100",
                        help="Percentages of dataset to insert, comma-separated")
    parser.add_argument("--output", type=Path, default=Path("results/fpr_growth.csv"),
                        help="CSV output path")
    args = parser.parse_args()

    if args.probes <= 0:
        parser.error("--probes must be positive")

    try:
        checkpoints = sorted({float(x.strip()) for x in args.checkpoints.split(",")})
    except ValueError:
        parser.error("--checkpoints must be comma-separated percentages")
    if not checkpoints or any(x <= 0 or x > 100 for x in checkpoints):
        parser.error("checkpoint percentages must be in (0, 100]")

    print(f"Loading unique passwords from {args.dataset} ...", flush=True)
    passwords, load_seconds = load_unique_passwords(args.dataset)
    total = len(passwords)
    if total == 0:
        raise SystemExit("Dataset contains no non-empty passwords")

    reference = BloomFilter.load(str(args.full_filter))
    if reference.count != total:
        print(
            f"WARNING: dataset has {total:,} unique passwords but the reference filter "
            f"records {reference.count:,} inserted items. Ensure they were built from the same dataset.",
            file=sys.stderr,
        )

    # Keep m and k fixed for every checkpoint so that only inserted item count changes.
    bf = BloomFilter(n=total, p=reference.p, m=reference.m, k=reference.k)
    probes = make_absent_probes(passwords, args.probes, args.seed)
    print(
        f"Unique passwords: {total:,}; m={bf.m:,} bits; k={bf.k}; "
        f"probes per checkpoint={len(probes):,}", flush=True
    )
    print("Note: set iteration order may differ between runs; the probe set is seeded.", flush=True)

    target_counts = []
    for percentage in checkpoints:
        target_counts.append((percentage, max(1, min(total, round(total * percentage / 100.0)))))
    # If percentages round to the same count on a tiny fixture, keep only unique counts.
    target_counts = sorted({count: (pct, count) for pct, count in target_counts}.values(), key=lambda x: x[1])

    rows: list[dict[str, object]] = []
    words_added = 0
    iterator = iter(passwords)
    insertion_start = time.perf_counter()

    for percentage, target_count in target_counts:
        while words_added < target_count:
            try:
                word = next(iterator)
            except StopIteration:
                break
            bf.add(word)
            words_added += 1

        insertion_seconds = time.perf_counter() - insertion_start
        fp_count, measured_fpr, query_seconds = measure_fpr(bf, probes)
        theoretical_fpr = bf.theoretical_fpr()
        row = {
            "checkpoint_percent": percentage,
            "dataset_unique_passwords": total,
            "inserted_count": bf.count,
            "filter_m_bits": bf.m,
            "filter_k_hashes": bf.k,
            "filter_size_bytes": bf.size_bytes(),
            "fill_ratio": bf.fill_ratio(),
            "probes": len(probes),
            "false_positives": fp_count,
            "measured_fpr": measured_fpr,
            "theoretical_fpr": theoretical_fpr,
            "absolute_difference": abs(measured_fpr - theoretical_fpr),
            "insertion_elapsed_seconds": insertion_seconds,
            "query_total_seconds": query_seconds,
            "query_average_microseconds": query_seconds / len(probes) * 1_000_000,
            "dataset_load_seconds": load_seconds,
            "seed": args.seed,
        }
        rows.append(row)
        print(
            f"{percentage:g}%: inserted={bf.count:,}; fill={bf.fill_ratio():.4f}; "
            f"measured FPR={measured_fpr:.6f}; theoretical FPR={theoretical_fpr:.6f}; "
            f"FP={fp_count:,}; query avg={row['query_average_microseconds']:.3f} us",
            flush=True,
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nCSV saved to: {args.output}")
    print("Experiment complete. Compare measured and theoretical FPR at each checkpoint.")


if __name__ == "__main__":
    main()
