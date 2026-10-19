#!/usr/bin/env python3
"""Experiment 3: measure the effect of k with fixed m and a full dataset."""
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


def make_absent_probes(words: set[str], count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    alphabet = string.ascii_letters + string.digits
    probes: list[str] = []
    seen: set[str] = set()
    while len(probes) < count:
        candidate = "__bloom_k_probe__" + "".join(rng.choices(alphabet, k=24))
        if candidate not in words and candidate not in seen:
            probes.append(candidate)
            seen.add(candidate)
    return probes


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure FPR and query speed for different k values.")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("full_filter", type=Path, help="Reference full-data filter; supplies fixed m")
    parser.add_argument("--probes", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=20261019)
    parser.add_argument("--k-values", default="3,5,7,9,11",
                        help="Comma-separated k values (default: 3,5,7,9,11)")
    parser.add_argument("--output", type=Path, default=Path("results/fpr_by_k.csv"))
    args = parser.parse_args()
    if args.probes <= 0:
        parser.error("--probes must be positive")
    try:
        k_values = sorted(set(int(x.strip()) for x in args.k_values.split(",")))
    except ValueError:
        parser.error("--k-values must be comma-separated positive integers")
    if not k_values or any(k <= 0 for k in k_values):
        parser.error("all k values must be positive integers")

    print(f"Loading unique passwords from {args.dataset} ...", flush=True)
    words, load_seconds = load_unique_passwords(args.dataset)
    if not words:
        raise SystemExit("Dataset contains no non-empty passwords")
    reference = BloomFilter.load(str(args.full_filter))
    if reference.count != len(words):
        raise SystemExit(
            f"Dataset has {len(words):,} unique passwords, but reference filter records "
            f"{reference.count:,}. Use a filter built from this exact dataset."
        )
    probes = make_absent_probes(words, args.probes, args.seed)
    print(f"Unique passwords={len(words):,}; fixed m={reference.m:,} bits; probes={len(probes):,}", flush=True)

    rows = []
    for k in k_values:
        bf = BloomFilter(n=len(words), p=reference.p, m=reference.m, k=k)
        insert_start = time.perf_counter()
        for word in words:
            bf.add(word)
        insertion_seconds = time.perf_counter() - insert_start
        query_start = time.perf_counter()
        false_positives = sum(1 for probe in probes if bf.contains(probe))
        query_seconds = time.perf_counter() - query_start
        measured = false_positives / len(probes)
        theoretical = bf.theoretical_fpr()
        row = {
            "dataset_unique_passwords": len(words), "filter_m_bits": bf.m,
            "filter_k_hashes": k, "filter_size_bytes": bf.size_bytes(),
            "fill_ratio": bf.fill_ratio(), "probes": len(probes),
            "false_positives": false_positives, "measured_fpr": measured,
            "theoretical_fpr": theoretical,
            "absolute_difference": abs(measured - theoretical),
            "insertion_seconds": insertion_seconds,
            "query_total_seconds": query_seconds,
            "query_average_microseconds": query_seconds / len(probes) * 1_000_000,
            "dataset_load_seconds": load_seconds, "seed": args.seed,
        }
        rows.append(row)
        print(f"k={k}: fill={bf.fill_ratio():.4f}; measured FPR={measured:.6f}; "
              f"theoretical FPR={theoretical:.6f}; FP={false_positives:,}; "
              f"query avg={row['query_average_microseconds']:.3f} us; "
              f"insert={insertion_seconds:.2f} s", flush=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nCSV saved to: {args.output}")

if __name__ == "__main__":
    main()
