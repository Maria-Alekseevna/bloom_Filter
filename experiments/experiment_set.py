#!/usr/bin/env python3
"""Experiment 4: compare Bloom filter and Python set lookup and memory."""
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
        candidate = "__bloom_set_probe__" + "".join(rng.choices(alphabet, k=24))
        if candidate not in words and candidate not in seen:
            probes.append(candidate)
            seen.add(candidate)
    return probes


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare Bloom filter and Python set.")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("full_filter", type=Path)
    parser.add_argument("--probes", type=int, default=100_000,
                        help="Number of absent probes (default: 100000)")
    parser.add_argument("--positive-probes", type=int, default=10_000,
                        help="Number of present probes (default: 10000)")
    parser.add_argument("--seed", type=int, default=20261019)
    parser.add_argument("--output", type=Path, default=Path("results/set_comparison.csv"))
    args = parser.parse_args()
    if args.probes <= 0 or args.positive_probes <= 0:
        parser.error("probe counts must be positive")

    print(f"Loading unique passwords from {args.dataset} ...", flush=True)
    words, load_seconds = load_unique_passwords(args.dataset)
    if not words:
        raise SystemExit("Dataset contains no non-empty passwords")
    bf = BloomFilter.load(str(args.full_filter))
    if bf.count != len(words):
        raise SystemExit(
            f"Dataset has {len(words):,} unique passwords, but filter records {bf.count:,}. "
            "Use a filter built from this exact dataset."
        )
    rng = random.Random(args.seed)
    positive_count = min(args.positive_probes, len(words))
    positives = rng.sample(tuple(words), positive_count)
    absent = make_absent_probes(words, args.probes, args.seed)

    # sys.getsizeof(set) includes its hash table; each unique string object is counted once.
    set_memory_bytes = sys.getsizeof(words) + sum(sys.getsizeof(word) for word in words)
    structures = [("bloom_filter", bf.size_bytes(), bf.contains), ("python_set", set_memory_bytes, words.__contains__)]
    rows = []
    for structure_name, memory_bytes, contains in structures:
        t0 = time.perf_counter()
        absent_hits = sum(1 for probe in absent if contains(probe))
        absent_seconds = time.perf_counter() - t0
        t0 = time.perf_counter()
        positive_misses = sum(1 for word in positives if not contains(word))
        positive_seconds = time.perf_counter() - t0
        rows.append({
            "structure": structure_name,
            "dataset_unique_passwords": len(words),
            "memory_bytes_estimated": memory_bytes,
            "memory_mib_estimated": memory_bytes / (1024 ** 2),
            "absent_probes": len(absent),
            "absent_hits_or_false_positives": absent_hits,
            "absent_query_total_seconds": absent_seconds,
            "absent_query_average_microseconds": absent_seconds / len(absent) * 1_000_000,
            "present_probes": len(positives),
            "present_false_negatives": positive_misses,
            "present_query_total_seconds": positive_seconds,
            "present_query_average_microseconds": positive_seconds / len(positives) * 1_000_000,
            "dataset_load_seconds": load_seconds,
            "seed": args.seed,
        })
        print(
            f"{structure_name}: memory~{memory_bytes / (1024 ** 2):.2f} MiB; "
            f"absent avg={rows[-1]['absent_query_average_microseconds']:.3f} us; "
            f"present avg={rows[-1]['present_query_average_microseconds']:.3f} us; "
            f"absent hits={absent_hits:,}; present misses={positive_misses:,}",
            flush=True,
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nCSV saved to: {args.output}")


if __name__ == "__main__":
    main()
