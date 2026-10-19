#!/usr/bin/env python3
"""Experiment 5: compare indexed SQLite lookups with Bloom filter.

The SQLite database is persisted at results/rockyou_index.sqlite by default.
It is a generated artifact and should not be committed to Git.
"""
from __future__ import annotations
import argparse
import csv
import random
import string
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from bloom_filter import BloomFilter  # noqa: E402


def make_absent_probes(conn: sqlite3.Connection, count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    alphabet = string.ascii_letters + string.digits
    probes: list[str] = []
    while len(probes) < count:
        candidate = "__sqlite_probe__" + "".join(rng.choices(alphabet, k=24))
        found = conn.execute("SELECT 1 FROM passwords WHERE password = ?", (candidate,)).fetchone()
        if found is None:
            probes.append(candidate)
    return probes


def build_database(dataset: Path, db_path: Path, batch_size: int) -> tuple[int, float]:
    if db_path.exists():
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode = OFF")
        conn.execute("PRAGMA synchronous = OFF")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("CREATE TABLE passwords (password TEXT PRIMARY KEY) WITHOUT ROWID")
        batch: list[tuple[str]] = []
        with dataset.open("r", encoding="latin-1") as f:
            for line in f:
                word = line.rstrip("\r\n")
                if word:
                    batch.append((word,))
                if len(batch) >= batch_size:
                    conn.executemany("INSERT OR IGNORE INTO passwords(password) VALUES (?)", batch)
                    batch.clear()
            if batch:
                conn.executemany("INSERT OR IGNORE INTO passwords(password) VALUES (?)", batch)
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM passwords").fetchone()[0]
    finally:
        conn.close()
    return count, time.perf_counter() - start


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare Bloom filter with indexed SQLite lookups.")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("full_filter", type=Path)
    parser.add_argument("--probes", type=int, default=100_000)
    parser.add_argument("--positive-probes", type=int, default=10_000)
    parser.add_argument("--batch-size", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20261019)
    parser.add_argument("--database", type=Path, default=Path("results/rockyou_index.sqlite"))
    parser.add_argument("--output", type=Path, default=Path("results/sqlite_comparison.csv"))
    args = parser.parse_args()
    if min(args.probes, args.positive_probes, args.batch_size) <= 0:
        parser.error("probes, positive-probes and batch-size must be positive")

    bf = BloomFilter.load(str(args.full_filter))
    print(f"Building SQLite index from {args.dataset} ...", flush=True)
    db_count, build_seconds = build_database(args.dataset, args.database, args.batch_size)
    if db_count != bf.count:
        raise SystemExit(
            f"SQLite has {db_count:,} unique passwords but Bloom filter records {bf.count:,}; "
            "use a filter built from this dataset."
        )

    conn = sqlite3.connect(args.database)
    try:
        rng = random.Random(args.seed)
        positives = [row[0] for row in conn.execute(
            "SELECT password FROM passwords ORDER BY RANDOM() LIMIT ?", (args.positive_probes,)
        )]
        absent = make_absent_probes(conn, args.probes, args.seed)
        db_size = args.database.stat().st_size

        rows = []
        for name, contains, memory_bytes in (
            ("bloom_filter", bf.contains, bf.size_bytes()),
            ("sqlite_indexed", lambda value: conn.execute(
                "SELECT 1 FROM passwords WHERE password = ?", (value,)
            ).fetchone() is not None, db_size),
        ):
            t0 = time.perf_counter()
            absent_hits = sum(1 for value in absent if contains(value))
            absent_seconds = time.perf_counter() - t0
            t0 = time.perf_counter()
            positive_misses = sum(1 for value in positives if not contains(value))
            positive_seconds = time.perf_counter() - t0
            row = {
                "structure": name,
                "dataset_unique_passwords": db_count,
                "storage_bytes_estimated": memory_bytes,
                "storage_mib_estimated": memory_bytes / (1024 ** 2),
                "storage_type": "RAM bit array" if name == "bloom_filter" else "SQLite database file on disk",
                "absent_probes": len(absent),
                "absent_hits_or_false_positives": absent_hits,
                "absent_query_total_seconds": absent_seconds,
                "absent_query_average_microseconds": absent_seconds / len(absent) * 1_000_000,
                "present_probes": len(positives),
                "present_false_negatives": positive_misses,
                "present_query_total_seconds": positive_seconds,
                "present_query_average_microseconds": positive_seconds / len(positives) * 1_000_000,
                "database_build_seconds": build_seconds,
                "database_path": str(args.database),
                "seed": args.seed,
            }
            rows.append(row)
            print(
                f"{name}: storage~{memory_bytes / (1024 ** 2):.2f} MiB; "
                f"absent avg={row['absent_query_average_microseconds']:.3f} us; "
                f"present avg={row['present_query_average_microseconds']:.3f} us; "
                f"absent hits={absent_hits:,}; present misses={positive_misses:,}", flush=True
            )
    finally:
        conn.close()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"SQLite build time: {build_seconds:.2f} s")
    print(f"SQLite database: {args.database} ({db_size:,} bytes)")
    print(f"CSV saved to: {args.output}")


if __name__ == "__main__":
    main()
