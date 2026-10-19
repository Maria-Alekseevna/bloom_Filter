"""Эксперимент 1: измерение FPR и сравнение с теорией.

Запуск из корня репозитория:
    python experiments/experiment_fpr.py rockyou.txt rockyou_1pct.bloom

Скрипт загружает уникальные пароли RockYou в set, чтобы гарантировать, что
тестовые запросы отсутствуют в исходном наборе. Поэтому для полного RockYou
нужно достаточно оперативной памяти (как и для build_rockyou.py).
"""

from __future__ import annotations

import argparse
import csv
import random
import string
import sys
import time
from pathlib import Path

# Позволяет запускать скрипт командой python experiments/experiment_fpr.py из корня.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bloom_filter import BloomFilter

ALPHABET = string.ascii_letters + string.digits


def load_passwords(path: Path) -> set[str]:
    """Читает RockYou в той же кодировке и с той же нормализацией, что и builder."""
    with path.open("r", encoding="latin-1") as file:
        passwords = {line.rstrip("\r\n") for line in file}
    passwords.discard("")
    return passwords


def make_absent_queries(passwords: set[str], count: int, seed: int) -> list[str]:
    """Создаёт воспроизводимый набор строк, гарантированно отсутствующих в RockYou."""
    rng = random.Random(seed)
    queries: set[str] = set()
    while len(queries) < count:
        candidate = "__bloom_fpr_probe__" + "".join(rng.choices(ALPHABET, k=24))
        if candidate not in passwords:
            queries.add(candidate)
    return list(queries)


def run(args: argparse.Namespace) -> dict[str, int | float | str]:
    started = time.perf_counter()
    passwords = load_passwords(args.rockyou)
    load_seconds = time.perf_counter() - started
    if not passwords:
        raise ValueError("В файле RockYou не найдено ни одного непустого пароля")

    bf = BloomFilter.load(str(args.filter))
    probes = make_absent_queries(passwords, args.probes, args.seed)

    # Проверяем отсутствие ложноотрицательных результатов на случайной выборке.
    rng = random.Random(args.seed + 1)
    sample_size = min(args.verify_sample, len(passwords))
    selected_indices = set(rng.sample(range(len(passwords)), sample_size))
    sample = [password for index, password in enumerate(passwords) if index in selected_indices]
    false_negatives = sum(not bf.contains(password) for password in sample)

    # Измеряем FPR только на запросах, которых точно нет в исходном наборе.
    started = time.perf_counter()
    false_positives = sum(bf.contains(query) for query in probes)
    query_seconds = time.perf_counter() - started
    measured_fpr = false_positives / len(probes)
    if bf.count != len(passwords):
        print(
            f"ПРЕДУПРЕЖДЕНИЕ: в фильтр добавлено {bf.count:,} элементов, "
            f"а в RockYou найдено {len(passwords):,} уникальных паролей. "
            "Возможно, фильтр построен по другой версии набора данных."
        )
    theoretical_fpr = bf.theoretical_fpr(n=bf.count)

    result: dict[str, int | float | str] = {
        "dataset_unique_passwords": len(passwords),
        "filter_inserted_count": bf.count,
        "filter_m_bits": bf.m,
        "filter_k_hashes": bf.k,
        "filter_size_bytes": bf.size_bytes(),
        "fill_ratio": bf.fill_ratio(),
        "probes": len(probes),
        "false_positives": false_positives,
        "measured_fpr": measured_fpr,
        "theoretical_fpr": theoretical_fpr,
        "absolute_difference": abs(measured_fpr - theoretical_fpr),
        "verified_present_passwords": sample_size,
        "false_negatives": false_negatives,
        "dataset_load_seconds": load_seconds,
        "query_total_seconds": query_seconds,
        "query_average_microseconds": query_seconds / len(probes) * 1_000_000,
        "seed": args.seed,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(result.keys()))
        writer.writeheader()
        writer.writerow(result)

    print("=== Эксперимент 1: измеренный FPR и теория ===")
    print(f"Уникальных паролей RockYou: {len(passwords):,}")
    print(f"Параметры фильтра: m={bf.m:,} бит, k={bf.k}")
    print(f"Размер битового массива: {bf.size_bytes() / (1024 ** 2):.2f} MiB")
    print(f"Заполненность битов: {bf.fill_ratio():.4%}")
    print(f"Ложные срабатывания: {false_positives} из {len(probes):,}")
    print(f"Измеренный FPR: {measured_fpr:.6%}")
    print(f"Теоретический FPR: {theoretical_fpr:.6%}")
    print(f"Абсолютная разница: {abs(measured_fpr - theoretical_fpr):.6%}")
    print(f"Проверено добавленных паролей: {sample_size:,}; ложноотрицательных: {false_negatives}")
    print(f"Среднее время одной проверки: {result['query_average_microseconds']:.3f} мкс")
    print(f"CSV с результатами: {args.output}")

    if false_negatives:
        raise AssertionError(
            "Обнаружены ложноотрицательные результаты. Проверьте, что фильтр построен "
            "по тому же набору RockYou и что файл фильтра не повреждён."
        )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rockyou", type=Path, help="Путь к rockyou.txt")
    parser.add_argument("filter", type=Path, help="Путь к готовому .bloom-фильтру")
    parser.add_argument("--probes", type=int, default=100_000,
                        help="Количество отсутствующих тестовых паролей (по умолчанию: 100000)")
    parser.add_argument("--verify-sample", type=int, default=10_000,
                        help="Сколько паролей из RockYou проверить на отсутствие false negatives")
    parser.add_argument("--seed", type=int, default=20261019,
                        help="Seed генератора для воспроизводимости")
    parser.add_argument("--output", type=Path, default=Path("results/fpr_results.csv"),
                        help="Куда сохранить CSV")
    args = parser.parse_args()
    if args.probes <= 0 or args.verify_sample < 0:
        parser.error("--probes должен быть > 0, а --verify-sample должен быть >= 0")
    if not args.rockyou.is_file():
        parser.error(f"Файл RockYou не найден: {args.rockyou}")
    if not args.filter.is_file():
        parser.error(f"Файл фильтра не найден: {args.filter}")
    return args


if __name__ == "__main__":
    run(parse_args())
