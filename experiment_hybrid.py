"""
experiment_hybrid.py: какая доля проверок обходится без сетевого запроса.

Запуск
    python experiment_hybrid.py --list rockyou.txt            # на реальном RockYou
    python experiment_hybrid.py --synthetic 1000000           # без RockYou, на синтетическом списке
Параметры
    --queries N   сколько проверок в каждом прогоне (по умолчанию 200000)
    --out PREFIX  префикс выходных файлов (по умолчанию hybrid_results)

Что делает
    Для каждого целевого FPR фильтра (1%, 0.1%, 0.01%) и для каждой доли q утёкших
    паролей в потоке проверок прогоняет поток через HybridChecker и измеряет:
        - долю проверок, закрытых локально (без запроса к серверу);
        - число запросов к серверу;
        - реальный FPR Bloom filter на "чистых" паролях;
        - ошибки итогового вердикта (их быть не должно).
    Теория для сравнения: локально закрывается (1 - q) * (1 - FPR).
    Результаты: <out>.csv, <out>.md (таблица) и <out>.png (график).

Поток проверок: доля q берётся из списка утёкших паролей, остальное
"чистые" случайные пароли, которых в списке нет.
"""
import argparse
import csv
import random
import string
import time

from bloom_filter import BloomFilter
from hybrid import HybridChecker, RangeServer

FPRS = [0.01, 0.001, 0.0001]
SHARES = [0.0, 0.1, 0.3, 0.5]   # доля утёкших паролей в потоке проверок

SYLLABLES = ["ma", "ri", "ko", "to", "sa", "lu", "be", "no", "da", "vi", "ke", "po",
             "an", "el", "or", "in", "ur", "ta", "ni", "shi", "mo", "la", "ra", "ze"]


def load_list(path):
    # latin-1 как в build_rockyou.py: в RockYou есть невалидный UTF-8
    with open(path, encoding="latin-1") as f:
        pw = {line.rstrip("\r\n") for line in f}
    pw.discard("")
    return sorted(pw)


def synthetic_list(n, seed=1):
    """Правдоподобный по форме синтетический список: слоги + цифры."""
    rng = random.Random(seed)
    out = set()
    while len(out) < n:
        word = "".join(rng.choices(SYLLABLES, k=rng.randint(2, 4)))
        tail = rng.choice(["", str(rng.randint(0, 99)), str(rng.randint(1970, 2010)),
                           str(rng.randint(0, 9999)), "123", "!"])
        out.add(word + tail)
    return sorted(out)


def clean_password(rng, leaked_set):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pw = "".join(rng.choices(alphabet, k=rng.randint(10, 16)))
        if pw not in leaked_set:
            return pw


def run(bloom, server, leaked, leaked_set, share, queries, seed):
    rng = random.Random(seed)
    checker = HybridChecker(bloom, server)
    server.requests = 0
    server.bytes_sent = 0
    server.seen_prefixes = []
    clean_total = clean_bloom_maybe = wrong = 0
    for _ in range(queries):
        if rng.random() < share:
            pw, truth = rng.choice(leaked), True
        else:
            pw, truth = clean_password(rng, leaked_set), False
        r = checker.check(pw)
        if not truth:
            clean_total += 1
            clean_bloom_maybe += r.bloom_maybe
        wrong += (r.leaked != truth)
    return {
        "queries": queries,
        "local_share": checker.local_share(),
        "network_requests": checker.network,
        "measured_fpr": clean_bloom_maybe / clean_total if clean_total else float("nan"),
        "wrong_verdicts": wrong,
        "avg_range_size": (server.bytes_sent / 37 / server.requests) if server.requests else 0.0,
    }


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", help="файл со списком паролей (например rockyou.txt)")
    g.add_argument("--synthetic", type=int, help="сколько синтетических паролей сгенерировать")
    ap.add_argument("--queries", type=int, default=200_000)
    ap.add_argument("--out", default="hybrid_results")
    args = ap.parse_args()

    t0 = time.time()
    leaked = load_list(args.list) if args.list else synthetic_list(args.synthetic)
    leaked_set = set(leaked)
    n = len(leaked)
    source = args.list if args.list else f"синтетический список ({n} паролей)"
    print(f"список: {source}, уникальных паролей: {n} ({time.time() - t0:.1f} c)")

    server = RangeServer(leaked)
    print(f"сервер построен: {len(server)} хешей ({time.time() - t0:.1f} c)")

    rows = []
    for p in FPRS:
        bloom = BloomFilter(n, p)
        for pw in leaked:
            bloom.add(pw)
        print(f"\nBloom FPR={p}: m={bloom.m}, k={bloom.k}, размер {bloom.size_bytes() / 1e6:.2f} МБ, "
              f"теор. FPR={bloom.theoretical_fpr():.5f}")
        for share in SHARES:
            res = run(bloom, server, leaked, leaked_set, share, args.queries, seed=42)
            theory = (1 - share) * (1 - bloom.theoretical_fpr())
            row = {"target_fpr": p, "leaked_share": share, "theory_local_share": theory,
                   "bloom_mb": bloom.size_bytes() / 1e6, **res}
            rows.append(row)
            print(f"  доля утёкших {share:>4.0%}: без сети {res['local_share']:.4f} "
                  f"(теория {theory:.4f}), запросов к серверу {res['network_requests']}, "
                  f"FPR факт {res['measured_fpr']:.5f}, ошибочных вердиктов {res['wrong_verdicts']}")

    assert all(r["wrong_verdicts"] == 0 for r in rows), "итоговый вердикт должен быть всегда верным"

    csv_path = f"{args.out}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    md_path = f"{args.out}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"Источник списка: {source}; проверок в каждом прогоне: {args.queries}\n\n")
        f.write("| Целевой FPR | Доля утёкших в потоке | Без сети (факт) | Без сети (теория) | "
                "Запросов к серверу | FPR факт |\n|---|---|---|---|---|---|\n")
        for r in rows:
            f.write(f"| {r['target_fpr']:.2%} | {r['leaked_share']:.0%} | {r['local_share']:.2%} | "
                    f"{r['theory_local_share']:.2%} | {r['network_requests']} | "
                    f"{r['measured_fpr']:.4%} |\n")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7, 4.2))
        for p in FPRS:
            pts = [(r["leaked_share"] * 100, r["local_share"] * 100) for r in rows if r["target_fpr"] == p]
            ax.plot(*zip(*pts), marker="o", label=f"Bloom FPR {p:.2%}")
        ax.plot([s * 100 for s in SHARES], [(1 - s) * 100 for s in SHARES], "k--", lw=1,
                label="верхний предел (1 − q)")
        ax.set_xlabel("доля утёкших паролей среди проверяемых, %")
        ax.set_ylabel("проверок без сетевого запроса, %")
        ax.set_title("Bloom + k-anonymity: доля локально закрытых проверок")
        ax.set_ylim(0, 102)
        ax.grid(alpha=0.3)
        ax.legend()
        fig.tight_layout()
        fig.savefig(f"{args.out}.png", dpi=150)
        print(f"\nграфик: {args.out}.png")
    except ImportError:
        print("matplotlib не установлен, график пропущен")

    print(f"таблица: {md_path}, данные: {csv_path}")


if __name__ == "__main__":
    main()
