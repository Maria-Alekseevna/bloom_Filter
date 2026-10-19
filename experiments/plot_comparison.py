
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

RESULTS = Path("results")
GRAPHS = Path("graphs")
GRAPHS.mkdir(exist_ok=True)


def save_plot(filename):
    plt.tight_layout()
    plt.savefig(GRAPHS / filename, dpi=180)
    plt.close()


# 1. FPR в зависимости от числа хеш-функций
df = pd.read_csv(RESULTS / "fpr_by_k.csv")

plt.figure(figsize=(8, 5))
plt.plot(
    df["filter_k_hashes"],
    df["measured_fpr"] * 100,
    marker="o",
    label="Измеренный FPR",
)
plt.plot(
    df["filter_k_hashes"],
    df["theoretical_fpr"] * 100,
    marker="s",
    linestyle="--",
    label="Теоретический FPR",
)
plt.xlabel("Количество хеш-функций k")
plt.ylabel("FPR, %")
plt.title("Влияние количества хеш-функций на FPR")
plt.xticks(df["filter_k_hashes"])
plt.grid(True)
plt.legend()
save_plot("fpr_by_k.png")


# 2. Сравнение объёма памяти и хранилища
bloom = pd.read_csv(RESULTS / "set_comparison.csv")
sqlite = pd.read_csv(RESULTS / "sqlite_comparison.csv")

names = ["Bloom filter", "Python set", "SQLite"]
sizes = [
    bloom.loc[bloom.structure == "bloom_filter",
              "memory_mib_estimated"].iloc[0],
    bloom.loc[bloom.structure == "python_set",
              "memory_mib_estimated"].iloc[0],
    sqlite.loc[sqlite.structure == "sqlite_indexed",
               "storage_mib_estimated"].iloc[0],
]

plt.figure(figsize=(8, 5))
bars = plt.bar(names, sizes)
plt.bar_label(bars, fmt="%.1f MiB")
plt.ylabel("Объём, МиБ")
plt.title("Сравнение памяти и размера хранилища")
plt.grid(axis="y")
save_plot("storage_comparison.png")


# 3. Сравнение скорости проверок
labels = ["Bloom filter", "Python set", "SQLite"]

absent = [
    bloom.loc[bloom.structure == "bloom_filter",
              "absent_query_average_microseconds"].iloc[0],
    bloom.loc[bloom.structure == "python_set",
              "absent_query_average_microseconds"].iloc[0],
    sqlite.loc[sqlite.structure == "sqlite_indexed",
               "absent_query_average_microseconds"].iloc[0],
]

present = [
    bloom.loc[bloom.structure == "bloom_filter",
              "present_query_average_microseconds"].iloc[0],
    bloom.loc[bloom.structure == "python_set",
              "present_query_average_microseconds"].iloc[0],
    sqlite.loc[sqlite.structure == "sqlite_indexed",
               "present_query_average_microseconds"].iloc[0],
]

x = range(len(labels))
width = 0.36

plt.figure(figsize=(8, 5))
plt.bar([i - width / 2 for i in x], absent, width,
        label="Пароль отсутствует")
plt.bar([i + width / 2 for i in x], present, width,
        label="Пароль присутствует")
plt.xticks(list(x), labels)
plt.ylabel("Среднее время проверки, мкс")
plt.title("Сравнение скорости проверки паролей")
plt.grid(axis="y")
plt.legend()
save_plot("lookup_time_comparison.png")

print("Графики сохранены в папке graphs/")
print(" - fpr_by_k.png")
print(" - storage_comparison.png")
print(" - lookup_time_comparison.png")
