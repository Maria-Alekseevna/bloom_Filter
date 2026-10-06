"""Строит Bloom filter по RockYou.
Запуск: python build_rockyou.py rockyou.txt 0.01 rockyou_1pct.bloom

Что делает
    1. Читает файл с паролями (по одному на строку).
       Кодировка latin-1, потому что в RockYou есть невалидный UTF-8.
    2. Убирает дубликаты и пустые строки (n считается по уникальным паролям).
    3. Создаёт BloomFilter с заданным FPR и добавляет в него все пароли.
    4. Сохраняет фильтр в файл и печатает статистику: число паролей, m, k,
       размер фильтра, время построения, долю занятых битов, теоретический FPR.
"""

import sys
import time

from bloom_filter import BloomFilter


def main(path, p, out):
    t0 = time.time()
    # latin-1 не падает на невалидном UTF-8; set убирает дубликаты
    with open(path, encoding="latin-1") as f:
        passwords = {line.rstrip("\r\n") for line in f}
    passwords.discard("")
    n = len(passwords)
    print(f"уникальных паролей: {n} (чтение {time.time() - t0:.1f} c)")

    bf = BloomFilter(n, p)
    t1 = time.time()
    for pw in passwords:
        bf.add(pw)
    build = time.time() - t1
    bf.save(out)

    print(f"m = {bf.m}, k = {bf.k}")
    print(f"размер фильтра: {bf.size_bytes() / 1e6:.2f} МБ")
    print(f"время построения: {build:.1f} c")
    print(f"доля занятых битов: {bf.fill_ratio():.4f}")
    print(f"теоретический FPR: {bf.theoretical_fpr():.5f}")


if __name__ == "__main__":
    main(sys.argv[1], float(sys.argv[2]) if len(sys.argv) > 2 else 0.01,
         sys.argv[3] if len(sys.argv) > 3 else "rockyou.bloom")