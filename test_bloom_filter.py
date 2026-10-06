"""
test_bloom_filter.py: базовые тесты для bloom_filter.py.

Что проверяется
    test_added_found                добавленные пароли находятся
    test_unknown_mostly_not_found   неизвестные пароли почти всегда не находятся
    test_no_false_negatives         нет ложноотрицательных срабатываний
    test_save_load                  после сохранения и загрузки результаты те же
    test_params_formulas            m и k считаются по формулам
"""

import os
import random
import string
import tempfile

from bloom_filter import BloomFilter


def rand_str(n=12):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def test_added_found():
    bf = BloomFilter(1000, 0.01)
    for w in ["password", "123456", "qwerty"]:
        bf.add(w)
    assert all(w in bf for w in ["password", "123456", "qwerty"])


def test_unknown_mostly_not_found():
    bf = BloomFilter(1000, 0.01)
    for i in range(1000):
        bf.add(f"pass{i}")
    hits = sum(bf.contains("X" + rand_str()) for _ in range(5000))
    assert hits / 5000 < 0.05


def test_no_false_negatives():
    bf = BloomFilter(5000, 0.001)
    words = [rand_str() for _ in range(5000)]
    for w in words:
        bf.add(w)
    assert all(bf.contains(w) for w in words)


def test_save_load():
    bf = BloomFilter(1000, 0.01)
    words = [rand_str() for _ in range(1000)]
    for w in words:
        bf.add(w)
    probes = [rand_str() for _ in range(2000)]
    before = [bf.contains(x) for x in probes]
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "f.bloom")
        bf.save(path)
        bf2 = BloomFilter.load(path)
    assert (bf2.m, bf2.k, bf2.count) == (bf.m, bf.k, bf.count)
    assert before == [bf2.contains(x) for x in probes]
    assert all(bf2.contains(w) for w in words)


def test_params_formulas():
    bf = BloomFilter(1_000_000, 0.01)
    assert abs(bf.m - 9_585_059) < 5   # m = -n ln p / (ln2)^2
    assert bf.k == 7


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("OK", name)