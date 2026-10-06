"""
Собственная реализация Bloom filter (double hashing на основе SHA-256).

Основной интерфейс
    BloomFilter(n, p)       создать фильтр (m и k можно задать вручную)
    add(item)               добавить элемент
    contains(item)          проверить элемент (или: item in bf)
    save(path) / load(path) сохранить фильтр в файл / загрузить из файла
    fill_ratio()            доля занятых битов
    theoretical_fpr()       теоретический FPR для текущего числа элементов
    size_bytes()            размер битового массива в байтах
    
"""
import hashlib
import json
import math
import struct


class BloomFilter:
    def __init__(self, n, p=0.01, k=None, m=None):
        """n - ожидаемое число элементов, p - желаемый FPR.
        m и k считаются по формулам, но их можно задать вручную
        (нужно для экспериментов с k и размером)."""
        if n <= 0 or not (0 < p < 1):
            raise ValueError("n > 0 и 0 < p < 1")
        self.n = n
        self.p = p
        self.m = m if m else math.ceil(-n * math.log(p) / (math.log(2) ** 2))
        self.k = k if k else max(1, round(self.m / n * math.log(2)))
        self.bits = bytearray((self.m + 7) // 8)  # битовый массив: 8 бит в байте
        self.count = 0  # сколько элементов добавлено

    def _positions(self, item):
        """Double hashing: g_i(x) = (h1 + i*h2) mod m."""
        data = item.encode("utf-8", errors="surrogateescape") if isinstance(item, str) else item
        digest = hashlib.sha256(data).digest()
        h1, h2 = struct.unpack("<QQ", digest[:16])
        h2 |= 1  # нечётный h2, чтобы шаги не вырождались
        return [(h1 + i * h2) % self.m for i in range(self.k)]

    def add(self, item):
        for pos in self._positions(item):
            self.bits[pos >> 3] |= 1 << (pos & 7)
        self.count += 1

    def contains(self, item):
        return all(self.bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(item))

    __contains__ = contains

    # ---- статистика и теория ----
    def fill_ratio(self):
        return sum(b.bit_count() for b in self.bits) / self.m

    def theoretical_fpr(self, n=None):
        """p ≈ (1 - e^(-kn/m))^k, по умолчанию для текущего числа элементов."""
        n = self.count if n is None else n
        return (1 - math.exp(-self.k * n / self.m)) ** self.k

    def size_bytes(self):
        return (self.m + 7) // 8

    # ---- сохранение / загрузка ----
    def save(self, path):
        meta = json.dumps({"n": self.n, "p": self.p, "m": self.m,
                           "k": self.k, "count": self.count}).encode()
        with open(path, "wb") as f:
            f.write(struct.pack("<I", len(meta)))
            f.write(meta)
            f.write(self.bits)

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            (meta_len,) = struct.unpack("<I", f.read(4))
            meta = json.loads(f.read(meta_len))
            bf = cls(meta["n"], meta["p"], k=meta["k"], m=meta["m"])
            bf.bits = bytearray(f.read())
            bf.count = meta["count"]
        return bf