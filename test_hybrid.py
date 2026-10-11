"""
test_hybrid.py: тесты для hybrid.py (схема Bloom filter + k-anonymity).

Что проверяется
    test_sha1_known_value        SHA-1 считается верно (известное значение для "password")
    test_range_server            сервер возвращает все суффиксы своего префикса и только их
    test_leaked_confirmed        утёкший пароль находится и подтверждается сервером
    test_clean_stays_local       чистый пароль закрывается локально, без запроса к серверу
    test_only_prefix_sent        на сервер уходит только 5-символьный префикс, не пароль и не полный хеш
    test_false_positive_resolved ложное срабатывание Bloom исправляется сервером
"""

import random
import string

from bloom_filter import BloomFilter
from hybrid import PREFIX_LEN, HybridChecker, RangeServer, sha1_hex


def rand_str(n=14):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def make(leaked, p=0.01, **bloom_kwargs):
    bf = BloomFilter(len(leaked), p, **bloom_kwargs)
    for w in leaked:
        bf.add(w)
    return HybridChecker(bf, RangeServer(leaked))


def test_sha1_known_value():
    assert sha1_hex("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_range_server():
    words = [rand_str() for _ in range(2000)]
    server = RangeServer(words)
    h = sha1_hex(words[0])
    suffixes = server.query_range(h[:PREFIX_LEN])
    assert h[PREFIX_LEN:] in suffixes
    expected = {sha1_hex(w)[PREFIX_LEN:] for w in words if sha1_hex(w).startswith(h[:PREFIX_LEN])}
    assert set(suffixes) == expected


def test_leaked_confirmed():
    leaked = ["123456", "password", "iloveyou"]
    checker = make(leaked)
    for w in leaked:
        r = checker.check(w)
        assert r.leaked and r.bloom_maybe and r.used_network


def test_clean_stays_local():
    checker = make([rand_str() for _ in range(2000)], p=0.001)
    results = [checker.check("clean-" + rand_str()) for _ in range(2000)]
    assert all(not r.leaked for r in results)           # ложных "найден" не бывает
    assert checker.local_share() > 0.99                 # почти всё закрыто без сети


def test_only_prefix_sent():
    leaked = ["hunter2"]
    checker = make(leaked)
    checker.check("hunter2")
    assert len(checker.server.seen_prefixes) == 1
    sent = checker.server.seen_prefixes[0]
    assert len(sent) == PREFIX_LEN
    assert sent == sha1_hex("hunter2")[:PREFIX_LEN]


def test_false_positive_resolved():
    # маленький фильтр с заведомо большим FPR: часть чистых паролей даст "возможно есть"
    leaked = [rand_str() for _ in range(2000)]
    checker = make(leaked, m=4000, k=2)
    clean = ["clean-" + rand_str() for _ in range(2000)]
    results = [checker.check(w) for w in clean]
    assert checker.false_positives > 0                  # Bloom ошибался...
    assert all(not r.leaked for r in results)           # ...но итоговый вердикт верный
    assert checker.network == checker.false_positives


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("OK", name)
