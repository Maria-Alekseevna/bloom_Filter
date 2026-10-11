"""
hybrid.py: схема Bloom filter + k-anonymity для проверки паролей.

Схема (шаги 1-5 из плана):
    пароль -> локальный Bloom filter
        "точно нет"      -> готово, сетевого запроса не было
        "возможно есть"  -> клиент считает SHA-1 пароля и отправляет серверу
                            ТОЛЬКО первые 5 hex-символов (префикс).
                            Сервер возвращает все суффиксы хешей с этим префиксом.
                            Клиент сам ищет свой суффикс в ответе и принимает
                            окончательное решение. Пароль и полный хеш серверу
                            не передаются.

Это тот же приём k-anonymity, что и в сервисе Pwned Passwords (Have I Been Pwned).

Классы
    RangeServer      "сервер": хранит хеши утёкших паролей, отвечает на запросы по префиксу
    HybridChecker    "клиент": Bloom filter + запросы к серверу, считает статистику
"""
import bisect
import hashlib
from dataclasses import dataclass

PREFIX_LEN = 5  # 5 hex-символов = 20 бит, как в Pwned Passwords


def sha1_hex(password):
    """SHA-1 пароля в верхнем регистре (hex). Кодировка та же, что и в BloomFilter."""
    data = password.encode("utf-8", errors="surrogateescape")
    return hashlib.sha1(data).hexdigest().upper()


class RangeServer:
    """Сервер с базой утёкших паролей. Хранит только SHA-1 хеши.

    query_range(prefix) возвращает список суффиксов (35 символов) всех хешей
    с таким префиксом. Что именно искал клиент, серверу неизвестно.
    """

    def __init__(self, passwords):
        self._hashes = sorted({sha1_hex(p) for p in passwords})
        self.requests = 0          # сколько запросов получил сервер
        self.bytes_sent = 0        # сколько байт ответов отдано
        self.seen_prefixes = []    # что видел сервер (для демонстрации приватности)

    def __len__(self):
        return len(self._hashes)

    def query_range(self, prefix):
        prefix = prefix.upper()
        if len(prefix) != PREFIX_LEN:
            raise ValueError(f"нужен префикс из {PREFIX_LEN} символов")
        lo = bisect.bisect_left(self._hashes, prefix)
        hi = bisect.bisect_left(self._hashes, prefix + "G")  # 'G' больше любого hex-символа
        suffixes = [h[PREFIX_LEN:] for h in self._hashes[lo:hi]]
        self.requests += 1
        self.seen_prefixes.append(prefix)
        self.bytes_sent += sum(len(s) + 2 for s in suffixes)  # суффикс + перевод строки
        return suffixes


@dataclass
class CheckResult:
    leaked: bool            # окончательный вердикт
    bloom_maybe: bool       # что сказал локальный Bloom filter
    used_network: bool      # потребовался ли запрос к серверу
    prefix: str = ""        # что ушло на сервер (пусто, если запроса не было)
    range_size: int = 0     # сколько суффиксов вернул сервер

    @property
    def verdict(self):
        if not self.bloom_maybe:
            return "точно нет (решено локально)"
        return "найден в утечках" if self.leaked else "ложное срабатывание Bloom (сервер не подтвердил)"


class HybridChecker:
    """Клиентская часть: локальный Bloom filter + запрос диапазона на сервер."""

    def __init__(self, bloom, server):
        self.bloom = bloom
        self.server = server
        self.total = 0
        self.local_only = 0      # запросы, закрытые без сети
        self.network = 0         # запросы, дошедшие до сервера
        self.false_positives = 0 # Bloom сказал "возможно", сервер не подтвердил

    def check(self, password):
        self.total += 1
        if not self.bloom.contains(password):
            self.local_only += 1
            return CheckResult(leaked=False, bloom_maybe=False, used_network=False)

        h = sha1_hex(password)
        prefix, suffix = h[:PREFIX_LEN], h[PREFIX_LEN:]
        suffixes = self.server.query_range(prefix)   # <- единственное, что уходит в сеть
        self.network += 1
        leaked = suffix in set(suffixes)             # решение принимает клиент
        if not leaked:
            self.false_positives += 1
        return CheckResult(leaked=leaked, bloom_maybe=True, used_network=True,
                           prefix=prefix, range_size=len(suffixes))

    def local_share(self):
        """Доля проверок, не потребовавших сетевого запроса."""
        return self.local_only / self.total if self.total else 0.0
