"""
demo_server.py: сервер для веб-демо схемы Bloom filter + k-anonymity.

Запуск
    python demo_server.py                              # маленький учебный список demo_passwords.txt
    python demo_server.py --list rockyou.txt           # настоящий RockYou
    python demo_server.py --list rockyou.txt --fpr 0.001
    python demo_server.py --fpr 0.3                    # заведомо "плохой" фильтр: удобно показать ложное срабатывание
Затем открыть http://localhost:8000

Что отдаёт сервер
    /               страница демо (demo/index.html)
    /bloom.bin      Bloom filter в формате .bloom (браузер скачивает его один раз и проверяет пароль у себя)
    /range/<prefix> суффиксы SHA-1 хешей утёкших паролей с данным 5-символьным префиксом
    /seen           что видел сервер: список полученных префиксов (для демонстрации приватности)

Пароль в браузере не покидает страницу: наружу уходит только префикс хеша,
и только если локальный Bloom filter сказал "возможно есть".
"""
import argparse
import json
import os
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bloom_filter import BloomFilter
from hybrid import PREFIX_LEN, RangeServer

HERE = os.path.dirname(os.path.abspath(__file__))
HEX = set("0123456789ABCDEF")


def load_passwords(path):
    with open(path, encoding="latin-1") as f:   # как в build_rockyou.py
        pw = {line.rstrip("\r\n") for line in f}
    pw.discard("")
    return sorted(pw)


def make_handler(bloom_bytes, server, info):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                with open(os.path.join(HERE, "demo", "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif path == "/bloom.bin":
                self._send(200, bloom_bytes, "application/octet-stream")
            elif path == "/info":
                self._send(200, json.dumps(info).encode(), "application/json")
            elif path == "/seen":
                body = json.dumps({"requests": server.requests, "prefixes": server.seen_prefixes})
                self._send(200, body.encode(), "application/json")
            elif path.startswith("/range/"):
                prefix = path[len("/range/"):].upper()
                if len(prefix) != PREFIX_LEN or not set(prefix) <= HEX:
                    self._send(400, b"bad prefix", "text/plain")
                    return
                body = "\n".join(server.query_range(prefix)).encode()
                self._send(200, body, "text/plain; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain")

        def log_message(self, fmt, *args):
            # в логе сервера видно только то, что реально дошло до сервера
            print("запрос:", self.path)

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", default=os.path.join(HERE, "demo_passwords.txt"))
    ap.add_argument("--fpr", type=float, default=0.01)
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    passwords = load_passwords(args.list)
    print(f"паролей в базе: {len(passwords)}")
    bloom = BloomFilter(len(passwords), args.fpr)
    for pw in passwords:
        bloom.add(pw)
    server = RangeServer(passwords)

    with tempfile.TemporaryDirectory() as d:     # готовый .bloom-файл отдаём из памяти
        tmp = os.path.join(d, "demo.bloom")
        bloom.save(tmp)
        with open(tmp, "rb") as f:
            bloom_bytes = f.read()

    info = {"passwords": len(passwords), "fpr": args.fpr, "m": bloom.m, "k": bloom.k,
            "bloom_bytes": len(bloom_bytes), "source": os.path.basename(args.list)}
    print(f"Bloom filter: m={bloom.m}, k={bloom.k}, {len(bloom_bytes) / 1e6:.2f} МБ")
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(bloom_bytes, server, info))
    print(f"демо: http://localhost:{args.port}  (остановить: Ctrl+C)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nостановлено")


if __name__ == "__main__":
    main()
