"""
check.py: быстрая проверка готового фильтра на нескольких паролях.
 
Что делает
    Загружает сохранённый фильтр и для каждого пароля из списка печатает
    "возможно есть" или "точно нет".
"""

from bloom_filter import BloomFilter

bf = BloomFilter.load("rockyou_1pct.bloom")
for w in ["123456", "password", "iloveyou", "qX7#mP9$zL2vNw8"]:
    print(w, "→", "возможно есть" if bf.contains(w) else "точно нет")