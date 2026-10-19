
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("results/fpr_growth.csv")

plt.figure(figsize=(9, 5))
plt.plot(
    df["checkpoint_percent"],
    df["measured_fpr"] * 100,
    marker="o",
    label="Измеренный FPR",
)
plt.plot(
    df["checkpoint_percent"],
    df["theoretical_fpr"] * 100,
    marker="s",
    linestyle="--",
    label="Теоретический FPR",
)

plt.xlabel("Доля вставленных паролей, %")
plt.ylabel("FPR, %")
plt.title("Зависимость вероятности ложного срабатывания от заполнения фильтра")
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.savefig("graphs/fpr_growth.png", dpi=180)
plt.show()
