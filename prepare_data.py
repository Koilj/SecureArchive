# prepare_data.py
import json
import os
import hashlib
from collections import Counter

import pandas as pd
from tqdm import tqdm

from utils import clean_text, format_model_input

DATA_FILE = "arxiv-metadata-oai-snapshot.json"
OUTPUT_FILE = "research_data_multilabel.csv"
STATS_FILE = "dataset_stats.json"

TOTAL_LIMIT = 150000
MIN_TEXT_LEN = 80             # минимальная длина итогового текста
MAX_LABELS_PER_SAMPLE = 4     # ограничение на число меток
DEDUP_MODE = "hash"           # "hash" (рекомендуется) или "none"

TARGET_CATEGORIES = {
    "cs.CV": "Computer Vision",
    "cs.LG": "Machine Learning",
    "cs.AI": "Artificial Intelligence",
    "cs.CL": "Computation and Language",
    "cs.CR": "Cryptography and Security",
    "cs.DC": "Distributed, Parallel, and Cluster Computing",
    "cs.SE": "Software Engineering",
    "cs.RO": "Robotics",
    "cs.CY": "Computers and Society",
    "cs.NI": "Networking and Internet Architecture",
    "cs.SI": "Social and Information Networks",
    "cs.IT": "Information Theory",
    "cs.DS": "Data Structures and Algorithms",
    "stat.ML": "Statistics - Machine Learning",
    "math.OC": "Optimization and Control",
    "math.PR": "Probability",
    "math.ST": "Statistics",
    "physics.comp-ph": "Computational Physics",
    "physics.data-an": "Data Analysis, Statistics and Probability",
    "quant-ph": "Quantum Physics",
    "q-bio.GN": "Genomics",
    "q-bio.NC": "Neuroscience",
    "q-bio.QM": "Quantitative Methods",
    "econ.EM": "Econometrics",
    "eess.IV": "Image and Video Processing",
    "eess.SP": "Signal Processing",
}

valid_cats_set = set(TARGET_CATEGORIES.keys())

def text_hash(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()

data = []
seen = set()
label_counter = Counter()
label_count_per_sample = Counter()

print(f"Сбор данных (multilabel, топ-{len(TARGET_CATEGORIES)} категорий)...")

if not os.path.exists(DATA_FILE):
    raise FileNotFoundError(f"❌ Файл {DATA_FILE} не найден.")

with open(DATA_FILE, "r", encoding="utf-8") as f:
    for i, line in tqdm(enumerate(f), total=None):
        if len(data) >= TOTAL_LIMIT:
            break

        try:
            doc = json.loads(line)

            raw_cats = str(doc.get("categories", "")).split()
            matched = [c for c in raw_cats if c in valid_cats_set]

            if not matched:
                continue

            # ограничим число меток, чтобы уменьшить шум
            matched = matched[:MAX_LABELS_PER_SAMPLE]

            title = clean_text(doc.get("title", ""))
            abstract = clean_text(doc.get("abstract", ""))
            authors = clean_text(doc.get("authors", ""))

            # можно добавить keywords, если они есть в твоём источнике
            full_text = format_model_input(title=title, authors=authors, abstract=abstract, keywords="")

            full_text = clean_text(full_text)

            if len(full_text) < MIN_TEXT_LEN:
                continue

            if DEDUP_MODE == "hash":
                h = text_hash(full_text)
                if h in seen:
                    continue
                seen.add(h)

            labels_str = ",".join(matched)

            data.append({"text": full_text, "labels": labels_str})

            label_count_per_sample[len(matched)] += 1
            for c in matched:
                label_counter[c] += 1

        except Exception:
            continue

df = pd.DataFrame(data)

df.to_csv(OUTPUT_FILE, index=False)

stats = {
    "total_rows": int(len(df)),
    "num_classes": int(len(valid_cats_set)),
    "labels_per_sample": {str(k): int(v) for k, v in sorted(label_count_per_sample.items())},
    "top_labels": dict(label_counter.most_common(30)),
}

with open(STATS_FILE, "w", encoding="utf-8") as f:
    json.dump(stats, f, ensure_ascii=False, indent=2)

print(f"\nСобрано {len(df)} статей.")
print(f"CSV: {OUTPUT_FILE}")
print(f"Stats: {STATS_FILE}")
