import os
import json
import random
import pickle
import numpy as np
import pandas as pd
import tensorflow as tf

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.metrics import classification_report, f1_score

from transformers import AutoTokenizer, TFAutoModelForSequenceClassification, create_optimizer
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras import mixed_precision

SEED = 42
DATA_FILE = os.getenv("TRAIN_DATA_FILE", "research_data_multilabel.csv")

MODEL_NAME = "allenai/scibert_scivocab_uncased"
MODEL_DIR = os.getenv("MODEL_DIR", "scibert_multilabel_v3")

ENCODER_FILE = os.path.join(MODEL_DIR, "multilabel_encoder.pickle")
THRESHOLDS_FILE = os.path.join(MODEL_DIR, "thresholds.json")

MAX_LEN = 320
BATCH_SIZE = 16
EPOCHS = 6
LEARNING_RATE = 2e-5

USE_MIXED_PRECISION = True
USE_POS_WEIGHT = True
POS_WEIGHT_CLIP = (1.0, 30.0)

GLOBAL_THRESHOLD_GRID = np.linspace(0.05, 0.70, 27)

os.environ["PYTHONHASHSEED"] = str(SEED)
random.seed(SEED)
np.random.seed(SEED)
tf.random.set_seed(SEED)

print(f"GPUs Available: {len(tf.config.list_physical_devices('GPU'))}")

if USE_MIXED_PRECISION:
    try:
        policy = mixed_precision.Policy("mixed_float16")
        mixed_precision.set_global_policy(policy)
        print(" Mixed Precision enabled")
    except Exception as e:
        print("Mixed precision not enabled:", e)

def clean_labels_cell(x: str):
    items = [t.strip() for t in str(x).split(",")]
    items = [t for t in items if t]
    return items

def make_tf_dataset(texts, labels, tokenizer, max_len, batch_size, shuffle=False):
    enc = tokenizer(
        texts.tolist(),
        truncation=True,
        padding="max_length",
        max_length=max_len,
        return_tensors="tf"
    )
    ds = tf.data.Dataset.from_tensor_slices((dict(enc), labels))
    if shuffle:
        ds = ds.shuffle(min(20000, len(texts)), seed=SEED, reshuffle_each_iteration=True)
    ds = ds.batch(batch_size).prefetch(tf.data.AUTOTUNE)
    return ds

def sigmoid_probs_from_logits(logits: np.ndarray) -> np.ndarray:
    logits = np.asarray(logits, dtype=np.float32)
    return 1.0 / (1.0 + np.exp(-logits))

def predict_probs(model, ds) -> np.ndarray:
    out = model.predict(ds, verbose=1)
    logits = out.logits if hasattr(out, "logits") else out[0]
    logits = np.asarray(logits, dtype=np.float32)
    return sigmoid_probs_from_logits(logits)

def best_global_threshold(y_true, probs, grid):
    best_t, best_f1 = 0.5, -1.0
    for t in grid:
        y_pred = (probs >= t).astype(np.int32)
        f1 = f1_score(y_true, y_pred, average="micro", zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_t = float(t)
    return best_t, float(best_f1)

class WeightedBCEWithLogits(tf.keras.losses.Loss):
    """
    Keras 3: не используем Reduction.AUTO.
    """
    def __init__(self, pos_weight: np.ndarray, name="weighted_bce_with_logits"):
        super().__init__(name=name, reduction="sum_over_batch_size")
        self.pos_weight = tf.constant(pos_weight, dtype=tf.float32)

    def call(self, y_true, y_pred):
        y_true = tf.cast(y_true, tf.float32)
        logits = tf.cast(y_pred, tf.float32)

        loss = tf.nn.weighted_cross_entropy_with_logits(
            labels=y_true,
            logits=logits,
            pos_weight=self.pos_weight
        )  
        return tf.reduce_mean(loss)

if not os.path.exists(DATA_FILE):
    raise FileNotFoundError(f"Файл {DATA_FILE} не найден.")

df = pd.read_csv(DATA_FILE)
df["text"] = df["text"].astype(str)
df["labels_list"] = df["labels"].apply(clean_labels_cell)

df = df[df["text"].str.len() > 0].copy()
df = df[df["labels_list"].map(len) > 0].copy()

mlb = MultiLabelBinarizer()
y = mlb.fit_transform(df["labels_list"])
classes = mlb.classes_
num_classes = len(classes)

print(f"🏷 Классов: {num_classes}")
print(f"Пример меток: {classes[:5]}")

X_train, X_temp, y_train, y_temp = train_test_split(
    df["text"].values, y, test_size=0.15, random_state=SEED
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, random_state=SEED
)

print(f"Train: {len(X_train)} | Val: {len(X_val)} | Test: {len(X_test)}")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, use_fast=True)

train_ds = make_tf_dataset(X_train, y_train, tokenizer, MAX_LEN, BATCH_SIZE, shuffle=True)
val_ds   = make_tf_dataset(X_val,   y_val,   tokenizer, MAX_LEN, BATCH_SIZE, shuffle=False)
test_ds  = make_tf_dataset(X_test,  y_test,  tokenizer, MAX_LEN, BATCH_SIZE, shuffle=False)

steps_per_epoch = int(np.ceil(len(X_train) / BATCH_SIZE))
total_train_steps = steps_per_epoch * EPOCHS
warmup_steps = int(0.1 * total_train_steps)

optimizer, _ = create_optimizer(
    init_lr=LEARNING_RATE,
    num_train_steps=total_train_steps,
    num_warmup_steps=warmup_steps,
)

model = TFAutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=num_classes,
    problem_type="multi_label_classification",
    from_pt=True
)

if USE_POS_WEIGHT:
    pos_counts = np.sum(y_train, axis=0).astype(np.float32)
    neg_counts = (y_train.shape[0] - pos_counts).astype(np.float32)
    pos_counts = np.maximum(pos_counts, 1.0)
    pos_weight = neg_counts / pos_counts
    pos_weight = np.clip(pos_weight, POS_WEIGHT_CLIP[0], POS_WEIGHT_CLIP[1])
    loss_fn = WeightedBCEWithLogits(pos_weight=pos_weight)
    print("⚖️ Using pos-weighted BCE. pos_weight range:", float(pos_weight.min()), float(pos_weight.max()))
else:
    loss_fn = tf.keras.losses.BinaryCrossentropy(from_logits=True)

model.compile(
    optimizer=optimizer,
    loss=loss_fn,
    metrics=[tf.keras.metrics.BinaryAccuracy(name="bin_acc", threshold=0.5)]
)

os.makedirs(MODEL_DIR, exist_ok=True)
ckpt_path = os.path.join(MODEL_DIR, "ckpt.weights.h5")

callbacks = [
    ModelCheckpoint(ckpt_path, save_best_only=True, monitor="val_loss", mode="min", save_weights_only=True, verbose=1),
    EarlyStopping(monitor="val_loss", patience=2, restore_best_weights=True, verbose=1),
]

print("\n Training...")
model.fit(
    train_ds,
    validation_data=val_ds,
    epochs=EPOCHS,
    callbacks=callbacks,
    verbose=1
)

if os.path.exists(ckpt_path):
    model.load_weights(ckpt_path)

print("\n🎚 Threshold tuning on val...")
probs_val = predict_probs(model, val_ds)
best_t, best_f1 = best_global_threshold(y_val, probs_val, GLOBAL_THRESHOLD_GRID)
print(f"✅ Best global threshold={best_t:.2f} | val micro-F1={best_f1:.4f}")

thresholds = {"type": "global", "global": float(best_t)}
with open(THRESHOLDS_FILE, "w", encoding="utf-8") as f:
    json.dump(thresholds, f, ensure_ascii=False, indent=2)

print("\n Test evaluation...")
probs_test = predict_probs(model, test_ds)
y_pred = (probs_test >= best_t).astype(np.int32)

micro = f1_score(y_test, y_pred, average="micro", zero_division=0)
macro = f1_score(y_test, y_pred, average="macro", zero_division=0)

print("Micro F1 Score:", micro)
print("Macro F1 Score:", macro)
print(classification_report(y_test, y_pred, target_names=classes, zero_division=0))

print("\n Saving artifacts...")
model.save_pretrained(MODEL_DIR)
tokenizer.save_pretrained(MODEL_DIR)

with open(ENCODER_FILE, "wb") as f:
    pickle.dump(mlb, f)

print(f" Model dir: {MODEL_DIR}")
print(f" Encoder:   {ENCODER_FILE}")
print(f" Threshold: {THRESHOLDS_FILE}")
