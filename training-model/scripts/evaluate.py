import os
import json
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
import matplotlib.pyplot as plt

from sklearn.metrics import (
    confusion_matrix,
    roc_auc_score,
    roc_curve
)

# ===================== CONFIG =====================
TEST_PATH   = "dataset/supervised_test.csv"
SCALER_PATH = "models/scaler.pkl"
MODEL_PATH  = "models/mlp.h5"
OUT_PATH    = "results/metrics.json"
PLOT_DIR    = "results/plots"

FEATURES_35 = [
    "Packet Length Std",
    "Total Length of Bwd Packets",
    "Subflow Bwd Bytes",
    "Destination Port",
    "Packet Length Variance",
    "Bwd Packet Length Mean",
    "Avg Bwd Segment Size",
    "Bwd Packet Length Max",
    "Init_Win_bytes_backward",
    "Total Length of Fwd Packets",
    "Subflow Fwd Bytes",
    "Init_Win_bytes_forward",
    "Average Packet Size",
    "Packet Length Mean",
    "Max Packet Length",
    "Fwd Packet Length Max",
    "Flow IAT Max",
    "Bwd Header Length",
    "Flow Duration",
    "Fwd IAT Max",
    "Fwd Header Length",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Flow IAT Mean",
    "Flow Bytes/s",
    "Bwd Packet Length Std",
    "Subflow Bwd Packets",
    "Total Backward Packets",
    "Fwd Packet Length Mean",
    "Avg Fwd Segment Size",
    "Bwd Packet Length Min",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s"
]
# =================================================


def main():
    os.makedirs(PLOT_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)

    print("[*] Loading test dataset")
    df = pd.read_csv(TEST_PATH)

    X = df[FEATURES_35]
    y_true = df["y"].values   # 0 = benign, 1 = anomaly

    print(f"    Test samples: {len(df)}")

    print("[*] Loading scaler & model")
    scaler = joblib.load(SCALER_PATH)
    model  = tf.keras.models.load_model(MODEL_PATH)

    X_scaled = scaler.transform(X)

    print("[*] Running inference")
    y_score = model.predict(X_scaled, batch_size=1024).ravel()
    y_pred  = (y_score >= 0.5).astype(int)

    df["y_pred"] = y_pred
    df["is_correct"] = (df["y_pred"] == df["y"])

    # ===================== PER-LABEL METRICS =====================
    label_stats = {}
    for label, group in df.groupby("Label"):
        total = len(group)
        correct = int(group["is_correct"].sum())
        accuracy = float(correct / total) if total > 0 else 0.0
        
        label_stats[label] = {
            "total_samples": total,
            "correct_detected": correct,
            "accuracy": round(accuracy, 4)
        }

    # ===================== OVERALL METRICS =====================
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    auc = roc_auc_score(y_true, y_score)

    metrics = {
        "overall": {
            "TPR": float(tpr),
            "FPR": float(fpr),
            "ROC_AUC": float(auc),
            "confusion_matrix": {
                "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)
            }
        },
        "per_label": label_stats
    }

    with open(OUT_PATH, "w") as f:
        json.dump(metrics, f, indent=4)

    # ===================== PLOTS =====================

    # 1. Score distribution 
    plt.figure(figsize=(8, 5))
    plt.hist(y_score[y_true == 0], bins=100, alpha=0.6, label="Benign", density=True)
    plt.hist(y_score[y_true == 1], bins=100, alpha=0.6, label="Anomaly", density=True)
    plt.axvline(0.5, color="red", linestyle="--", label="Threshold = 0.5")
    plt.xlabel("MLP Output Score (Sigmoid)")
    plt.ylabel("Density")
    plt.title("MLP Output Score Distribution")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(PLOT_DIR, "score_distribution.png"))
    plt.close()

    # 2. ROC Curve
    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, label=f"AUC = {auc:.4f}")
    plt.plot([0, 1], [0, 1], linestyle="--", color="gray")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve (MLP)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(PLOT_DIR, "roc_curve.png"))
    plt.close()

    # 3. Confusion Matrix
    plt.figure(figsize=(5, 4))
    plt.imshow(cm, cmap="Blues")
    plt.title("Confusion Matrix (MLP)")
    plt.colorbar()
    plt.xticks([0, 1], ["Benign", "Anomaly"])
    plt.yticks([0, 1], ["Benign", "Anomaly"])

    for i in range(2):
        for j in range(2):
            plt.text(
                j, i, cm[i, j],
                ha="center", va="center",
                color="white" if cm[i, j] > cm.max() / 2 else "black"
            )

    plt.tight_layout()
    plt.savefig(os.path.join(PLOT_DIR, "confusion_matrix.png"))
    plt.close()

    print("\n========== MLP EVALUATION ==========")
    print(f"TPR (Recall) : {tpr:.4f}")
    print(f"FPR          : {fpr:.4f}")
    print(f"ROC-AUC      : {auc:.4f}")
    print("===================================")

    print("[+] Metrics saved to:", OUT_PATH)
    print("[+] Plots saved to:", PLOT_DIR)


if __name__ == "__main__":
    main()
