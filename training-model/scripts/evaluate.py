import os
import json
import sys
import types
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

FEATURES_34 = [
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


class StandardScalerLite:
    """Portable StandardScaler (mean/scale only).

    This avoids pickle/joblib incompatibilities across numpy/sklearn versions.
    """

    def __init__(self, feature_names, mean_, scale_):
        self.feature_names_in_ = np.array(list(feature_names))
        self.n_features_in_ = int(len(feature_names))
        self.mean_ = np.array(mean_, dtype=np.float64)
        self.scale_ = np.array(scale_, dtype=np.float64)

    def transform(self, X):
        if hasattr(X, "to_numpy"):
            X = X.to_numpy()
        X = np.asarray(X, dtype=np.float64)
        denom = np.where(self.scale_ == 0, 1.0, self.scale_)
        return (X - self.mean_) / denom


def joblib_load_compat(path: str):
    """Load joblib artifacts with a small compatibility shim.

    Some pickles reference `numpy._core` (numpy 2.x internal path). Older numpy
    builds don't expose that module, causing `ModuleNotFoundError`.
    """
    try:
        return joblib.load(path)
    except (ModuleNotFoundError, ImportError) as e:
        msg = str(e)
        if "numpy._core" not in msg:
            raise

        import numpy.core.multiarray as _ma
        import numpy.core._multiarray_umath as _mu

        m = types.ModuleType("numpy._core")
        m.__path__ = []
        m.multiarray = _ma
        m._multiarray_umath = _mu
        sys.modules.setdefault("numpy._core", m)
        sys.modules.setdefault("numpy._core.multiarray", _ma)
        sys.modules.setdefault("numpy._core._multiarray_umath", _mu)
        return joblib.load(path)


def load_scaler_with_fallback(scaler_path: str):
    """Prefer joblib scaler; fall back to models/scaler_params.json if present."""
    try:
        return joblib_load_compat(scaler_path)
    except Exception:
        json_path = os.path.join(os.path.dirname(scaler_path), "scaler_params.json")
        if os.path.isfile(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                params = json.load(f)
            return StandardScalerLite(
                feature_names=params.get("feature_names", FEATURES_34),
                mean_=params.get("mean_", []),
                scale_=params.get("scale_", []),
            )
        raise


def main():
    os.makedirs(PLOT_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)

    print("[*] Loading test dataset")
    df = pd.read_csv(TEST_PATH)

    X = df[FEATURES_34]
    y_true = df["y"].values   # 0 = benign, 1 = anomaly

    print(f"    Test samples: {len(df)}")

    print("[*] Loading scaler & model")
    scaler = load_scaler_with_fallback(SCALER_PATH)
    model  = tf.keras.models.load_model(MODEL_PATH)

    X_scaled = scaler.transform(X)

    print("[*] Running inference")
    y_score = model.predict(X_scaled, batch_size=1024).ravel()
    threshold = float(os.getenv("MLP_THRESHOLD", "0.5"))
    y_pred  = (y_score >= threshold).astype(int)

    df["y_pred"] = y_pred
    df["is_correct"] = (df["y_pred"] == df["y"])

    # ===================== PER-LABEL METRICS (optional) =====================
    label_stats = {}
    if "Label" in df.columns:
        for label, group in df.groupby("Label"):
            total = len(group)
            correct = int(group["is_correct"].sum())
            accuracy = float(correct / total) if total > 0 else 0.0

            label_stats[str(label)] = {
                "total_samples": int(total),
                "correct_detected": int(correct),
                "accuracy": round(accuracy, 4),
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
    plt.axvline(threshold, color="red", linestyle="--", label=f"Threshold = {threshold}")
    plt.xlabel("MLP Output Score (Sigmoid)")
    plt.ylabel("Density")
    plt.title("MLP Output Score Distribution")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(PLOT_DIR, "score_distribution.png"))
    plt.close()

    # 2. ROC Curve
    fpr_curve, tpr_curve, _ = roc_curve(y_true, y_score)

    plt.figure(figsize=(6, 5))
    plt.plot(fpr_curve, tpr_curve, label=f"AUC = {auc:.4f}")
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
