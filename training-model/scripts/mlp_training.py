import os
import json

import pandas as pd
import joblib
import numpy as np

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.losses import BinaryCrossentropy

from sklearn.preprocessing import StandardScaler

# ===================== CONFIG =====================
TRAIN_PATH = "dataset/supervised_train.csv"
SCALER_PATH = "models/scaler.pkl"
MODEL_OUT   = "models/mlp.h5"

RANDOM_STATE = 42
BATCH_SIZE = 256
EPOCHS = 100
LEARNING_RATE = 0.001

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


def main():
    tf.random.set_seed(RANDOM_STATE)
    np.random.seed(RANDOM_STATE)

    print("[*] Loading datasets")
    
    train_df = pd.read_csv(TRAIN_PATH)
    X_train = train_df[FEATURES_34]
    y_train = train_df["y"]

    # Load scaler if exists, otherwise fit a new one
    os.makedirs(os.path.dirname(SCALER_PATH), exist_ok=True)
    if os.path.exists(SCALER_PATH):
        print("[*] Loading scaler")
        scaler = joblib.load(SCALER_PATH)
    else:
        print("[*] Fitting new StandardScaler")
        scaler = StandardScaler()
        scaler.fit(X_train)
        joblib.dump(scaler, SCALER_PATH)
        print("[*] Scaler saved to:", SCALER_PATH)

    X_train = scaler.transform(X_train)

    print("[*] Building MLP model")

    model = Sequential([
        Dense(100, activation="relu", input_shape=(len(FEATURES_34),)),
        Dense(50, activation="relu"),
        Dense(1, activation="sigmoid")
    ])

    model.compile(
        optimizer=Adam(learning_rate=LEARNING_RATE),
        loss=BinaryCrossentropy(),
        metrics=["accuracy"]
    )

    print("[*] Training MLP")
    history = model.fit(
        X_train, y_train,
        validation_split=0.2,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        verbose=1
    )

    os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
    model.save(MODEL_OUT)

    print("[*] Model saved to:", MODEL_OUT)

    # Export scaler parameters to a portable JSON for deployments that avoid pickle
    try:
        params = {
            "feature_names": FEATURES_34,
            "mean_": [float(x) for x in getattr(scaler, "mean_", [])],
            "scale_": [float(x) for x in getattr(scaler, "scale_", [])],
        }
        out_json = os.path.join(os.path.dirname(SCALER_PATH), "scaler_params.json")
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(params, f, indent=2)
        print("[*] Scaler params saved to:", out_json)
    except Exception as e:
        print("[!] Cannot export scaler_params.json:", e)


if __name__ == "__main__":
    main()
