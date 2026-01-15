import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ===================== CONFIG =====================
BENIGN_PATH = "dataset/benign.csv"
ATTACK_PATH = "dataset/attack.csv"

TRAIN_OUT = "dataset/supervised_train.csv"
TEST_OUT  = "dataset/supervised_test.csv"

SCALER_OUT = "models/scaler.pkl"

RANDOM_STATE = 42

UNKNOWN_ATTACKS = {
    "DoS slowloris",
    "DoS Slowhttptest",
    "Bot"
}

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
    print("[*] Loading datasets")
    benign_df = pd.read_csv(BENIGN_PATH)
    attack_df = pd.read_csv(ATTACK_PATH)

    # ---------- sanity check ----------
    missing = set(FEATURES_35) - set(benign_df.columns)
    if missing:
        raise RuntimeError(f"Missing features in dataset: {missing}")

    # ---------- keep only selected features ----------
    benign_df = benign_df[FEATURES_35 + ["Label"]]
    attack_df = attack_df[FEATURES_35 + ["Label"]]

    # ---------- split BENIGN ----------
    benign_train, benign_test = train_test_split(
        benign_df,
        test_size=0.2,
        random_state=RANDOM_STATE,
        shuffle=True
    )

    # ---------- ATTACK ----------
    unknown_df = attack_df[attack_df["Label"].isin(UNKNOWN_ATTACKS)]
    known_df   = attack_df[~attack_df["Label"].isin(UNKNOWN_ATTACKS)]

    known_train, known_test = train_test_split(
        known_df,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=known_df["Label"]
    )
    attack_train = known_train
    attack_test = pd.concat([known_test, unknown_df], ignore_index=True)

    # ---------- merge ----------
    train_df = pd.concat([benign_train, attack_train], ignore_index=True)
    test_df  = pd.concat([benign_test, attack_test], ignore_index=True)

    train_df = train_df.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
    test_df  = test_df.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

    # ---------- binary label ----------
    train_df["y"] = (train_df["Label"] != "BENIGN").astype(int)
    test_df["y"]  = (test_df["Label"] != "BENIGN").astype(int)

    # ---------- scaler ----------
    X_train = train_df[FEATURES_35]
    scaler = StandardScaler()
    scaler.fit(X_train)

    os.makedirs(os.path.dirname(SCALER_OUT), exist_ok=True)
    joblib.dump(scaler, SCALER_OUT)

    # ---------- save ----------
    os.makedirs(os.path.dirname(TRAIN_OUT), exist_ok=True)
    train_df.to_csv(TRAIN_OUT, index=False)
    test_df.to_csv(TEST_OUT, index=False)

    # ---------- debug ----------
    print("\n=========== BUILD SUMMARY ===========")
    print(f"Features used : {len(FEATURES_35)}")
    print(f"Train samples : {len(train_df)}")
    print(train_df["y"].value_counts())
    print(f"Test samples  : {len(test_df)}")
    print(test_df["y"].value_counts())

    print("\nSaved:")
    print(" ->", TRAIN_OUT)
    print(" ->", TEST_OUT)
    print(" ->", SCALER_OUT)
    print("====================================")


if __name__ == "__main__":
    main()
