import os
import pandas as pd
import numpy as np
import glob

# ===================== CONFIG ===================== 
DATASET_DIR = "dataset/cic-ids-2017"
BENIGN_OUT  = "dataset/benign.csv"
ATTACK_OUT  = "dataset/attack.csv"

CSV_FILES = sorted(glob.glob(os.path.join(DATASET_DIR, "*.csv")))

print("[DEBUG] DATASET_DIR =", DATASET_DIR)
print("[DEBUG] Found CSV files:", len(CSV_FILES))

# ==================================================

def normalize_label(df: pd.DataFrame) -> pd.DataFrame:
    df["Label"] = df["Label"].astype(str).str.strip()
    
    # Mapping
    label_fix = {
        "FTP-Patator": "FTP-Patator",
        "SSH-Patator": "SSH-Patator",
        "DoS Hulk": "DoS Hulk",
        "DoS GoldenEye": "DoS GoldenEye",
        "DoS slowloris": "DoS slowloris",
        "DoS Slowhttptest": "DoS Slowhttptest",
        "DDoS": "DDoS",
        "Bot": "Bot",
        "Infiltration": "Infiltration",
        "Heartbleed": "Heartbleed",
        "PortScan": "PortScan"
    }
    
    # Standardation Web-Attack
    df["Label"] = df["Label"].str.replace(r"Web Attack.*Brute Force", "Web Attack - Brute Force", regex=True, case=False)
    df["Label"] = df["Label"].str.replace(r"Web Attack.*XSS", "Web Attack - XSS", regex=True, case=False)
    df["Label"] = df["Label"].str.replace(r"Web Attack.*SQL Injection", "Web Attack - SQL Injection", regex=True, case=False)
    
    return df


def load_csv(path):
    print(f"[*] Loading {os.path.basename(path)}")
    df = pd.read_csv(path, encoding="latin1")

    # Fix column names
    df.columns = df.columns.str.strip()
    df.columns = df.columns.str.replace(r"\s+", " ", regex=True)

    if "Label" not in df.columns:
        raise RuntimeError(f"File {path} không có cột Label")

    df = normalize_label(df)

    # clean Inf / NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    return df


def main():
    benign_dfs = []
    attack_dfs = []

    for path in CSV_FILES:
        df = load_csv(path)

        benign = df[df["Label"] == "BENIGN"]
        attack = df[df["Label"] != "BENIGN"]

        benign_dfs.append(benign)
        attack_dfs.append(attack)

        print(f"    BENIGN : {len(benign):>8}")
        print(f"    ATTACK : {len(attack):>8}")

    benign_df = pd.concat(benign_dfs, ignore_index=True)
    attack_df = pd.concat(attack_dfs, ignore_index=True)

    os.makedirs("dataset", exist_ok=True)

    benign_df.to_csv(BENIGN_OUT, index=False)
    attack_df.to_csv(ATTACK_OUT, index=False)

    print("\n================ FINAL SUMMARY ================")
    print(f"BENIGN total : {len(benign_df)}")
    print("\nATTACK breakdown:")
    print(attack_df["Label"].value_counts().sort_index())

    print("\nSaved files:")
    print(f"  -> {BENIGN_OUT}")
    print(f"  -> {ATTACK_OUT}")
    print("================================================")


if __name__ == "__main__":
    main()
