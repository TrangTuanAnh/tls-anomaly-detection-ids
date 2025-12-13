import pandas as pd
import numpy as np
import os
import time
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# --- Configuration ---
INPUT_FILE = "dataset/tls_features.csv"  # Đảm bảo trùng với file bạn export từ bước feature
MODEL_FILE = "models/isolation_forest_tls.pkl"

# Tỉ lệ ước lượng anomaly trong dữ liệu train (unsupervised)
OUTLIERS_FRACTION = 0.01


def load_data(input_path):
    """Loads the preprocessed feature CSV file."""
    print(f"[+] [1/3] Loading features from {input_path}...")
    try:
        df = pd.read_csv(input_path)
        print(f"[+] Dataset loaded successfully. Total records: {len(df)}")

        # Log nhanh các cột hash để biết chắc là KHÔNG dùng làm feature
        hash_cols = [c for c in df.columns if "hash" in c.lower()]
        if hash_cols:
            print(f"[i] Hash columns (meta only, NOT used for training): {hash_cols}")

        return df
    except FileNotFoundError:
        print(f"[-] ERROR: Input file {input_path} not found. Please ensure feature engineering was completed.")
        return None


def preprocess_for_if(df):
    """
    Chọn các feature số đúng nghĩa crypto feature và scale dữ liệu.

    Giả định file tls_features.csv (từ script feature trước) có:
      - metadata: timestamp, src_ip, dest_ip, version, ja3_hash, ja3s_hash, label
      - numeric features: tls_version_enum, is_legacy_version, RULE_DEPRECATED_VERSION,
                          num_ciphers, num_strong_ciphers, num_weak_ciphers,
                          weak_cipher_ratio, supports_pfs, prefers_pfs, pfs_cipher_ratio,
                          num_groups, uses_modern_group, legacy_group_ratio,
                          RULE_WEAK_CIPHER, RULE_NO_PFS, RULE_CBC_ONLY
    """
    print("[+] [2/3] Selecting numerical TLS/crypto features and scaling data...")

    # 1) Lấy toàn bộ cột numeric
    numeric_cols = df.select_dtypes(include=np.number).columns.tolist()

    # 2) Loại bỏ những cột không nên dùng làm feature nếu sau này vô tình thành numeric
    exclude_cols = {"label"}  # dự phòng nếu bạn encode label thành số sau này
    features_to_train = [c for c in numeric_cols if c not in exclude_cols]

    if not features_to_train:
        print("[-] WARNING: No numerical features found for training. Check feature engineering script output.")
        return None, None, None

    print(f"[i] Using {len(features_to_train)} numeric feature columns for training:")
    for c in features_to_train:
        print(f"    - {c}")

    # 3) Tạo ma trận X
    X = df[features_to_train].fillna(0)

    # 4) Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print(f"[+] Data scaled. Training features dimension: {X_scaled.shape}")
    return X_scaled, scaler, features_to_train


def train_isolation_forest(X_scaled, scaler, feature_names):
    """Trains the Isolation Forest model and saves it together with scaler + feature list."""
    print(f"[+] [3/3] Training Isolation Forest model...")

    model = IsolationForest(
        n_estimators=100,
        max_samples="auto",
        contamination=OUTLIERS_FRACTION,
        random_state=42,
        verbose=0,
    )

    start_time = time.time()
    model.fit(X_scaled)
    end_time = time.time()

    print(f"[+] Training complete in {end_time - start_time:.2f} seconds.")

    # Đóng gói model + scaler + danh sách feature để inference sau này dùng y hệt
    artifact = {
        "model": model,
        "scaler": scaler,
        "features": feature_names,
    }

    if not os.path.exists("models"):
        os.makedirs("models")
    joblib.dump(artifact, MODEL_FILE)
    print(f"[+] SUCCESS: Model + scaler + feature list saved to {MODEL_FILE}")

    return model


if __name__ == "__main__":
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.getcwd() != ROOT_DIR:
        os.chdir(ROOT_DIR)

    data_df = load_data(INPUT_FILE)

    if data_df is not None and len(data_df) > 0:
        print(f"[+] Dataset size for training: {len(data_df)} records.")
        X_scaled, scaler, feature_names = preprocess_for_if(data_df)

        if X_scaled is not None and X_scaled.size > 0:
            train_isolation_forest(X_scaled, scaler, feature_names)
        else:
            print("[-] Cannot train: Features array is empty after preprocessing.")
    else:
        print("[-] Cannot train: Dataset is empty or failed to load.")
