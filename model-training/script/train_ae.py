# Sửa file train_autoencoder.py
import os

# Bỏ qua việc sử dụng GPU, buộc chạy trên CPU
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

import time
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, LeakyReLU
from tensorflow.keras.callbacks import ModelCheckpoint

# --- Configuration ---
INPUT_FILE = "logs/tls_features.csv"  # File feature đã export ở bước trước
MODEL_FILE = "models/autoencoder_tls.h5"
SCALER_FILE = "models/scaler_tls.pkl"
EPOCHS = 50
BATCH_SIZE = 128


def load_data(input_path):
    """Loads the preprocessed feature CSV file."""
    print(f"[+] [1/3] Loading features from {input_path}...")
    try:
        df = pd.read_csv(input_path)
        print(f"[+] Dataset loaded successfully. Total records: {len(df)}")

        # Log nhanh để thấy các cột hash (meta, không dùng làm feature)
        hash_cols = [c for c in df.columns if "hash" in c.lower()]
        if hash_cols:
            print(f"[i] Hash columns (metadata only, NOT used for training): {hash_cols}")

        return df
    except FileNotFoundError:
        print(
            f"[-] ERROR: Input file {input_path} not found. "
            f"Please ensure feature engineering was completed."
        )
        return None


def preprocess_for_ae(df):
    """Chọn feature số (TLS crypto features) và scale dữ liệu."""
    print("[+] [2/3] Selecting numerical TLS/crypto features and scaling data...")

    # 1) Lấy toàn bộ cột numeric
    numeric_cols = df.select_dtypes(include=np.number).columns.tolist()

    # 2) Loại trừ các cột không muốn train (nếu sau này có label dạng numeric)
    exclude_cols = {"label"}
    features_to_train = [c for c in numeric_cols if c not in exclude_cols]

    if not features_to_train:
        print(
            "[-] WARNING: No numerical features found for training. "
            "Check feature engineering script output."
        )
        return None, None

    print(f"[i] Using {len(features_to_train)} numeric feature columns for training:")
    for c in features_to_train:
        print(f"    - {c}")

    # 3) X là ma trận feature
    X = df[features_to_train].fillna(0.0)

    # 4) Scale (rất quan trọng cho NN)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Gắn tên cột vào scaler để script evaluate sau này có thể dùng lại đúng order
    try:
        scaler.feature_names_in_ = np.array(features_to_train)
    except Exception:
        pass

    # 5) Lưu scaler
    if not os.path.exists("models"):
        os.makedirs("models")
    joblib.dump(scaler, SCALER_FILE)
    print(f"[+] Data scaled. Scaler saved to {SCALER_FILE}")
    print(f"[+] Training features dimension: {X_scaled.shape}")

    return X_scaled, X.shape[1]


def build_autoencoder(input_dim):
    """Builds the Autoencoder model với kiến trúc đơn giản."""
    # Giảm chiều xuống khoảng 1/2, đảm bảo không quá bé
    encoding_dim = max(4, input_dim // 2)
    bottleneck_dim = max(2, encoding_dim // 2)

    # Encoder
    input_layer = Input(shape=(input_dim,), name="input")
    x = Dense(encoding_dim, name="enc_dense1")(input_layer)
    x = LeakyReLU(alpha=0.1, name="enc_lrelu1")(x)
    x = Dense(bottleneck_dim, name="enc_dense2")(x)
    x = LeakyReLU(alpha=0.1, name="enc_lrelu2")(x)
    encoded = x

    # Decoder
    x = Dense(encoding_dim, name="dec_dense1")(encoded)
    x = LeakyReLU(alpha=0.1, name="dec_lrelu1")(x)
    # Vì input đã được StandardScaler (mean~0, std~1), nên dùng 'linear' thay vì 'sigmoid'
    output_layer = Dense(input_dim, activation="linear", name="output")(x)

    autoencoder = Model(inputs=input_layer, outputs=output_layer, name="tls_autoencoder")
    autoencoder.compile(optimizer="adam", loss="mse")  # reconstruction MSE

    print(autoencoder.summary())
    return autoencoder


def train_autoencoder(X, input_dim):
    """Trains the Autoencoder model and saves it."""
    print(
        f"[+] [3/3] Training Autoencoder model "
        f"(Input Dim: {input_dim}, Epochs: {EPOCHS}, Batch: {BATCH_SIZE})..."
    )

    autoencoder = build_autoencoder(input_dim)

    # Checkpoint: lưu model tốt nhất theo val_loss
    checkpoint = ModelCheckpoint(
        MODEL_FILE,
        monitor="val_loss",
        save_best_only=True,
        mode="min",
        verbose=1,
    )

    start_time = time.time()
    history = autoencoder.fit(
        X,
        X,  # AE: input = output
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        shuffle=True,
        validation_split=0.1,  # 10% cho validation
        callbacks=[checkpoint],
        verbose=1,
    )
    end_time = time.time()

    print(f"\n[+] Training complete in {end_time - start_time:.2f} seconds.")
    print(f"[+] SUCCESS: Best model weights saved to {MODEL_FILE}.")

    return autoencoder, history


if __name__ == "__main__":
    # Check for TensorFlow/Keras installation
    try:
        import tensorflow as tf

        print(f"[+] TensorFlow version: {tf.__version__}")
    except ImportError:
        print(
            "[-] ERROR: TensorFlow/Keras not installed. "
            "Please install it using 'pip install tensorflow'."
        )
        exit()

    # Đảm bảo chạy từ thư mục root (giống các script khác)
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.getcwd() != ROOT_DIR:
        os.chdir(ROOT_DIR)

    data_df = load_data(INPUT_FILE)

    if data_df is not None and len(data_df) > 0:
        print(f"[+] Dataset size for training: {len(data_df)} records.")
        X_scaled, input_dim = preprocess_for_ae(data_df)

        if X_scaled is not None and X_scaled.size > 0:
            train_autoencoder(X_scaled, input_dim)
        else:
            print("[-] Cannot train: Features array is empty after preprocessing.")
    else:
        print("[-] Cannot train: Dataset is empty or failed to load.")
