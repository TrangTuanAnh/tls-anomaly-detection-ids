import os
import json
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

# --- CONFIG ---
EVE_PATH = "../logs/eve.json"
MODEL_FILE = "../models/isolation_forest_tls.pkl"
SCALER_FILE = "../models/scaler_tls.pkl"
TRAIN_FEATURE_FILE = "dataset/tls_features.csv"  # dùng để fit lại scaler nếu không có


# Đúng 16 feature numeric như trong báo cáo / train_ae log
FEATURE_COLUMNS = [
    "tls_version_enum",
    "is_legacy_version",
    "RULE_DEPRECATED_VERSION",
    "num_ciphers",
    "num_strong_ciphers",
    "num_weak_ciphers",
    "weak_cipher_ratio",
    "supports_pfs",
    "prefers_pfs",
    "pfs_cipher_ratio",
    "num_groups",
    "uses_modern_group",
    "legacy_group_ratio",
    "RULE_WEAK_CIPHER",
    "RULE_NO_PFS",
    "RULE_CBC_ONLY",
]

# --- BẢNG TRA CƠ BẢN (HEURISTIC) ---

# TLS version mapping (chuẩn đủ dùng cho detection)
TLS_VERSION_ENUM = {
    "SSLv2": 0,
    "SSLv3": 0,
    "TLSv1": 1,
    "TLSv1.0": 1,
    "TLS1.0": 1,
    "TLSv1.1": 2,
    "TLS1.1": 2,
    "TLSv1.2": 3,
    "TLS1.2": 3,
    "TLSv1.3": 4,
    "TLS1.3": 4,
}
DEPRECATED_VERS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLS1.0", "TLSv1.1", "TLS1.1"}

# Một số cipher ID phổ biến (decimal) – đủ cover phần lớn traffic thực tế
# TLS 1.3 AEAD (mạnh)
AEAD_TLS13 = {4865, 4866, 4867, 4868, 4869}  # 0x1301..0x1305
# TLS 1.2 ECDHE+AES-GCM / CHACHA20 (mạnh + PFS)
PFS_AEAD_IDS = {
    49195, 49196, 49199, 49200,     # ECDHE_*_AES_GCM
    52392, 52393, 52394,            # ECDHE/DHE_*_CHACHA20
    158, 159,                       # DHE_RSA_WITH_AES_*_GCM
}
AEAD_CIPHER_IDS = AEAD_TLS13 | PFS_AEAD_IDS

# Một ít cipher yếu kinh điển (RC4, 3DES) – decimal values từ IANA
WEAK_CIPHER_IDS = {
    4,   # TLS_RSA_WITH_RC4_128_MD5
    5,   # TLS_RSA_WITH_RC4_128_SHA
    10,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
}

# PFS cipher: tạm thời dùng đúng PFS_AEAD_IDS (đủ tốt cho detection)
PFS_CIPHER_IDS = PFS_AEAD_IDS.copy()

# Group IDs (EllipticCurves) theo RFC
MODERN_GROUP_IDS = {23, 24, 29, 30}  # secp256r1, secp384r1, x25519, x448


# --- HÀM TIỆN ÍCH FEATURE ENGINEERING ---

def normalize_tls_version(ver_str: str):
    if not isinstance(ver_str, str):
        return -1, 0, 0  # enum, is_legacy, RULE_DEPRECATED_VERSION

    v = ver_str.strip()
    enum = TLS_VERSION_ENUM.get(v, -1)
    is_legacy = 1 if v in DEPRECATED_VERS or enum in (0, 1, 2) else 0
    rule_dep = 1 if v in DEPRECATED_VERS else 0
    return enum, is_legacy, rule_dep


def parse_ja3_string(ja3_str: str):
    """
    JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    Trả về:
      - danh sách cipher_ids (int)
      - danh sách group_ids (int)
    """
    if not isinstance(ja3_str, str) or not ja3_str:
        return [], []

    parts = ja3_str.split(",")
    if len(parts) < 4:
        return [], []

    # Ciphers
    ciphers_part = parts[1]
    if ciphers_part == "0" or ciphers_part == "":
        cipher_ids = []
    else:
        cipher_ids = []
        for tok in ciphers_part.split("-"):
            if tok and tok != "0":
                try:
                    cipher_ids.append(int(tok))
                except ValueError:
                    continue

    # EllipticCurves (groups)
    groups_part = parts[3]
    if groups_part == "0" or groups_part == "":
        group_ids = []
    else:
        group_ids = []
        for tok in groups_part.split("-"):
            if tok and tok != "0":
                try:
                    group_ids.append(int(tok))
                except ValueError:
                    continue

    return cipher_ids, group_ids


def parse_ja3s_string(ja3s_str: str):
    """
    JA3S format: TLSVersion,Cipher,Extensions
    -> ta chỉ cần Cipher ID server chọn.
    """
    if not isinstance(ja3s_str, str) or not ja3s_str:
        return None

    parts = ja3s_str.split(",")
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def cipher_stats(cipher_ids):
    num_ciphers = len(cipher_ids)
    num_strong = 0
    num_weak = 0
    num_pfs = 0

    for cid in cipher_ids:
        if cid in AEAD_CIPHER_IDS:
            num_strong += 1
        if cid in WEAK_CIPHER_IDS:
            num_weak += 1
        if cid in PFS_CIPHER_IDS:
            num_pfs += 1

    weak_ratio = (num_weak / num_ciphers) if num_ciphers > 0 else 0.0
    pfs_ratio = (num_pfs / num_ciphers) if num_ciphers > 0 else 0.0
    supports_pfs = 1 if num_pfs > 0 else 0
    prefers_pfs = 1 if (cipher_ids and cipher_ids[0] in PFS_CIPHER_IDS) else 0

    return {
        "num_ciphers": num_ciphers,
        "num_strong_ciphers": num_strong,
        "num_weak_ciphers": num_weak,
        "weak_cipher_ratio": weak_ratio,
        "supports_pfs": supports_pfs,
        "prefers_pfs": prefers_pfs,
        "pfs_cipher_ratio": pfs_ratio,
        "num_aead": sum(1 for cid in cipher_ids if cid in AEAD_CIPHER_IDS),
    }


def group_stats(group_ids):
    num_groups = len(group_ids)
    modern = sum(1 for g in group_ids if g in MODERN_GROUP_IDS)
    legacy = num_groups - modern
    legacy_ratio = (legacy / num_groups) if num_groups > 0 else 0.0
    uses_modern = 1 if modern > 0 else 0

    return {
        "num_groups": num_groups,
        "uses_modern_group": uses_modern,
        "legacy_group_ratio": legacy_ratio,
    }


def extract_tls_features(event):
    """
    Nhận 1 event TLS từ eve.json, trả về:
      - feature_dict (chỉ 16 numeric feature)
      - metadata (timestamp, src/dst, ja3 hash,...)
    """

    tls = event.get("tls", {})
    version = tls.get("version", "UNKNOWN")

    ja3 = tls.get("ja3", {})
    ja3s = tls.get("ja3s", {})

    if isinstance(ja3, dict):
        ja3_str = ja3.get("string")
        ja3_hash = ja3.get("hash")
    else:
        ja3_str = None
        ja3_hash = None

    if isinstance(ja3s, dict):
        ja3s_str = ja3s.get("string")
        ja3s_hash = ja3s.get("hash")
    else:
        ja3s_str = None
        ja3s_hash = None

    # Version features
    tls_version_enum, is_legacy, rule_deprecated = normalize_tls_version(version)

    # Client cipher & group features from JA3
    cipher_ids, group_ids = parse_ja3_string(ja3_str or "")
    c_stats = cipher_stats(cipher_ids)
    g_stats = group_stats(group_ids)

    # RULE_WEAK_CIPHER & RULE_NO_PFS dựa trên cipher server chọn (JA3S)
    server_cipher_id = parse_ja3s_string(ja3s_str or "")
    rule_weak_cipher = 0
    rule_no_pfs = 0

    if server_cipher_id is not None:
        # weak nếu RC4/3DES (ID trong WEAK_CIPHER_IDS)
        if server_cipher_id in WEAK_CIPHER_IDS:
            rule_weak_cipher = 1
        # NO_PFS: nếu server chọn cipher không nằm trong PFS_CIPHER_IDS và version != TLS1.3
        if (server_cipher_id not in PFS_CIPHER_IDS) and tls_version_enum != 4:
            rule_no_pfs = 1

    # RULE_CBC_ONLY: TLS >= 1.2 mà không có AEAD cipher nào trong list
    rule_cbc_only = 0
    if tls_version_enum >= 3 and c_stats["num_aead"] == 0:
        rule_cbc_only = 1

    feature_row = {
        "tls_version_enum": tls_version_enum,
        "is_legacy_version": is_legacy,
        "RULE_DEPRECATED_VERSION": rule_deprecated,
        "num_ciphers": c_stats["num_ciphers"],
        "num_strong_ciphers": c_stats["num_strong_ciphers"],
        "num_weak_ciphers": c_stats["num_weak_ciphers"],
        "weak_cipher_ratio": c_stats["weak_cipher_ratio"],
        "supports_pfs": c_stats["supports_pfs"],
        "prefers_pfs": c_stats["prefers_pfs"],
        "pfs_cipher_ratio": c_stats["pfs_cipher_ratio"],
        "num_groups": g_stats["num_groups"],
        "uses_modern_group": g_stats["uses_modern_group"],
        "legacy_group_ratio": g_stats["legacy_group_ratio"],
        "RULE_WEAK_CIPHER": rule_weak_cipher,
        "RULE_NO_PFS": rule_no_pfs,
        "RULE_CBC_ONLY": rule_cbc_only,
    }

    metadata = {
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "dest_ip": event.get("dest_ip"),
        "sni": tls.get("sni"),
        "version": version,
        "ja3_hash": ja3_hash,
        "ja3s_hash": ja3s_hash,
    }

    return feature_row, metadata


# --- LOAD MODEL + SCALER ---

def load_model_and_scaler():
    if not os.path.exists(MODEL_FILE):
        raise FileNotFoundError(f"Không tìm thấy IsolationForest model: {MODEL_FILE}")

    print(f"[+] Load Isolation Forest model từ {MODEL_FILE} ...")
    model = joblib.load(MODEL_FILE)

    if os.path.exists(SCALER_FILE):
        print(f"[+] Load scaler IF từ {SCALER_FILE}")
        scaler = joblib.load(SCALER_FILE)
    else:
        print("[i] Không thấy scaler_if_tls.pkl, fit lại scaler từ dataset/tls_features.csv ...")
        if not os.path.exists(TRAIN_FEATURE_FILE):
            raise FileNotFoundError(
                f"Không tìm thấy file training feature {TRAIN_FEATURE_FILE} để fit scaler."
            )
        df_train = pd.read_csv(TRAIN_FEATURE_FILE)
        missing_cols = [c for c in FEATURE_COLUMNS if c not in df_train.columns]
        if missing_cols:
            raise ValueError(f"Thiếu các cột feature trong dataset: {missing_cols}")

        X_train = df_train[FEATURE_COLUMNS].fillna(0.0)
        scaler = StandardScaler().fit(X_train)
        os.makedirs(os.path.dirname(SCALER_FILE), exist_ok=True)
        joblib.dump(scaler, SCALER_FILE)
        print(f"[+] Scaler IF đã fit và lưu tại {SCALER_FILE}")

    return model, scaler


# --- TAIL EVE.JSON ---

def follow_eve(path):
    """
    Đọc file giống tail -F: cứ có dòng mới là yield ra.
    """
    with open(path, "r") as f:
        # nhảy đến cuối file hiện tại (chỉ bắt sự kiện mới)
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    if not os.path.exists(EVE_PATH):
        print(f"[-] Không tìm thấy {EVE_PATH}. Hãy chắc chắn Suricata đang log eve.json vào thư mục logs/")
        return

    model, scaler = load_model_and_scaler()
    print("[+] Bắt đầu theo dõi TLS realtime từ logs/eve.json ... (Ctrl+C để dừng)\n")

    try:
        for line in follow_eve(EVE_PATH):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Chỉ xử lý TLS event (hoặc alert có trường tls)
            if event.get("event_type") != "tls" and not (
                event.get("event_type") == "alert" and "tls" in event
            ):
                continue

            feature_row, meta = extract_tls_features(event)

            # Đưa về DataFrame để dễ align cột
            df_feat = pd.DataFrame([feature_row])
            df_feat = df_feat[FEATURE_COLUMNS].fillna(0.0)

            X_scaled = scaler.transform(df_feat.values)

            # Isolation Forest: -1 = anomaly, 1 = normal
            y_pred = model.predict(X_scaled)[0]
            score = model.decision_function(X_scaled)[0]

            is_anom = (y_pred == -1)
            label = "ANOMALY" if is_anom else "normal "

            # In ra console
            ts = meta.get("timestamp")
            src = meta.get("src_ip")
            dst = meta.get("dest_ip")
            sni = meta.get("sni") or "-"
            ver = meta.get("version") or "UNKNOWN"

            print(
                f"[{ts}] {src} -> {dst} | SNI={sni} | ver={ver} "
                f"| IF={label} | score={score:.4f}"
            )

    except KeyboardInterrupt:
        print("\n[+] Dừng realtime IF.")


if __name__ == "__main__":
    main()
