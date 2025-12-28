# python-real-time-service/main.py
import os
import numpy as np
import joblib
import requests
import hmac
import hashlib
import json
import secrets
import time
from tensorflow.keras.models import load_model

from config import EVE_PATH, AE_THRESHOLD, ISO_THRESHOLD
from log_utils import follow_file, parse_tls_event
from feature_extractor import build_feature_vector_from_event

# URL Backend: chỉnh bằng biến môi trường BACKEND_URL
# - Trong Docker: thường là "http://backend:8000"
# - Khi chạy local: "http://localhost:8000"
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

# (Optional) HMAC signing for ingest -> backend
INGEST_HMAC_SECRET = os.getenv("INGEST_HMAC_SECRET", "")
INGEST_REQUIRE = os.getenv("REQUIRE_INGEST_HMAC", "false").lower() == "true"

# (Optional) Model integrity checks
AE_MODEL_SHA256 = os.getenv("AE_MODEL_SHA256", "")
SCALER_SHA256 = os.getenv("SCALER_SHA256", "")

# Tên feature tương ứng với vector trả về từ build_feature_vector_from_event(...)
FEATURE_NAMES = [
    "tls_version_enum",       # 0
    "is_legacy_version",      # 1
    "rule_deprecated_version",# 2  (RULE_DEPRECATED_VERSION)
    "num_ciphers",            # 3
    "num_strong_ciphers",     # 4
    "num_weak_ciphers",       # 5
    "weak_cipher_ratio",      # 6
    "supports_pfs",           # 7
    "prefers_pfs",            # 8
    "pfs_cipher_ratio",       # 9
    "num_groups",             # 10
    "uses_modern_group",      # 11
    "legacy_group_ratio",     # 12
    "rule_weak_cipher",       # 13  (RULE_WEAK_CIPHER)
    "rule_no_pfs",            # 14  (RULE_NO_PFS)
    "rule_cbc_only",          # 15  (RULE_CBC_ONLY)
]

INT_FEATURES = {
    "tls_version_enum",
    "num_ciphers",
    "num_strong_ciphers",
    "num_weak_ciphers",
    "num_groups",
}

BOOL_FEATURES = {
    "is_legacy_version",
    "rule_deprecated_version",
    "supports_pfs",
    "prefers_pfs",
    "uses_modern_group",
    "rule_weak_cipher",
    "rule_no_pfs",
    "rule_cbc_only",
}

FLOAT_FEATURES = {
    "weak_cipher_ratio",
    "pfs_cipher_ratio",
    "legacy_group_ratio",
}


def load_models():
    """
    Load scaler + autoencoder (và Isolation Forest nếu có).
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "trained_models")

    scaler_path_candidates = [
        os.getenv("SCALER_PATH", ""),
        os.path.join(models_dir, "scaler_tls.pkl"),
        os.path.join(models_dir, "scaler.pkl"),
    ]
    scaler_path = next((p for p in scaler_path_candidates if p and os.path.isfile(p)), "")
    ae_path = os.path.join(models_dir, "autoencoder_tls.h5")
    iso_path = os.path.join(models_dir, "isolation_forest_tls.pkl")

    if not scaler_path:
        raise FileNotFoundError("Không tìm thấy scaler (SCALER_PATH/scaler_tls.pkl/scaler.pkl)")
    if not os.path.isfile(ae_path):
        raise FileNotFoundError(f"Không tìm thấy autoencoder: {ae_path}")

    # ---- Integrity checks (sha256) ----
    def sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    if AE_MODEL_SHA256:
        actual = sha256_file(ae_path)
        if actual.lower() != AE_MODEL_SHA256.strip().lower():
            raise RuntimeError(f"AE model sha256 mismatch: expected {AE_MODEL_SHA256}, got {actual}")

    if SCALER_SHA256:
        actual = sha256_file(scaler_path)
        if actual.lower() != SCALER_SHA256.strip().lower():
            raise RuntimeError(f"Scaler sha256 mismatch: expected {SCALER_SHA256}, got {actual}")

    scaler = joblib.load(scaler_path)
    # compile=False để tránh lỗi deserialize metrics cũ
    ae_model = load_model(ae_path, compile=False)

    iso_model = None
    if os.path.isfile(iso_path):
        iso_model = joblib.load(iso_path)

    return scaler, ae_model, iso_model


def predict_anomaly(features, scaler, ae_model, iso_model=None):
    """
    Nhận list feature, scale và chạy qua model.
    Trả về dict: ae_error, ae_anom, (optional iso_score, iso_anom), anomaly.
    """
    x = np.asarray([features], dtype=float)
    x_scaled = scaler.transform(x)

    # --- Autoencoder ---
    recon = ae_model.predict(x_scaled, verbose=0)
    recon_err = float(((x_scaled - recon) ** 2).mean())
    ae_anom = int(recon_err > AE_THRESHOLD)

    result = {
        "ae_error": recon_err,
        "ae_anom": ae_anom,
    }

    # --- Isolation Forest (nếu có) ---
    if iso_model is not None:
        iso_score = iso_model.decision_function(x_scaled)[0]
        iso_anom = int(iso_score < ISO_THRESHOLD)
        result["iso_score"] = iso_score
        result["iso_anom"] = iso_anom
        # verdict tổng: OR 2 model
        result["anomaly"] = int(ae_anom == 1 or iso_anom == 1)
    else:
        result["anomaly"] = ae_anom

    return result


def build_feature_dict(features):
    """
    Map list feature (16 phần tử) -> dict tên:giá_trị,
    và convert sang đúng kiểu (int / bool / float) để backend & DB dùng.
    """
    if not isinstance(features, (list, tuple)):
        return {}

    # Nếu thiếu thì pad None
    if len(features) < len(FEATURE_NAMES):
        features = list(features) + [None] * (len(FEATURE_NAMES) - len(features))

    raw_dict = dict(zip(FEATURE_NAMES, features))
    out = {}

    for name, val in raw_dict.items():
        if val is None:
            out[name] = None
            continue

        if name in INT_FEATURES:
            out[name] = int(val)
        elif name in BOOL_FEATURES:
            # 0.0 -> False, 1.0 -> True
            out[name] = bool(round(float(val)))
        elif name in FLOAT_FEATURES:
            out[name] = float(val)
        else:
            # fallback: cứ để float
            out[name] = float(val)

    return out


def build_backend_payload(evt, features, result):
    """
    Đóng gói event TLS + kết quả model thành JSON gửi lên Backend.
    """
    tls = evt.get("tls") or {}
    ja3_obj = tls.get("ja3") or {}
    ja3s_obj = tls.get("ja3s") or {}

    feature_dict = build_feature_dict(features)

    payload = {
        # Thông tin chung của flow
        "event_time": evt.get("timestamp"),
        "sensor_name": evt.get("host"),     # nếu Suricata có field host
        "flow_id": evt.get("flow_id"),
        "src_ip": evt.get("src_ip"),
        "src_port": evt.get("src_port"),
        "dst_ip": evt.get("dest_ip"),
        "dst_port": evt.get("dest_port"),
        "proto": evt.get("proto"),

        # TLS / JA3 metadata
        "tls_version": tls.get("version"),
        "ja3_hash": ja3_obj.get("hash"),
        "ja3_string": ja3_obj.get("string"),
        "ja3s_string": ja3s_obj.get("string"),
        "sni": tls.get("sni"),

        # Kết quả model
        "ae_error": result.get("ae_error"),
        "ae_anom": bool(result.get("ae_anom", 0)),
        "iso_score": result.get("iso_score"),
        "iso_anom": bool(result.get("iso_anom", 0)) if "iso_anom" in result else None,
        "is_anomaly": bool(result.get("anomaly", 0)),

        # Toàn bộ feature để debug / lưu JSON
        "features_json": feature_dict,
    }

    # Đẩy luôn các feature chính ra top-level cho DB truy vấn dễ
    payload.update(feature_dict)

    return payload


def send_event_to_backend(payload):
    """
    Gửi POST /api/events lên Backend.
    Nếu lỗi thì chỉ log warning, không phá service.
    """
    if not BACKEND_URL:
        return

    url = BACKEND_URL.rstrip("/") + "/api/events"

    headers = {}

    # Optional: sign request (HMAC + nonce + timestamp) to harden ingest path
    if INGEST_HMAC_SECRET:
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        mac = hmac.new(INGEST_HMAC_SECRET.encode("utf-8"), digestmod=hashlib.sha256)
        mac.update(ts.encode("utf-8"))
        mac.update(b".")
        mac.update(nonce.encode("utf-8"))
        mac.update(b".")
        mac.update(body)
        sig = mac.hexdigest()
        headers.update({"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig})
    elif INGEST_REQUIRE:
        print("[RT][ERROR] REQUIRE_INGEST_HMAC=true but INGEST_HMAC_SECRET is empty")
        return

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=1.0)
        if not resp.ok:
            print(f"[RT][WARN] Backend trả HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"[RT][WARN] Không gửi được event lên backend: {e}")


def main():
    # Log khởi động ngắn gọn
    print("[RT] TLS anomaly detection service starting...")
    print(f"[RT] EVE_PATH = {EVE_PATH}")
    print(f"[RT] BACKEND_URL = {BACKEND_URL}")

    try:
        scaler, ae_model, iso_model = load_models()
    except Exception as e:
        print(f"[RT][ERROR] Không load được model: {e}")
        return

    if iso_model is not None:
        print("[RT] Models loaded: scaler + autoencoder + isolation forest.")
    else:
        print("[RT] Models loaded: scaler + autoencoder (không có isolation forest).")

    print("[RT] Service is running. Watching eve.json for TLS events...")

    # Vòng lặp realtime
    for line in follow_file(EVE_PATH):
        evt = parse_tls_event(line)
        if not evt:
            continue

        try:
            features = build_feature_vector_from_event(evt)
        except Exception as e:
            # Chỉ log lỗi thật sự
            print(f"[RT][ERROR] Lỗi khi trích feature từ event TLS: {e}")
            continue

        result = predict_anomaly(features, scaler, ae_model, iso_model)

        # Chỉ xử lý/bắn lên backend khi BẤT THƯỜNG
        if result.get("anomaly", 0) != 1:
            continue

        src = evt.get("src_ip")
        dst = evt.get("dest_ip")
        sport = evt.get("src_port")
        dport = evt.get("dest_port")
        ts = evt.get("timestamp")
        tls_ver = (evt.get("tls") or {}).get("version", "UNKNOWN")

        # In 1 dòng gọn cho mỗi anomaly
        ae_err = result.get("ae_error")
        iso_score = result.get("iso_score", None)

        msg = (
            f"[RT][ANOMALY] {ts} {src}:{sport} -> {dst}:{dport} "
            f"TLS={tls_ver} | ae_err={ae_err:.6f}"
        )
        if iso_score is not None:
            msg += f", iso_score={iso_score:.6f}"

        print(msg)

        # >>> Gửi lên Backend <<<
        payload = build_backend_payload(evt, features, result)
        send_event_to_backend(payload)


if __name__ == "__main__":
    main()
