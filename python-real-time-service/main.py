# python-real-time-service/main.py
import os
import numpy as np
import joblib
from tensorflow.keras.models import load_model

from config import EVE_PATH, AE_THRESHOLD, ISO_THRESHOLD
from log_utils import follow_file, parse_tls_event
from feature_extractor import build_feature_vector_from_event


def load_models():
    """
    Load scaler + autoencoder (và Isolation Forest nếu có).
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "trained_models")

    scaler_path = os.path.join(models_dir, "scaler_tls.pkl")
    ae_path = os.path.join(models_dir, "autoencoder_tls.h5")
    iso_path = os.path.join(models_dir, "isolation_forest_tls.pkl")

    if not os.path.isfile(scaler_path):
        raise FileNotFoundError(f"Không tìm thấy scaler: {scaler_path}")
    if not os.path.isfile(ae_path):
        raise FileNotFoundError(f"Không tìm thấy autoencoder: {ae_path}")

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


def main():
    # Log khởi động ngắn gọn
    print("[RT] TLS anomaly detection service starting...")
    print(f"[RT] EVE_PATH = {EVE_PATH}")

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

        # Chỉ in log khi BẤT THƯỜNG
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


if __name__ == "__main__":
    main()
