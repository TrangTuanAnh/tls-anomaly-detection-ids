# python-real-time-service/main.py
from __future__ import annotations
from http_ingest import start_http_ingest

import os
import sys
import time
import json
import hmac
import hashlib
import secrets
import threading
import queue
from typing import Optional, Dict, Any

import numpy as np
import joblib
import requests
from tensorflow.keras.models import load_model

from config import (
    FLOW_CSV_PATH,
    BACKEND_URL,
    AE_THRESHOLD,
    ISO_THRESHOLD,
    REQUIRE_INGEST_HMAC,
    INGEST_HMAC_SECRET,
    INGEST_HMAC_MAX_AGE_SEC,
    AE_MODEL_SHA256,
    SCALER_SHA256,
)
from log_utils import follow_csv
from feature_extractor import FEATURES, build_feature_vector, extract_flow_meta


def _infer_ae_input_dim(ae_model) -> Optional[int]:
    """Best-effort infer autoencoder expected input dimension."""
    try:
        shape = getattr(ae_model, "input_shape", None)
        if shape and isinstance(shape, (tuple, list)) and len(shape) >= 2:
            dim = shape[-1]
            return int(dim) if dim is not None else None
    except Exception:
        pass

    try:
        # Some Keras models expose inputs[...] shapes instead
        t = ae_model.inputs[0]
        dim = getattr(t, "shape", None)[-1]
        return int(dim) if dim is not None else None
    except Exception:
        return None


def _validate_feature_contract(scaler, ae_model) -> None:
    expected_n = len(FEATURES)

    # Scaler dimension checks
    n_in = getattr(scaler, "n_features_in_", None)
    if n_in is not None and int(n_in) != expected_n:
        raise RuntimeError(
            f"Scaler feature count mismatch: expected={expected_n} got={int(n_in)}. "
            f"Make sure scaler/model are trained on the exact FEATURES list in feature_extractor.py"
        )

    # If scaler has feature names, enforce exact order when available
    names = getattr(scaler, "feature_names_in_", None)
    if names is not None:
        names = list(names)
        if names != FEATURES:
            raise RuntimeError(
                "Scaler feature_names_in_ do not match required feature order. "
                "Re-train scaler with the same ordered FEATURES list in feature_extractor.py"
            )

    # Autoencoder input dim checks
    ae_dim = _infer_ae_input_dim(ae_model)
    if ae_dim is not None and int(ae_dim) != expected_n:
        raise RuntimeError(
            f"Autoencoder input dimension mismatch: expected={expected_n} got={int(ae_dim)}. "
            f"Provide an autoencoder trained on the exact FEATURES list in feature_extractor.py"
        )


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_integrity(path: str, expected_sha256: str, label: str) -> None:
    if not expected_sha256:
        return
    got = _sha256_file(path)
    if got.lower() != expected_sha256.lower():
        raise RuntimeError(f"{label} integrity check failed: expected={expected_sha256} got={got}")


def _joblib_load_compat(path: str):
    """Load joblib artifacts with a small compatibility shim.

    Some pickles created with NumPy 2.x reference `numpy._core.*`. If the runtime happens
    to use an older NumPy (1.x), joblib.load can fail with `ModuleNotFoundError: numpy._core`.

    We do a best-effort alias so the same artifact can still be loaded.
    """
    try:
        return joblib.load(path)
    except (ModuleNotFoundError, ImportError) as e:
        msg = str(e)
        if "numpy._core" not in msg:
            raise

        import types
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


def load_models():
    """Load scaler + autoencoder (+ optional isolation forest)."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "trained_models")

    scaler_path = os.getenv("SCALER_PATH", "") or os.path.join(models_dir, "scaler.pkl")
    ae_path = os.getenv("AE_MODEL_PATH", "") or os.path.join(models_dir, "autoencoder.h5")

    iso_path = os.getenv("ISO_MODEL_PATH", "") or os.path.join(models_dir, "isolation_forest.pkl")

    if not os.path.isfile(scaler_path):
        raise FileNotFoundError(f"Scaler not found: {scaler_path}")
    if not os.path.isfile(ae_path):
        raise FileNotFoundError(f"Autoencoder model not found: {ae_path}")

    _check_integrity(ae_path, AE_MODEL_SHA256, "Autoencoder")
    _check_integrity(scaler_path, SCALER_SHA256, "Scaler")

    scaler = _joblib_load_compat(scaler_path)
    ae_model = load_model(ae_path, compile=False)

    # Ensure model + scaler are trained for the exact CICFlowMeter feature contract
    _validate_feature_contract(scaler, ae_model)

    iso_model = None
    if os.path.isfile(iso_path):
        iso_model = _joblib_load_compat(iso_path)

    return scaler, ae_model, iso_model


def predict_anomaly(x: np.ndarray, scaler, ae_model, iso_model=None) -> Dict[str, Any]:
    """Return anomaly decision and scores."""
    x_scaled = scaler.transform(x)

    # AE reconstruction error (MSE per sample)
    recon = ae_model.predict(x_scaled, verbose=0)
    err = np.mean((x_scaled - recon) ** 2, axis=1)[0]
    ae_anom = float(err) > AE_THRESHOLD

    iso_score = None
    iso_anom = None
    if iso_model is not None:
        try:
            # decision_function: higher = more normal (sklearn convention)
            iso_score = float(iso_model.decision_function(x_scaled)[0])
            iso_anom = iso_score < ISO_THRESHOLD
        except Exception:
            iso_score = None
            iso_anom = None

    anomaly = bool(ae_anom) or bool(iso_anom) if iso_anom is not None else bool(ae_anom)

    return {
        "ae_error": float(err),
        "ae_anom": bool(ae_anom),
        "iso_score": iso_score,
        "iso_anom": iso_anom,
        "anomaly": anomaly,
    }


def build_backend_payload(row: Dict[str, Any], feature_dict: Dict[str, float], result: Dict[str, Any]) -> Dict[str, Any]:
    sensor_name = os.getenv("SENSOR_NAME")
    meta = extract_flow_meta(row, sensor_name=sensor_name)

    payload: Dict[str, Any] = {
        "event_time": meta.event_time.isoformat(),
        "sensor_name": meta.sensor_name,
        "flow_id": meta.flow_id,
        "src_ip": meta.src_ip,
        "src_port": meta.src_port,
        "dst_ip": meta.dst_ip,
        "dst_port": meta.dst_port,
        "proto": meta.proto,
        "ae_error": result.get("ae_error"),
        "ae_anom": bool(result.get("ae_anom", False)),
        "iso_score": result.get("iso_score"),
        "iso_anom": result.get("iso_anom"),
        "is_anomaly": bool(result.get("anomaly", False)),
        "features_json": feature_dict,
    }
    return payload


def send_event_to_backend(payload: Dict[str, Any]) -> None:
    if not BACKEND_URL:
        return

    url = BACKEND_URL.rstrip("/") + "/api/events"
    headers: Dict[str, str] = {}

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
    elif REQUIRE_INGEST_HMAC:
        print("[RT][ERROR] REQUIRE_INGEST_HMAC=true but INGEST_HMAC_SECRET is empty")
        return

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=1.5)
        if not resp.ok:
            print(f"[RT][WARN] Backend HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"[RT][WARN] Cannot send event to backend: {e}")


def reader_thread(q: "queue.Queue[Dict[str, Any]]") -> None:
    print(f"[RT] Following CSV: {FLOW_CSV_PATH}")
    for row in follow_csv(FLOW_CSV_PATH):
        try:
            q.put(row, timeout=1.0)
        except Exception:
            pass


def worker_thread(q: "queue.Queue[Dict[str, Any]]", scaler, ae_model, iso_model) -> None:
    print("[RT] Worker started (feature -> ML -> backend)")
    while True:
        row = q.get()
        try:
            x, feat_dict = build_feature_vector(row)
            result = predict_anomaly(x, scaler, ae_model, iso_model)
            payload = build_backend_payload(row, feat_dict, result)
            send_event_to_backend(payload)
        except Exception as e:
            print(f"[RT][WARN] Failed to process row: {e}")
        finally:
            q.task_done()


def main():
    print("[RT] Flow-based anomaly detection service starting...")
    print(f"[RT] BACKEND_URL = {BACKEND_URL}")
    print(f"[RT] FLOW_CSV_PATH = {FLOW_CSV_PATH}")

    scaler, ae_model, iso_model = load_models()

    q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=int(os.getenv("QUEUE_MAXSIZE", "5000")))


    ingest_mode = os.getenv("INGEST_MODE", "csv").lower()  # csv | http
    t_worker = threading.Thread(target=worker_thread, args=(q, scaler, ae_model, iso_model), daemon=True)
    t_worker.start()

    if ingest_mode == "http":
        t_http = threading.Thread(target=start_http_ingest, args=(q,), daemon=True)
        t_http.start()
    else:
        t_reader = threading.Thread(target=reader_thread, args=(q,), daemon=True)
        t_reader.start()


    # keep alive
    while True:
        time.sleep(5)


if __name__ == "__main__":
    main()
