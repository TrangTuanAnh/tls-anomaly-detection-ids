# python-real-time-service/main.py
from __future__ import annotations

import os
import sys
import time
import json
import hmac
import hashlib
import secrets
import threading
import queue
from typing import Optional, Dict, Any, List, Union

import numpy as np
import joblib
import requests
import pandas as pd
from tensorflow.keras.models import load_model

from fastapi import FastAPI, Body, HTTPException
import uvicorn

from config import (
    FLOW_CSV_PATH,
    BACKEND_URL,
    MLP_THRESHOLD,
    ISO_THRESHOLD,
    REQUIRE_INGEST_HMAC,
    INGEST_HMAC_SECRET,
    INGEST_HMAC_MAX_AGE_SEC,
    MLP_MODEL_SHA256,
    SCALER_SHA256,
    INGEST_MODE,
    LISTEN_HOST,
    LISTEN_PORT,
)
from log_utils import follow_csv
from feature_extractor import FEATURES, build_feature_vector, extract_flow_meta


app = FastAPI(title="Flow Realtime Service", version="1.1")


class StandardScalerLite:
    """Portable StandardScaler (mean/scale) fallback.

    This avoids pickle/joblib incompatibilities across numpy/sklearn versions.
    """

    def __init__(self, feature_names: List[str], mean_: List[float], scale_: List[float]):
        self.feature_names_in_ = np.array(list(feature_names))
        self.n_features_in_ = int(len(feature_names))
        self.mean_ = np.array(mean_, dtype=np.float64)
        self.scale_ = np.array(scale_, dtype=np.float64)
        if self.mean_.shape[0] != self.n_features_in_ or self.scale_.shape[0] != self.n_features_in_:
            raise ValueError("Scaler params length mismatch")

    def transform(self, X):
        if hasattr(X, "to_numpy"):
            X = X.to_numpy()
        X = np.asarray(X, dtype=np.float64)
        if X.ndim != 2 or X.shape[1] != self.n_features_in_:
            raise ValueError(f"Expected shape (n,{self.n_features_in_}), got {X.shape}")
        denom = np.where(self.scale_ == 0, 1.0, self.scale_)
        return (X - self.mean_) / denom


def _load_scaler_with_fallback(scaler_path: str):
    """Try joblib scaler first; fallback to scaler_params.json if present."""
    try:
        return _joblib_load_compat(scaler_path)
    except Exception as e:
        json_path = os.getenv("SCALER_PARAMS_JSON", "")
        if not json_path:
            json_path = os.path.join(os.path.dirname(scaler_path), "scaler_params.json")
        if os.path.isfile(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                params = json.load(f)
            return StandardScalerLite(
                feature_names=params.get("feature_names", FEATURES),
                mean_=params.get("mean_", []),
                scale_=params.get("scale_", []),
            )
        raise e


# -----------------
# Model utilities
# -----------------

def _infer_model_input_dim(model) -> Optional[int]:
    """Best-effort infer model expected input dimension."""
    try:
        shape = getattr(model, "input_shape", None)
        if shape and isinstance(shape, (tuple, list)) and len(shape) >= 2:
            dim = shape[-1]
            return int(dim) if dim is not None else None
    except Exception:
        pass

    try:
        t = model.inputs[0]
        dim = getattr(t, "shape", None)[-1]
        return int(dim) if dim is not None else None
    except Exception:
        return None


def _validate_feature_contract(scaler, model) -> None:
    expected_n = len(FEATURES)

    n_in = getattr(scaler, "n_features_in_", None)
    if n_in is not None and int(n_in) != expected_n:
        raise RuntimeError(
            f"Scaler feature count mismatch: expected={expected_n} got={int(n_in)}. "
            f"Make sure scaler/model are trained on the exact FEATURES list in feature_extractor.py"
        )

    names = getattr(scaler, "feature_names_in_", None)
    if names is not None:
        names = list(names)
        if names != FEATURES:
            raise RuntimeError(
                "Scaler feature_names_in_ do not match required feature order. "
                "Re-train scaler with the same ordered FEATURES list in feature_extractor.py"
            )

    model_dim = _infer_model_input_dim(model)
    if model_dim is not None and int(model_dim) != expected_n:
        raise RuntimeError(
            f"Model input dimension mismatch: expected={expected_n} got={int(model_dim)}. "
            f"Provide an MLP model trained on the exact FEATURES list in feature_extractor.py"
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
    """Load joblib artifacts with a small compatibility shim."""
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
    """Load scaler + MLP classifier (+ optional isolation forest)."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "trained_models")

    scaler_path = os.getenv("SCALER_PATH", "") or os.path.join(models_dir, "scaler.pkl")
    # Backward-compatible env var name: AE_MODEL_PATH
    mlp_path = os.getenv("MLP_MODEL_PATH", os.getenv("AE_MODEL_PATH", "")) or os.path.join(models_dir, "mlp.h5")
    iso_path = os.getenv("ISO_MODEL_PATH", "") or os.path.join(models_dir, "isolation_forest.pkl")

    if not os.path.isfile(scaler_path):
        raise FileNotFoundError(f"Scaler not found: {scaler_path}")
    if not os.path.isfile(mlp_path):
        raise FileNotFoundError(f"MLP model not found: {mlp_path}")

    _check_integrity(mlp_path, MLP_MODEL_SHA256, "MLP model")
    _check_integrity(scaler_path, SCALER_SHA256, "Scaler")

    scaler = _load_scaler_with_fallback(scaler_path)
    mlp_model = load_model(mlp_path, compile=False)

    _validate_feature_contract(scaler, mlp_model)

    iso_model = None
    if os.path.isfile(iso_path):
        iso_model = _joblib_load_compat(iso_path)

    return scaler, mlp_model, iso_model


def predict_anomaly(x: np.ndarray, scaler, mlp_model, iso_model=None) -> Dict[str, Any]:
    """Return anomaly decision and scores.

    Primary detector is an MLP classifier (sigmoid output in [0,1]).
    """
    # If the scaler was fitted with feature names (pandas DataFrame during training),
    # passing a raw ndarray will trigger a warning and makes it easier to accidentally
    # mismatch column order. Convert to a DataFrame with the strict FEATURES order.
    try:
        x_df = pd.DataFrame(x, columns=FEATURES)
        x_scaled = scaler.transform(x_df)
    except Exception:
        # Fallback (should rarely happen)
        x_scaled = scaler.transform(x)

    y_score = float(mlp_model.predict(x_scaled, verbose=0).ravel()[0])
    mlp_anom = y_score >= float(MLP_THRESHOLD)

    iso_score = None
    iso_anom = None
    if iso_model is not None:
        try:
            iso_score = float(iso_model.decision_function(x_scaled)[0])
            iso_anom = iso_score < ISO_THRESHOLD
        except Exception:
            iso_score = None
            iso_anom = None

    anomaly = bool(mlp_anom) or bool(iso_anom) if iso_anom is not None else bool(mlp_anom)

    return {
        "mlp_score": float(y_score),
        "mlp_anom": bool(mlp_anom),
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
        "mlp_score": result.get("mlp_score"),
        "mlp_anom": bool(result.get("mlp_anom", False)),
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
        # Send the exact canonical JSON bytes that were signed.
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        headers = {**headers, "Content-Type": "application/json"}
        resp = requests.post(url, data=body, headers=headers, timeout=1.5)
        if not resp.ok:
            print(f"[RT][WARN] Backend HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"[RT][WARN] Cannot send event to backend: {e}")


# -----------------
# Runtime threads
# -----------------

_Q: Optional["queue.Queue[Dict[str, Any]]"] = None
_SCALER = None
_MLP_MODEL = None
_ISO_MODEL = None


def reader_thread(q: "queue.Queue[Dict[str, Any]]") -> None:
    print(f"[RT] Following CSV: {FLOW_CSV_PATH}")
    for row in follow_csv(FLOW_CSV_PATH):
        try:
            q.put(row, timeout=1.0)
        except Exception:
            pass


def worker_thread(q: "queue.Queue[Dict[str, Any]]", scaler, mlp_model, iso_model) -> None:
    print("[RT] Worker started (feature -> ML -> backend)")
    while True:
        row = q.get()
        try:
            x, feat_dict = build_feature_vector(row)
            result = predict_anomaly(x, scaler, mlp_model, iso_model)
            payload = build_backend_payload(row, feat_dict, result)
            send_event_to_backend(payload)
        except Exception as e:
            print(f"[RT][WARN] Failed to process flow: {e}")
        finally:
            q.task_done()


def bootstrap_runtime() -> None:
    global _Q, _SCALER, _MLP_MODEL, _ISO_MODEL

    if _Q is not None:
        return

    print("[RT] Flow-based anomaly detection service starting...")
    print(f"[RT] BACKEND_URL = {BACKEND_URL}")
    print(f"[RT] INGEST_MODE = {INGEST_MODE}")

    _SCALER, _MLP_MODEL, _ISO_MODEL = load_models()
    _Q = queue.Queue(maxsize=int(os.getenv("QUEUE_MAXSIZE", "5000")))

    t_worker = threading.Thread(target=worker_thread, args=(_Q, _SCALER, _MLP_MODEL, _ISO_MODEL), daemon=True)
    t_worker.start()

    if INGEST_MODE in {"csv", "both"}:
        t_reader = threading.Thread(target=reader_thread, args=(_Q,), daemon=True)
        t_reader.start()


def _enqueue(flow: Dict[str, Any]) -> bool:
    if _Q is None:
        return False
    try:
        _Q.put_nowait(flow)
        return True
    except queue.Full:
        return False


# -----------------
# HTTP API (url/both mode)
# -----------------


@app.get("/health")
def health():
    return {
        "status": "ok",
        "ingest_mode": INGEST_MODE,
        "queue_size": _Q.qsize() if _Q is not None else None,
    }


@app.post("/flow")
def ingest_flow(payload: Union[Dict[str, Any], List[Dict[str, Any]]] = Body(...)):
    """Receive CICFlowMeter flows in realtime (recommended).

    cicflowmeter --url mode will POST a JSON object (a dict) per collected flow.
    We also accept a list of flows for flexibility.
    """
    if _Q is None:
        raise HTTPException(status_code=503, detail="service not ready")

    items: List[Dict[str, Any]]
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        items = [payload]
    else:
        raise HTTPException(status_code=400, detail="invalid payload")

    accepted = 0
    dropped = 0
    for it in items:
        if not isinstance(it, dict):
            dropped += 1
            continue
        if _enqueue(it):
            accepted += 1
        else:
            dropped += 1

    return {"ok": True, "accepted": accepted, "dropped": dropped}


def main():
    bootstrap_runtime()

    if INGEST_MODE == "csv":
        # Legacy mode: keep process alive; reader thread does the ingest.
        while True:
            time.sleep(5)

    # URL / BOTH mode: expose HTTP endpoint for realtime ingest.
    print(f"[RT] HTTP listening on {LISTEN_HOST}:{LISTEN_PORT} (/flow)")
    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT, log_level=os.getenv("LOG_LEVEL", "info"))


if __name__ == "__main__":
    main()
