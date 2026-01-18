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

# Lop StandardScalerLite: Chuan hoa du lieu dau vao (Mean/Scale)
# Giup mo hinh AI hoat dong on dinh tren nhieu phien ban thu vien khac nhau
class StandardScalerLite:
    def __init__(self, feature_names: List[str], mean_: List[float], scale_: List[float]):
        self.feature_names_in_ = np.array(list(feature_names))
        self.n_features_in_ = int(len(feature_names))
        self.mean_ = np.array(mean_, dtype=np.float64)
        self.scale_ = np.array(scale_, dtype=np.float64)

    def transform(self, X):
        if hasattr(X, "to_numpy"):
            X = X.to_numpy()
        X = np.asarray(X, dtype=np.float64)
        denom = np.where(self.scale_ == 0, 1.0, self.scale_)
        return (X - self.mean_) / denom

# Ham kiem tra tinh toan ven (Integrity) cua file mo hinh bang SHA256
def _check_integrity(path: str, expected_sha256: str, label: str) -> None:
    if not expected_sha256: return
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    got = h.hexdigest()
    if got.lower() != expected_sha256.lower():
        raise RuntimeError(f"Loi bao mat: File {label} da bi thay doi!")

# Tai cac mo hinh da huan luyen (Scaler, MLP, Isolation Forest) vao bo nho
def load_models():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "trained_models")

    scaler_path = os.path.join(models_dir, "scaler.pkl")
    mlp_path = os.path.join(models_dir, "mlp.h5")
    
    _check_integrity(mlp_path, MLP_MODEL_SHA256, "MLP model")
    _check_integrity(scaler_path, SCALER_SHA256, "Scaler")

    scaler = joblib.load(scaler_path)
    mlp_model = load_model(mlp_path, compile=False)
    
    # Isolation Forest (Optional): Mo hinh phat hien bat thuong khong giam sat
    iso_path = os.path.join(models_dir, "isolation_forest.pkl")
    iso_model = joblib.load(iso_path) if os.path.isfile(iso_path) else None

    return scaler, mlp_model, iso_model

# Ham du doan bat thuong dua tren Vector dac trung mang da trich xuat
def predict_anomaly(x: np.ndarray, scaler, mlp_model, iso_model=None) -> Dict[str, Any]:
    # 1. Chuan hoa du lieu bang Scaler
    x_scaled = scaler.transform(pd.DataFrame(x, columns=FEATURES))

    # 2. Su dung mo hinh MLP de phan loai (Sigmoid 0-1)
    y_score = float(mlp_model.predict(x_scaled, verbose=0).ravel()[0])
    mlp_anom = y_score >= float(MLP_THRESHOLD)

    # 3. Ket hop voi mo hinh Isolation Forest (neu co)
    iso_score, iso_anom = None, None
    if iso_model:
        iso_score = float(iso_model.decision_function(x_scaled)[0])
        iso_anom = iso_score < ISO_THRESHOLD

    anomaly = bool(mlp_anom) or (bool(iso_anom) if iso_anom is not None else False)

    return {
        "mlp_score": y_score,
        "mlp_anom": mlp_anom,
        "iso_score": iso_score,
        "iso_anom": iso_anom,
        "anomaly": anomaly,
    }


def build_backend_payload(
    flow_row: Dict[str, Any],
    features_json: Dict[str, float],
    result: Dict[str, Any],
) -> Dict[str, Any]:
    """Build payload that matches backend FlowEventIn (extra fields are forbidden).

    Backend schema expects:
      event_time, sensor_name, flow_id, src_ip, src_port, dst_ip, dst_port, proto,
      features_json, mlp_score, mlp_anom, iso_score, iso_anom, is_anomaly, verdict
    """
    sensor_name = os.getenv("SENSOR_NAME")

    meta = extract_flow_meta(flow_row, sensor_name=sensor_name)
    is_anom = bool(result.get("anomaly"))

    return {
        "event_time": meta.event_time.isoformat(),
        "sensor_name": meta.sensor_name,
        "flow_id": meta.flow_id,
        "src_ip": meta.src_ip,
        "src_port": meta.src_port,
        "dst_ip": meta.dst_ip,
        "dst_port": meta.dst_port,
        "proto": meta.proto,
        "features_json": features_json,
        "mlp_score": result.get("mlp_score"),
        "mlp_anom": result.get("mlp_anom"),
        "iso_score": result.get("iso_score"),
        "iso_anom": result.get("iso_anom"),
        "is_anomaly": is_anom,
        "verdict": "anomaly" if is_anom else "normal",
    }

# Gui ket qua phan tich ve Backend thong qua HTTP POST kem chu ky HMAC
def send_event_to_backend(payload: Dict[str, Any]) -> None:
    if not BACKEND_URL: return
    url = BACKEND_URL.rstrip("/") + "/api/events"
    headers = {"Content-Type": "application/json"}

    # Ky ten du lieu bang HMAC de Backend xac thuc nguon goc (chong gia mao)
    if INGEST_HMAC_SECRET:
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        # Must match backend canonical JSON (sort_keys + compact separators + utf-8, and allow non-ascii)
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        mac = hmac.new(INGEST_HMAC_SECRET.encode("utf-8"), digestmod=hashlib.sha256)
        mac.update(ts.encode("utf-8") + b"." + nonce.encode("utf-8") + b"." + body)
        headers.update({"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": mac.hexdigest()})

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=2.5)
        if resp.status_code >= 300:
            # Print backend error so it's visible in flow-rt logs
            msg = resp.text
            if len(msg) > 500:
                msg = msg[:500] + "..."
            print(f"[RT][Backend] HTTP {resp.status_code}: {msg}")
    except Exception as e:
        print(f"[RT][Loi] Khong the gui ket qua ve Backend: {e}")

# Luu luong xu ly: Lay du lieu tu Queue -> ML Predict -> Backend
def worker_thread(q: queue.Queue, scaler, mlp_model, iso_model):
    while True:
        row = q.get()
        try:
            x, feat_dict = build_feature_vector(row)
            result = predict_anomaly(x, scaler, mlp_model, iso_model)
            payload = build_backend_payload(row, feat_dict, result)
            send_event_to_backend(payload)
        except Exception as e:
            print(f"[RT][Warn] Loi xu ly luong mang: {e}")
        finally:
            q.task_done()

# Khoi tao cac luong (Thread) chay ngam de xu ly du lieu song song
def bootstrap_runtime():
    global _Q, _SCALER, _MLP_MODEL, _ISO_MODEL
    _SCALER, _MLP_MODEL, _ISO_MODEL = load_models()
    _Q = queue.Queue(maxsize=5000)

    # Thread xu ly phan tich chinh
    threading.Thread(target=worker_thread, args=(_Q, _SCALER, _MLP_MODEL, _ISO_MODEL), daemon=True).start()

    # Thread doc file CSV neu o che do ingest truyen thong
    if INGEST_MODE in {"csv", "both"}:
        threading.Thread(target=lambda: [(_Q.put(r) if _Q else None) for r in follow_csv(FLOW_CSV_PATH)], daemon=True).start()

# API Endpoint de nhan du lieu luu luong mang thoi gian thuc tu Sniffer
@app.post("/flow")
def ingest_flow(payload: Union[Dict[str, Any], List[Dict[str, Any]]] = Body(...)):
    if _Q is None: raise HTTPException(status_code=503, detail="Dich vu chua san sang")
    items = payload if isinstance(payload, list) else [payload]
    for it in items:
        try: _Q.put_nowait(it)
        except queue.Full: return {"ok": False, "detail": "Hang doi bi day"}
    return {"ok": True, "accepted": len(items)}

def main():
    bootstrap_runtime()
    # Khoi chay Web Server de nhan du lieu qua HTTP
    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT)

if __name__ == "__main__":
    main()