# python-real-time-service/feature_extractor.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Any, List
import re
import math

import numpy as np
from dateutil import parser as dtparser

_ws_re = re.compile(r"\s+")


# NOTE:
# dataset_filter.py says "39 features" but the actual list currently has 43 items.
# We follow the list content as the source of truth.
FEATURES: List[str] = [
    # Flow & volume
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",

    # Packet length (forward)
    "Fwd Packet Length Min",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",

    # Packet length (backward)
    "Bwd Packet Length Min",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",

    # Packet length (global)
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",

    # Timing (IAT)
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",

    # Direction
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Down/Up Ratio",

    # TCP flags (core)
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
]


def _norm_key(k: str) -> str:
    k = (k or "").strip()
    k = _ws_re.sub(" ", k)
    return k


def normalize_row_keys(row: Dict[str, Any]) -> Dict[str, Any]:
    return {_norm_key(k): v for k, v in row.items()}


def _to_float(x: Any) -> float:
    if x is None:
        return 0.0
    if isinstance(x, (int, float)):
        if isinstance(x, float) and (math.isinf(x) or math.isnan(x)):
            return 0.0
        return float(x)
    s = str(x).strip()
    if not s:
        return 0.0
    # some CICFlowMeter outputs use 'Infinity'
    if s.lower() in {"inf", "infinity", "+inf", "-inf", "nan"}:
        return 0.0
    try:
        v = float(s)
        if math.isinf(v) or math.isnan(v):
            return 0.0
        return v
    except Exception:
        return 0.0


@dataclass
class FlowMeta:
    event_time: datetime
    sensor_name: Optional[str]
    flow_id: Optional[int]
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    proto: Optional[str]


def _pick(row: Dict[str, Any], keys: List[str]) -> Optional[str]:
    for k in keys:
        if k in row and str(row[k]).strip() != "":
            return str(row[k]).strip()
    return None


def extract_flow_meta(row_in: Dict[str, Any], sensor_name: Optional[str] = None) -> FlowMeta:
    row = normalize_row_keys(row_in)

    # CICFlowMeter / cicflowmeter commonly outputs these columns
    ts = _pick(row, ["Timestamp", "Flow Start Time", "Start Time", "time", "Time"])
    if ts:
        try:
            event_time = dtparser.parse(ts)
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
        except Exception:
            event_time = datetime.now(timezone.utc)
    else:
        event_time = datetime.now(timezone.utc)

    flow_id_s = _pick(row, ["Flow ID", "flow_id", "FlowId", "FlowID"])
    flow_id = None
    if flow_id_s:
        try:
            flow_id = int(float(flow_id_s))
        except Exception:
            flow_id = None

    src_ip = _pick(row, ["Source IP", "Src IP", "src_ip", "src"])
    dst_ip = _pick(row, ["Destination IP", "Dst IP", "dest_ip", "dst"])

    if not src_ip:
        src_ip = "0.0.0.0"
    if not dst_ip:
        dst_ip = "0.0.0.0"

    src_port_s = _pick(row, ["Source Port", "Src Port", "src_port"])
    dst_port_s = _pick(row, ["Destination Port", "Dst Port", "dest_port"])

    def to_int_port(s: Optional[str]) -> Optional[int]:
        if not s:
            return None
        try:
            return int(float(s))
        except Exception:
            return None

    src_port = to_int_port(src_port_s)
    dst_port = to_int_port(dst_port_s)

    proto = _pick(row, ["Protocol", "proto"])

    return FlowMeta(
        event_time=event_time,
        sensor_name=sensor_name,
        flow_id=flow_id,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
    )


def build_feature_dict(row_in: Dict[str, Any]) -> Dict[str, float]:
    """Extract the exact feature set used for training from one CICFlowMeter CSV row."""
    row = normalize_row_keys(row_in)
    out: Dict[str, float] = {}
    for feat in FEATURES:
        out[feat] = _to_float(row.get(feat))
    return out


def build_feature_vector(row_in: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, float]]:
    feat_dict = build_feature_dict(row_in)
    vec = np.array([feat_dict[f] for f in FEATURES], dtype=np.float32).reshape(1, -1)
    return vec, feat_dict
