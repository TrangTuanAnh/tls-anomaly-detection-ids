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


"""Feature extraction for CICFlowMeter(-like) CSV.

This project is **locked** to a strict feature contract (the same columns used in training).
We keep canonical CIC-style names, but tolerate common header variants from different
`cicflowmeter` / CICFlowMeter builds via aliases.
"""

# Strict feature contract (34 features) — MUST match training order
FEATURES: List[str] = [
    "Packet Length Std",
    "Total Length of Bwd Packets",
    "Subflow Bwd Bytes",
    "Destination Port",
    "Packet Length Variance",
    "Bwd Packet Length Mean",
    "Avg Bwd Segment Size",
    "Bwd Packet Length Max",
    "Init_Win_bytes_backward",
    "Total Length of Fwd Packets",
    "Subflow Fwd Bytes",
    "Init_Win_bytes_forward",
    "Average Packet Size",
    "Packet Length Mean",
    "Max Packet Length",
    "Fwd Packet Length Max",
    "Flow IAT Max",
    "Bwd Header Length",
    "Flow Duration",
    "Fwd IAT Max",
    "Fwd Header Length",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Flow IAT Mean",
    "Flow Bytes/s",
    "Bwd Packet Length Std",
    "Subflow Bwd Packets",
    "Total Backward Packets",
    "Fwd Packet Length Mean",
    "Avg Fwd Segment Size",
    "Bwd Packet Length Min",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
]

# Header aliases observed across CICFlowMeter(-like) tools.
# Keys and values are canonical CIC names (same as FEATURES) and acceptable alternates.
FEATURE_ALIASES: Dict[str, List[str]] = {
    "Destination Port": ["Dst Port", "Dest Port"],
    "Total Backward Packets": ["Total Bwd Packets", "Tot Bwd Pkts"],
    "Total Length of Fwd Packets": ["Total Length of Forward Packets", "TotLen Fwd Pkts"],
    "Total Length of Bwd Packets": ["Total Length of Backward Packets", "TotLen Bwd Pkts"],
    "Flow Bytes/s": ["FlowBytes/s"],
    "Flow Packets/s": ["FlowPackets/s"],
    "Fwd Packets/s": ["FwdPackets/s"],
    "Bwd Packets/s": ["BwdPackets/s"],
    "Init_Win_bytes_forward": ["Init Win bytes forward"],
    "Init_Win_bytes_backward": ["Init Win bytes backward"],
}


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
    """Pick first non-empty value among candidate keys.

    Row keys are already whitespace-normalized, but we also do case-insensitive lookup.
    """
    row_l = {str(k).lower(): v for k, v in row.items()}
    for k in keys:
        kk = _norm_key(k)
        if kk in row and str(row[kk]).strip() != "":
            return str(row[kk]).strip()
        v = row_l.get(kk.lower())
        if v is not None and str(v).strip() != "":
            return str(v).strip()
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
    row_l = {str(k).lower(): v for k, v in row.items()}
    out: Dict[str, float] = {}
    for feat in FEATURES:
        candidates = [feat] + FEATURE_ALIASES.get(feat, [])
        raw = None
        for c in candidates:
            ck = _norm_key(c)
            if ck in row and str(row[ck]).strip() != "":
                raw = row[ck]
                break
            v = row_l.get(ck.lower())
            if v is not None and str(v).strip() != "":
                raw = v
                break
        out[feat] = _to_float(raw)
    return out


def build_feature_vector(row_in: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, float]]:
    feat_dict = build_feature_dict(row_in)
    vec = np.array([feat_dict[f] for f in FEATURES], dtype=np.float32).reshape(1, -1)
    return vec, feat_dict
