from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Any, List
import re
import math

import numpy as np
from dateutil import parser as dtparser

# Su dung Regex de chuan hoa cac khoang trang trong ten cot du lieu
_ws_re = re.compile(r"\s+")

"""
Module trich xuat dac trung tu du lieu CICFlowMeter
Module nay dam bao du lieu dau vao luon khop voi cau truc mo hinh AI da huan luyen
"""

# Danh sach co dinh 34 dac trung mang theo dung thu tu dau vao cua mo hinh ML
# Bat ky su thay doi nao ve thu tu cung se lam sai lech ket qua du doan
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

# Danh sach cac ten goi khac nhau cua cung mot dac trung
# Giup he thong tuong thich voi nhieu phien ban cong cu sniffer khac nhau
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

# Ham chuan hoa ten khoa (key) de loai bo khoang trang thua
def _norm_key(k: str) -> str:
    k = (k or "").strip()
    k = _ws_re.sub(" ", k)
    return k

def normalize_row_keys(row: Dict[str, Any]) -> Dict[str, Any]:
    return {_norm_key(k): v for k, v in row.items()}

# Ham chuyen doi du lieu sang so thuc va xu ly cac gia tri loi (NaN, Infinity)
# Dam bao mo hinh AI khong bi loi khi gap du lieu mang bat thuong
def _to_float(x: Any) -> float:
    if x is None:
        return 0.0
    if isinstance(x, (int, float)):
        if isinstance(x, float) and (math.isinf(x) or math.isnan(x)):
            return 0.0
        return float(x)
    s = str(x).strip()
    if not s or s.lower() in {"inf", "infinity", "+inf", "-inf", "nan"}:
        return 0.0
    try:
        v = float(s)
        return 0.0 if math.isinf(v) or math.isnan(v) else v
    except Exception:
        return 0.0

# Cau truc du lieu de luu tru thong tin dinh danh cua mot luong du lieu (Flow)
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

# Ham tim kiem gia tri trong hang du lieu dua tren danh sach cac ten cot kha thi
def _pick(row: Dict[str, Any], keys: List[str]) -> Optional[str]:
    row_l = {str(k).lower(): v for k, v in row.items()}
    for k in keys:
        kk = _norm_key(k)
        if kk in row and str(row[kk]).strip() != "":
            return str(row[kk]).strip()
        v = row_l.get(kk.lower())
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return None

# Trich xuat thong tin metadata nhu IP, Port, thoi gian de phuc vu truy vet
def extract_flow_meta(row_in: Dict[str, Any], sensor_name: Optional[str] = None) -> FlowMeta:
    row = normalize_row_keys(row_in)
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

    src_ip = _pick(row, ["Source IP", "Src IP", "src_ip", "src"]) or "0.0.0.0"
    dst_ip = _pick(row, ["Destination IP", "Dst IP", "dest_ip", "dst"]) or "0.0.0.0"

    src_port_s = _pick(row, ["Source Port", "Src Port", "src_port"])
    dst_port_s = _pick(row, ["Destination Port", "Dst Port", "dest_port"])

    def to_int_port(s: Optional[str]) -> Optional[int]:
        try: return int(float(s)) if s else None
        except Exception: return None

    return FlowMeta(
        event_time=event_time,
        sensor_name=sensor_name,
        flow_id=None,
        src_ip=src_ip,
        src_port=to_int_port(src_port_s),
        dst_ip=dst_ip,
        dst_port=to_int_port(dst_port_s),
        proto=_pick(row, ["Protocol", "proto"]),
    )

# Chuyen doi mot hang du lieu thich ung sang dung 34 dac trung yeu cau
def build_feature_dict(row_in: Dict[str, Any]) -> Dict[str, float]:
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

# Chuyen doi du lieu sang dang Vector (NumPy array) de dua vao mo hinh Machine Learning
def build_feature_vector(row_in: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, float]]:
    feat_dict = build_feature_dict(row_in)
    vec = np.array([feat_dict[f] for f in FEATURES], dtype=np.float32).reshape(1, -1)
    return vec, feat_dict