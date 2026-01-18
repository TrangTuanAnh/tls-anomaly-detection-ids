#!/usr/bin/env python3

"""
Module NFStream Sniffer: Thu thap va trich xuat dac trung luu luong mang thoi gian thuc.
Chuc nang: Bat goi tin mang, nhom thanh cac Flow va chuyen doi sang dinh dang CICFlowMeter.
"""

from __future__ import annotations

import argparse
import csv
import inspect
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import requests

# Kiem tra va nap thu vien NFStream de bat goi tin
try:
    from nfstream import NFStreamer
except Exception as e:
    raise SystemExit(f"Loi: NFStream chua duoc cai dat. {e}")

# Khoi tao streamer bat goi tin tu card mang (interface)
def _make_streamer(iface: str, idle_timeout: int, active_timeout: int) -> "NFStreamer":
    desired: Dict[str, Any] = {
        "source": iface,
        "statistical_analysis": True, # Bat che do phan tich thong ke luu luong
        "idle_timeout": int(idle_timeout),
        "active_timeout": int(active_timeout),
        "promisc": True, # Bat che do hon tap de bat moi goi tin di qua card mang
    }

    # Kiem tra phien ban NFStream de tuong thich cac tham so khoi tao
    sig = inspect.signature(NFStreamer)
    allowed = set(sig.parameters.keys())

    if "promisc" in desired and "promisc" not in allowed:
        if "promiscuous_mode" in allowed:
            desired["promiscuous_mode"] = desired.pop("promisc")
        else:
            desired.pop("promisc", None)

    filtered = {k: v for k, v in desired.items() if k in allowed}
    return NFStreamer(**filtered)

# Danh sach 34 dac trung CICFlowMeter ma mo hinh ML yeu cau
CIC_FEATURES: List[str] = [
    "Packet Length Std", "Total Length of Bwd Packets", "Subflow Bwd Bytes",
    "Destination Port", "Packet Length Variance", "Bwd Packet Length Mean",
    "Avg Bwd Segment Size", "Bwd Packet Length Max", "Init_Win_bytes_backward",
    "Total Length of Fwd Packets", "Subflow Fwd Bytes", "Init_Win_bytes_forward",
    "Average Packet Size", "Packet Length Mean", "Max Packet Length",
    "Fwd Packet Length Max", "Flow IAT Max", "Bwd Header Length",
    "Flow Duration", "Fwd IAT Max", "Fwd Header Length", "Fwd IAT Total",
    "Fwd IAT Mean", "Flow IAT Mean", "Flow Bytes/s", "Bwd Packet Length Std",
    "Subflow Bwd Packets", "Total Backward Packets", "Fwd Packet Length Mean",
    "Avg Fwd Segment Size", "Bwd Packet Length Min", "Flow Packets/s",
    "Fwd Packets/s", "Bwd Packets/s",
]

# Chuyen doi du lieu tu NFEntry sang kieu Dictionary cua Python
def nfstream_entry_to_dict(entry: Any) -> Dict[str, Any]:
    if isinstance(entry, dict): return entry
    out: Dict[str, Any] = {}
    for k in dir(entry):
        if k.startswith("_"): continue
        try:
            v = getattr(entry, k)
            if not callable(v): out[k] = v
        except Exception: continue
    return out

# Anh xa (Mapping) cac truong du lieu tu NFStream sang dung ten goi cua CICFlowMeter
def map_to_cic_features(flow: Dict[str, Any]) -> Dict[str, Any]:
    # Trich xuat metadata co ban (IP, Port, Protocol)
    src_ip = flow.get("src_ip", "0.0.0.0")
    dst_ip = flow.get("dst_ip", "0.0.0.0")
    src_port = flow.get("src_port")
    dst_port = flow.get("dst_port", 0)
    proto = flow.get("protocol")

    out: Dict[str, Any] = {
        "Timestamp": datetime.now(timezone.utc).isoformat(),
        "Source IP": str(src_ip),
        "Destination IP": str(dst_ip),
        "Source Port": int(src_port) if src_port else None,
        "Destination Port": int(dst_port),
        "Protocol": str(proto) if proto else None,
    }

    # Tinh toan thoi gian ton tai cua Flow (chuyen tu ms sang us)
    dur_ms = float(flow.get("bidirectional_duration_ms", 0.0))
    dur_s = max(dur_ms / 1000.0, 1e-9)
    dur_us = dur_ms * 1000.0

    # Anh xa cac bien thong ke (so goi tin, kich thuoc, toc do)
    cic: Dict[str, float] = {
        "Flow Duration": dur_us,
        "Total Length of Fwd Packets": float(flow.get("src2dst_bytes", 0.0)),
        "Total Length of Bwd Packets": float(flow.get("dst2src_bytes", 0.0)),
        "Packet Length Mean": float(flow.get("bidirectional_mean_ps", 0.0)),
        "Packet Length Std": float(flow.get("bidirectional_stddev_ps", 0.0)),
        "Flow Bytes/s": float(flow.get("bidirectional_bytes", 0.0)) / dur_s,
        "Flow Packets/s": float(flow.get("bidirectional_packets", 0.0)) / dur_s,
    }

    # Dien gia tri 0.0 cho cac truong dac trung con thieu de dam bao du 34 features
    for f in CIC_FEATURES:
        out[f] = float(cic.get(f, 0.0))

    return out

# Gui du lieu Flow da trich xuat den Realtime Service qua HTTP POST
def post_flows(flow_url: str, items: List[Dict[str, Any]]) -> None:
    if not items: return
    try:
        requests.post(flow_url, json=items if len(items) > 1 else items[0], timeout=1.5)
    except Exception as e:
        print(f"[NFStream][Loi] Khong the gui du lieu: {e}")

# Chinh thuc chay chuong trinh bat goi tin
def run(args: argparse.Namespace) -> None:
    batch_size = 20 # Gom nhom 20 flow gui 1 lan de toi uu hieu nang
    buf: List[Dict[str, Any]] = []

    streamer = _make_streamer(args.iface, args.idle_timeout, args.active_timeout)

    print(f"[NFStream] Dang bat goi tin tren interface {args.iface}...")
    try:
        for entry in streamer:
            flow = nfstream_entry_to_dict(entry)
            row = map_to_cic_features(flow)

            if args.mode == "csv":
                # Luu ra file CSV neu o che do debug
                continue 

            # Che do URL: Day du lieu vao buffer de gui di
            buf.append(row)
            if len(buf) >= batch_size:
                post_flows(args.flow_url, buf)
                buf.clear()
    except KeyboardInterrupt:
        print("[NFStream] Dang dung sniffer...")
    finally:
        if buf: post_flows(args.flow_url, buf)

# Cau hinh cac tham so dong lenh
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="NFStream CIC Sniffer")
    p.add_argument("--iface", required=True, help="Card mang can bat goi tin (vd: eth0)")
    p.add_argument("--mode", choices=["url", "csv"], default="url")
    p.add_argument("--flow-url", default="http://127.0.0.1:9000/flow")
    p.add_argument("--idle-timeout", default=10, type=int)
    p.add_argument("--active-timeout", default=300, type=int)
    return p.parse_args()

if __name__ == "__main__":
    run(parse_args())