#!/usr/bin/env python3

"""NFStream realtime sniffer that outputs CICFlowMeter-compatible feature payloads.

The python-real-time-service in this repository is trained/locked to CICFlowMeter
feature names (see python-real-time-service/feature_extractor.py). To keep the ML
pipeline stable, we map NFStream flow statistics to the same canonical feature
names.

Output modes:
 - url : POST JSON to FLOW_URL (recommended, low latency)
 - csv : append rows to a CSV file (debug/legacy)

Notes on mapping:
 - We use NFStream statistical features where available.
 - If a field is missing (version differences / protocol differences), we fall
   back to a reasonable approximation or 0.0.
 - Time-related CIC features are expected in microseconds; NFStream typically
   reports milliseconds -> we convert ms to us.
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

try:
    from nfstream import NFStreamer
except Exception as e:  # pragma: no cover
    raise SystemExit(
        "NFStream is required. Make sure the container installed `nfstream` correctly. "
        f"Import error: {e}"
    )


def _make_streamer(iface: str, idle_timeout: int, active_timeout: int) -> "NFStreamer":
    """Create NFStreamer in a version-tolerant way.

    NFStream has changed a few constructor kwargs across versions (e.g. `promisc`).
    To keep this project runnable across environments, we only pass supported
    keyword args.
    """

    # Desired kwargs (we'll filter based on the installed NFStream version)
    desired: Dict[str, Any] = {
        "source": iface,
        "statistical_analysis": True,
        "idle_timeout": int(idle_timeout),
        "active_timeout": int(active_timeout),
        # Some NFStream versions support `promisc`, some use other names, some
        # don't expose it at all. We'll adapt below.
        "promisc": True,
    }

    sig = inspect.signature(NFStreamer)
    allowed = set(sig.parameters.keys())

    # Remap promiscuous flag if needed
    if "promisc" in desired and "promisc" not in allowed:
        if "promiscuous_mode" in allowed:
            desired["promiscuous_mode"] = desired.pop("promisc")
        else:
            desired.pop("promisc", None)

    # Keep only args supported by this NFStream build
    filtered = {k: v for k, v in desired.items() if k in allowed}
    dropped = sorted(set(desired.keys()) - set(filtered.keys()))
    if dropped:
        print(f"[NFStream] NFStreamer: dropped unsupported args: {dropped}")
    print(f"[NFStream] NFStreamer args: {sorted(filtered.keys())}")

    return NFStreamer(**filtered)


# Canonical CIC feature contract (must match python-real-time-service/feature_extractor.py)
CIC_FEATURES: List[str] = [
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


def _to_py(x: Any) -> Any:
    """Convert common numeric-like objects to JSON-friendly Python types."""
    if x is None:
        return None
    try:
        # numpy scalars
        import numpy as np  # type: ignore

        if isinstance(x, (np.integer,)):
            return int(x)
        if isinstance(x, (np.floating,)):
            return float(x)
    except Exception:
        pass
    if isinstance(x, (int, float, str, bool)):
        return x
    try:
        return float(x)
    except Exception:
        return str(x)


def _get(d: Dict[str, Any], *keys: str, default: Any = 0.0) -> Any:
    for k in keys:
        if k in d and d[k] is not None and d[k] != "":
            return d[k]
    return default


def _proto_hdr_len(proto: Optional[int]) -> int:
    # Approximate per-packet header bytes (IPv4).
    # CICFlowMeter counts header lengths; exact values vary with options.
    if proto == 6:  # TCP
        return 40  # 20 IP + 20 TCP (no options)
    if proto == 17:  # UDP
        return 28  # 20 IP + 8 UDP
    return 28


def _ts_from_ms(ms: float) -> str:
    try:
        dt = datetime.fromtimestamp(float(ms) / 1000.0, tz=timezone.utc)
    except Exception:
        dt = datetime.now(timezone.utc)
    return dt.isoformat()


def _safe_div(a: float, b: float) -> float:
    if b == 0.0:
        return 0.0
    return a / b


def nfstream_entry_to_dict(entry: Any) -> Dict[str, Any]:
    """Best-effort convert NFEntry to a plain dict."""
    if isinstance(entry, dict):
        return entry

    for attr in ("to_dict", "as_dict"):
        fn = getattr(entry, attr, None)
        if callable(fn):
            try:
                d = fn()
                if isinstance(d, dict):
                    return d
            except Exception:
                pass

    # NFEntry is a C-extension-like object; vars() often works.
    try:
        d = vars(entry)
        if isinstance(d, dict) and d:
            return d
    except Exception:
        pass

    # Fallback: enumerate known attributes from dir().
    out: Dict[str, Any] = {}
    for k in dir(entry):
        if k.startswith("_"):
            continue
        try:
            v = getattr(entry, k)
        except Exception:
            continue
        if callable(v):
            continue
        out[k] = v
    return out


def map_to_cic_features(flow: Dict[str, Any]) -> Dict[str, Any]:
    """Map NFStream flow dict -> CICFlowMeter-compatible dict."""

    # --- meta ---
    src_ip = _get(flow, "src_ip", "src", "source_ip", default="0.0.0.0")
    dst_ip = _get(flow, "dst_ip", "dst", "destination_ip", default="0.0.0.0")
    src_port = _get(flow, "src_port", "sport", "source_port", default=None)
    dst_port = _get(flow, "dst_port", "dport", "destination_port", default=None)

    proto_raw = _get(flow, "protocol", "proto", default=None)
    try:
        proto = int(proto_raw) if proto_raw is not None else None
    except Exception:
        proto = None

    # Use last_seen when possible.
    ts_ms = _get(
        flow,
        "bidirectional_last_seen_ms",
        "bidirectional_first_seen_ms",
        "first_seen_ms",
        "last_seen_ms",
        default=float(time.time() * 1000.0),
    )

    out: Dict[str, Any] = {
        "Timestamp": _ts_from_ms(float(ts_ms)),
        "Source IP": str(src_ip),
        "Destination IP": str(dst_ip),
        "Source Port": int(float(src_port)) if src_port is not None else None,
        "Destination Port": int(float(dst_port)) if dst_port is not None else 0,
        "Protocol": str(proto) if proto is not None else None,
    }

    # --- base counters ---
    total_pkts = float(_get(flow, "bidirectional_packets", "packets", default=0.0))
    total_bytes = float(_get(flow, "bidirectional_bytes", "bytes", default=0.0))
    fwd_pkts = float(_get(flow, "src2dst_packets", "forward_packets", default=0.0))
    bwd_pkts = float(_get(flow, "dst2src_packets", "backward_packets", default=0.0))
    fwd_bytes = float(_get(flow, "src2dst_bytes", "forward_bytes", default=0.0))
    bwd_bytes = float(_get(flow, "dst2src_bytes", "backward_bytes", default=0.0))

    dur_ms = float(
        _get(
            flow,
            "bidirectional_duration_ms",
            "bidirectional_duration",
            "duration_ms",
            default=0.0,
        )
    )
    dur_s = max(dur_ms / 1000.0, 1e-9)
    dur_us = dur_ms * 1000.0

    # --- packet size stats ---
    bid_mean_ps = float(_get(flow, "bidirectional_mean_ps", "bidirectional_mean_packet_size", default=0.0))
    bid_std_ps = float(_get(flow, "bidirectional_stddev_ps", "bidirectional_std_ps", default=0.0))
    bid_max_ps = float(_get(flow, "bidirectional_max_ps", "bidirectional_max_packet_size", default=0.0))

    fwd_mean_ps = float(_get(flow, "src2dst_mean_ps", "src2dst_mean_packet_size", default=0.0))
    fwd_max_ps = float(_get(flow, "src2dst_max_ps", "src2dst_max_packet_size", default=0.0))

    bwd_mean_ps = float(_get(flow, "dst2src_mean_ps", "dst2src_mean_packet_size", default=0.0))
    bwd_max_ps = float(_get(flow, "dst2src_max_ps", "dst2src_max_packet_size", default=0.0))
    bwd_std_ps = float(_get(flow, "dst2src_stddev_ps", "dst2src_std_ps", default=0.0))
    bwd_min_ps = float(_get(flow, "dst2src_min_ps", "dst2src_min_packet_size", default=0.0))

    if bid_mean_ps == 0.0 and total_pkts > 0.0:
        bid_mean_ps = _safe_div(total_bytes, total_pkts)
    avg_pkt_size = _safe_div(total_bytes, total_pkts) if total_pkts > 0.0 else 0.0

    # --- inter-arrival stats (ms -> us) ---
    bid_mean_piat_ms = float(_get(flow, "bidirectional_mean_piat_ms", "bidirectional_mean_piat", default=0.0))
    bid_max_piat_ms = float(_get(flow, "bidirectional_max_piat_ms", "bidirectional_max_piat", default=0.0))
    fwd_mean_piat_ms = float(_get(flow, "src2dst_mean_piat_ms", "src2dst_mean_piat", default=0.0))
    fwd_max_piat_ms = float(_get(flow, "src2dst_max_piat_ms", "src2dst_max_piat", default=0.0))

    # fallbacks if NFStream build doesn't expose PIAT
    if bid_mean_piat_ms == 0.0 and total_pkts > 1.0 and dur_ms > 0.0:
        bid_mean_piat_ms = _safe_div(dur_ms, (total_pkts - 1.0))
    if bid_max_piat_ms == 0.0:
        bid_max_piat_ms = bid_mean_piat_ms

    if fwd_mean_piat_ms == 0.0 and fwd_pkts > 1.0 and dur_ms > 0.0:
        fwd_mean_piat_ms = _safe_div(dur_ms, (fwd_pkts - 1.0))
    if fwd_max_piat_ms == 0.0:
        fwd_max_piat_ms = fwd_mean_piat_ms

    # --- header lengths (approx) ---
    hdr_len = _proto_hdr_len(proto)
    fwd_hdr_len = fwd_pkts * float(hdr_len)
    bwd_hdr_len = bwd_pkts * float(hdr_len)

    # --- TCP init window (best-effort) ---
    init_fwd = float(
        _get(
            flow,
            "src2dst_init_window_size",
            "src2dst_init_window_bytes",
            "src2dst_tcp_init_window_size",
            "src2dst_init_win_bytes",
            default=0.0,
        )
    )
    init_bwd = float(
        _get(
            flow,
            "dst2src_init_window_size",
            "dst2src_init_window_bytes",
            "dst2src_tcp_init_window_size",
            "dst2src_init_win_bytes",
            default=0.0,
        )
    )

    # --- build CIC features ---
    cic: Dict[str, float] = {}
    cic["Packet Length Std"] = bid_std_ps
    cic["Packet Length Variance"] = bid_std_ps ** 2
    cic["Packet Length Mean"] = bid_mean_ps
    cic["Average Packet Size"] = avg_pkt_size
    cic["Max Packet Length"] = bid_max_ps

    cic["Total Length of Fwd Packets"] = fwd_bytes
    cic["Total Length of Bwd Packets"] = bwd_bytes

    # Subflow features: use total-by-direction as a stable proxy
    cic["Subflow Fwd Bytes"] = fwd_bytes
    cic["Subflow Bwd Bytes"] = bwd_bytes

    cic["Total Backward Packets"] = bwd_pkts
    cic["Subflow Bwd Packets"] = bwd_pkts

    cic["Fwd Packet Length Max"] = fwd_max_ps
    cic["Fwd Packet Length Mean"] = fwd_mean_ps
    cic["Avg Fwd Segment Size"] = fwd_mean_ps

    cic["Bwd Packet Length Max"] = bwd_max_ps
    cic["Bwd Packet Length Mean"] = bwd_mean_ps
    cic["Avg Bwd Segment Size"] = bwd_mean_ps
    cic["Bwd Packet Length Std"] = bwd_std_ps
    cic["Bwd Packet Length Min"] = bwd_min_ps

    cic["Flow Duration"] = dur_us

    # IAT in microseconds
    cic["Flow IAT Mean"] = bid_mean_piat_ms * 1000.0
    cic["Flow IAT Max"] = bid_max_piat_ms * 1000.0
    cic["Fwd IAT Mean"] = fwd_mean_piat_ms * 1000.0
    cic["Fwd IAT Max"] = fwd_max_piat_ms * 1000.0
    cic["Fwd IAT Total"] = (fwd_mean_piat_ms * max(fwd_pkts - 1.0, 0.0)) * 1000.0

    cic["Fwd Header Length"] = fwd_hdr_len
    cic["Bwd Header Length"] = bwd_hdr_len

    cic["Init_Win_bytes_forward"] = init_fwd
    cic["Init_Win_bytes_backward"] = init_bwd

    cic["Flow Bytes/s"] = _safe_div(total_bytes, dur_s)
    cic["Flow Packets/s"] = _safe_div(total_pkts, dur_s)
    cic["Fwd Packets/s"] = _safe_div(fwd_pkts, dur_s)
    cic["Bwd Packets/s"] = _safe_div(bwd_pkts, dur_s)

    # Ensure every required CIC feature exists (0.0 if missing)
    for f in CIC_FEATURES:
        out[f] = float(cic.get(f, 0.0))

    return out


def post_flows(flow_url: str, items: List[Dict[str, Any]], timeout: float = 1.5) -> None:
    if not items:
        return
    try:
        resp = requests.post(flow_url, json=items if len(items) > 1 else items[0], timeout=timeout)
        if not resp.ok:
            print(f"[NFStream][WARN] HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"[NFStream][WARN] Cannot post flows: {e}")


def write_csv(csv_path: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    # Keep deterministic header: meta fields + CIC features
    fieldnames = [
        "Timestamp",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Protocol",
    ] + CIC_FEATURES

    new_file = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        if new_file:
            w.writeheader()
        for r in rows:
            w.writerow({k: _to_py(r.get(k)) for k in fieldnames})
        f.flush()


def run(args: argparse.Namespace) -> None:
    # Buffer to batch POSTs (reduces overhead, improves stability)
    batch_size = int(os.getenv("BATCH_SIZE", "20"))
    flush_interval = float(os.getenv("FLUSH_INTERVAL", "1.0"))
    # Optional debug logging: print a sample every N flows posted (0 disables)
    debug_every = int(os.getenv("DEBUG_EVERY", "0"))
    sent_total = 0
    next_debug_at = debug_every if debug_every > 0 else None
    last_flush = time.time()
    buf: List[Dict[str, Any]] = []

    streamer = _make_streamer(
        iface=args.iface,
        idle_timeout=int(args.idle_timeout),
        active_timeout=int(args.active_timeout),
    )

    print("[NFStream] Streaming... (Ctrl+C to stop)")
    try:
        for entry in streamer:
            flow = nfstream_entry_to_dict(entry)
            row = map_to_cic_features(flow)

            if args.mode == "csv":
                write_csv(args.csv_path, [row])
                continue

            # url mode
            buf.append(row)
            now = time.time()
            if len(buf) >= batch_size or (now - last_flush) >= flush_interval:
                sample = buf[0] if buf else None
                post_flows(args.flow_url, buf)
                sent_total += len(buf)
                if debug_every > 0 and sample is not None:
                    while next_debug_at is not None and sent_total >= next_debug_at:
                        print(
                            "[NFStream][DEBUG] posted_flows=%d sample=%s:%s -> %s:%s proto=%s dur_us=%.0f bytes_per_s=%.2f pkts_per_s=%.2f"
                            % (
                                sent_total,
                                sample.get("Source IP"),
                                sample.get("Source Port"),
                                sample.get("Destination IP"),
                                sample.get("Destination Port"),
                                sample.get("Protocol"),
                                float(sample.get("Flow Duration", 0.0)),
                                float(sample.get("Flow Bytes/s", 0.0)),
                                float(sample.get("Flow Packets/s", 0.0)),
                            )
                        )
                        next_debug_at += debug_every
                buf.clear()
                last_flush = now
    except KeyboardInterrupt:
        print("[NFStream] Stopping...")
    finally:
        if args.mode == "url" and buf:
            post_flows(args.flow_url, buf)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="NFStream CIC-compatible sniffer")
    p.add_argument("--iface", required=True, help="capture interface, e.g. eth0")
    p.add_argument("--mode", choices=["url", "csv"], default="url")
    p.add_argument("--flow-url", dest="flow_url", default="http://127.0.0.1:9000/flow")
    p.add_argument("--csv-path", dest="csv_path", default="/shared/flows/flows.csv")
    p.add_argument("--idle-timeout", dest="idle_timeout", default=10, type=int)
    p.add_argument("--active-timeout", dest="active_timeout", default=300, type=int)
    return p.parse_args()


if __name__ == "__main__":
    run(parse_args())
