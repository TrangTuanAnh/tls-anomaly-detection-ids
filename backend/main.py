"""
Backend he thong phat hien xam nhap IDS dua tren luu luong mang
Su dung FastAPI de tiep nhan du lieu tu Sensor va luu tru vao MySQL
"""

from __future__ import annotations

import os
import time
import hmac
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Header, Depends, Query
from pydantic import BaseModel, Field, ConfigDict

from sqlalchemy import (
    create_engine,
    Column,
    BigInteger,
    Integer,
    String,
    DateTime,
    Boolean,
    Float,
    JSON,
    Text,
    func,
    UniqueConstraint,
)
from sqlalchemy.orm import sessionmaker, declarative_base

# Danh sach 34 dac trung mang trich xuat tu CICFlowMeter
# Bat buoc dung thu tu nay de trung khop voi mo hinh AI da huan luyen
FEATURE_NAMES: List[str] = [
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

# Ham xu ly so thuc de loai bo cac gia tri loi nhu vo cung hoac rong
def _coerce_float(v: Any) -> float:
    try:
        if v is None:
            return 0.0
        f = float(v)
        if f != f or f in (float("inf"), float("-inf")):
            return 0.0
        return f
    except Exception:
        return 0.0

# Ham chuan hoa du lieu dau vao de dam bao day du cac dac trung mang
def clean_features(features_in: Optional[Dict[str, Any]]) -> Dict[str, float]:
    src = features_in or {}
    out: Dict[str, float] = {}
    for k in FEATURE_NAMES:
        out[k] = _coerce_float(src.get(k))
    return out

# Doc cau hinh tu bien moi truong cho Database va Bao mat
DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", os.getenv("MYSQL_DATABASE", "tls_ids"))
DB_USER = os.getenv("DB_USER", os.getenv("MYSQL_USER", "tls_user"))
DB_PASSWORD = os.getenv("DB_PASSWORD", os.getenv("MYSQL_PASSWORD", ""))

REQUIRE_INGEST_HMAC = os.getenv("REQUIRE_INGEST_HMAC", "false").lower() == "true"
INGEST_HMAC_SECRET = os.getenv("INGEST_HMAC_SECRET", "")
INGEST_HMAC_MAX_AGE_SEC = int(os.getenv("INGEST_HMAC_MAX_AGE_SEC", "120"))
NONCE_TTL_SEC = int(os.getenv("NONCE_TTL_SEC", "300"))

AUTO_BLOCK = os.getenv("AUTO_BLOCK", "false").lower() == "true"
AUTO_BLOCK_ACTION = os.getenv("AUTO_BLOCK_ACTION", "BLOCK")

# Khoi tao ket noi den co so du lieu MySQL
dsn = f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(dsn, pool_pre_ping=True, pool_recycle=3600)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Bang flow_events: Luu tru thong tin goi tin va ket qua phan loai AI
class FlowEvent(Base):
    __tablename__ = "flow_events"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)
    event_time = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    sensor_name = Column(String(64))
    flow_id = Column(BigInteger)
    src_ip = Column(String(45), nullable=False)
    src_port = Column(Integer)
    dst_ip = Column(String(45), nullable=False)
    dst_port = Column(Integer)
    proto = Column(String(16))
    features_json = Column(JSON, nullable=False)
    mlp_score = Column(Float)
    mlp_anom = Column(Boolean, nullable=False, server_default="0")
    iso_score = Column(Float)
    iso_anom = Column(Boolean)
    is_anomaly = Column(Boolean, nullable=False, server_default="0")
    verdict = Column(String(16), nullable=False, server_default="normal")

# Bang request_nonces: Luu ma ngau nhien de chong tan cong phat lai
class RequestNonce(Base):
    __tablename__ = "request_nonces"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    scope = Column(String(32), nullable=False)
    nonce = Column(String(128), nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    expires_at = Column(DateTime, nullable=False)

    __table_args__ = (
        UniqueConstraint("scope", "nonce", name="uq_scope_nonce"),
    )

# Bang firewall_actions: Luu tru cac lenh chan IP tu dong
class FirewallAction(Base):
    __tablename__ = "firewall_actions"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    src_ip = Column(String(45), nullable=False)
    action_type = Column(String(16), nullable=False)
    target = Column(String(64))
    description = Column(Text)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

# Tao tat ca cac bang vao database MySQL
Base.metadata.create_all(bind=engine)

# Dinh nghia cau truc du lieu JSON truyen vao va xuat ra cho API
class FlowEventIn(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")
    event_time: datetime
    sensor_name: Optional[str] = None
    flow_id: Optional[int] = None
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: str
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    features_json: Dict[str, float] = Field(default_factory=dict)
    mlp_score: Optional[float] = None
    mlp_anom: Optional[bool] = False
    iso_score: Optional[float] = None
    iso_anom: Optional[bool] = None
    is_anomaly: Optional[bool] = False
    verdict: Optional[str] = None

class FlowEventOut(FlowEventIn):
    id: int
    created_at: datetime

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

# Ham cung cap ket noi database cho moi request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Ham xac thuc HMAC de dam bao du lieu gui tu Sensor khong bi gia mao
def verify_hmac_request(
    db,
    scope: str,
    secret: str,
    body_bytes: bytes,
    ts_header: Optional[str],
    nonce_header: Optional[str],
    sig_header: Optional[str],
    max_age_sec: int,
    ttl_sec: int,
) -> None:
    if not secret:
        raise HTTPException(status_code=500, detail="HMAC secret not configured")

    if not (ts_header and nonce_header and sig_header):
        raise HTTPException(status_code=401, detail="Missing HMAC headers")

    try:
        ts = int(ts_header)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid timestamp")

    # Kiem tra do tre thoi gian va Nonce de ngan chan tan cong phat lai
    now = int(time.time())
    if abs(now - ts) > max_age_sec:
        raise HTTPException(status_code=401, detail="Timestamp too old")

    expires_at = utc_now() + timedelta(seconds=ttl_sec)
    nonce = nonce_header.strip()

    try:
        db.query(RequestNonce).filter(RequestNonce.expires_at < utc_now()).delete()
        db.commit()
    except Exception:
        db.rollback()

    rn = RequestNonce(scope=scope, nonce=nonce, expires_at=expires_at)
    try:
        db.add(rn)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=401, detail="Nonce already used (replay)")

    # Tinh toan chu ky va so sanh voi du lieu nhan vao
    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    mac.update(ts_header.encode("utf-8"))
    mac.update(b".")
    mac.update(nonce_header.encode("utf-8"))
    mac.update(b".")
    mac.update(body_bytes)
    expected = mac.hexdigest()

    if not hmac.compare_digest(expected, sig_header.strip()):
        raise HTTPException(status_code=401, detail="Bad signature")

def compute_verdict(payload: FlowEventIn) -> str:
    if payload.verdict:
        return payload.verdict
    return "anomaly" if payload.is_anomaly else "normal"

app = FastAPI(title="Flow IDS Backend")

@app.get("/health")
def health():
    return {"status": "ok"}

# Endpoint nhan du lieu tu Sensor, kiem tra bao mat va luu vao DB
@app.post("/api/events", response_model=FlowEventOut)
async def ingest_event(
    payload: FlowEventIn,
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp"),
    x_nonce: Optional[str] = Header(None, alias="X-Nonce"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    db=Depends(get_db),
):
    if REQUIRE_INGEST_HMAC:
        body = payload.json(separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        verify_hmac_request(
            db=db,
            scope="ingest",
            secret=INGEST_HMAC_SECRET,
            body_bytes=body,
            ts_header=x_timestamp,
            nonce_header=x_nonce,
            sig_header=x_signature,
            max_age_sec=INGEST_HMAC_MAX_AGE_SEC,
            ttl_sec=NONCE_TTL_SEC,
        )

    et = payload.event_time
    if et.tzinfo is None:
        et = et.replace(tzinfo=timezone.utc)

    verdict = compute_verdict(payload)
    features_clean = clean_features(payload.features_json)

    # Tao doi tuong ban ghi su kien mang
    row = FlowEvent(
        event_time=et,
        sensor_name=payload.sensor_name,
        flow_id=payload.flow_id,
        src_ip=payload.src_ip,
        src_port=payload.src_port,
        dst_ip=payload.dst_ip,
        dst_port=payload.dst_port,
        proto=payload.proto,
        features_json=features_clean,
        mlp_score=payload.mlp_score,
        mlp_anom=bool(payload.mlp_anom),
        iso_score=payload.iso_score,
        iso_anom=payload.iso_anom,
        is_anomaly=bool(payload.is_anomaly),
        verdict=verdict,
    )
    db.add(row)

    # Neu phat hien bat thuong thi tu dong ghi lenh chan vao firewall_actions
    if AUTO_BLOCK and payload.is_anomaly and payload.src_ip:
        act = FirewallAction(
            src_ip=payload.src_ip,
            action_type=AUTO_BLOCK_ACTION,
            target="iptables",
            description="Auto-block triggered by anomaly verdict",
        )
        db.add(act)

    db.commit()
    db.refresh(row)
    return row

# Endpoint lay danh sach su kien mang de hien thi len giao dien quan tri
@app.get("/api/events", response_model=List[FlowEventOut])
def list_events(
    only_anomaly: bool = Query(False),
    limit: int = Query(100, ge=1, le=2000),
    db=Depends(get_db),
):
    q = db.query(FlowEvent).order_by(FlowEvent.event_time.desc())
    if only_anomaly:
        q = q.filter(FlowEvent.is_anomaly.is_(True))
    return q.limit(limit).all()