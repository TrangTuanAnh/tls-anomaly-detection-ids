"""TLS IDS Backend (FastAPI)

Phiên bản rút gọn cho đồ án **không có Front-end**:
- Giữ nguyên luồng ingest từ python-real-time-service -> POST /api/events
- Lưu dữ liệu vào bảng `tls_events`
- (Tuỳ chọn) HMAC + nonce + timestamp cho ingest (chống replay) -> bảng `request_nonces`

Các phần phục vụ Web UI (alerts, firewall_actions, users, audit_logs, session token/RBAC)
đã được loại bỏ để tránh dư thừa ở DB và backend.

Lưu ý: Project này dùng MySQL schema từ mysql-init/schema.sql.
Nếu bạn đã có DB cũ, hãy re-init (xóa mysql-data) hoặc tự migrate.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, Query, HTTPException, Request

from sqlalchemy.exc import OperationalError, IntegrityError
from sqlalchemy import (
    create_engine,
    Column,
    BigInteger,
    Integer,
    SmallInteger,
    String,
    Text,
    DateTime,
    Boolean,
    Float,
    JSON,
    func,
    UniqueConstraint,
)
from sqlalchemy.orm import sessionmaker, declarative_base

from pydantic import BaseModel


# =========================
# Config
# =========================

DATABASE_USER = os.getenv("DB_USER", "tls_user")
DATABASE_PASSWORD = os.getenv("DB_PASSWORD", "tls_pass")
DATABASE_HOST = os.getenv("DB_HOST", "db")
DATABASE_PORT = os.getenv("DB_PORT", "3306")
DATABASE_NAME = os.getenv("DB_NAME", "tls_ids")

DATABASE_URL = (
    f"mysql+mysqlconnector://{DATABASE_USER}:{DATABASE_PASSWORD}"
    f"@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}"
)

# Ingest hardening (python-real-time-service -> backend)
REQUIRE_INGEST_HMAC = os.getenv("REQUIRE_INGEST_HMAC", "false").lower() == "true"
INGEST_HMAC_SECRET = os.getenv("INGEST_HMAC_SECRET", "")
INGEST_HMAC_MAX_AGE_SEC = int(os.getenv("INGEST_HMAC_MAX_AGE_SEC", "120"))

# Auto-block (backend -> firewall-controller via DB polling)
AUTO_BLOCK_ENABLED = os.getenv("AUTO_BLOCK_ENABLED", "false").lower() == "true"
FIREWALL_TARGET = os.getenv("FIREWALL_TARGET", "iptables")

# FirewallAction signature (backend -> firewall-controller)
FW_ACTION_HMAC_SECRET = os.getenv("FW_ACTION_HMAC_SECRET", "")
FW_ACTION_EXPIRES_SEC = int(os.getenv("FW_ACTION_EXPIRES_SEC", "3600"))

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# =========================
# SQLAlchemy models
# =========================


class TLSEvent(Base):
    __tablename__ = "tls_events"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)

    event_time = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    sensor_name = Column(String(255))
    flow_id = Column(BigInteger)
    src_ip = Column(String(45), nullable=False)
    src_port = Column(Integer)
    dst_ip = Column(String(45), nullable=False)
    dst_port = Column(Integer)
    proto = Column(String(16))

    tls_version = Column(String(16))
    ja3_hash = Column(String(32))
    ja3_string = Column(Text)
    ja3s_string = Column(Text)
    sni = Column(Text)
    cipher_suites = Column(Text)
    tls_groups = Column(Text)

    tls_version_enum = Column(SmallInteger)
    is_legacy_version = Column(Boolean)
    rule_deprecated_version = Column(Boolean)

    num_ciphers = Column(SmallInteger)
    num_strong_ciphers = Column(SmallInteger)
    num_weak_ciphers = Column(SmallInteger)
    weak_cipher_ratio = Column(Float)
    supports_pfs = Column(Boolean)
    prefers_pfs = Column(Boolean)
    pfs_cipher_ratio = Column(Float)

    num_groups = Column(SmallInteger)
    uses_modern_group = Column(Boolean)
    legacy_group_ratio = Column(Float)

    rule_weak_cipher = Column(Boolean)
    rule_no_pfs = Column(Boolean)
    rule_cbc_only = Column(Boolean)

    ae_error = Column(Float)
    ae_anom = Column(Boolean)
    iso_score = Column(Float)
    iso_anom = Column(Boolean)
    is_anomaly = Column(Boolean, nullable=False, default=False)

    verdict = Column(String(16), nullable=False, default="NORMAL")
    features_json = Column(JSON)


class FirewallAction(Base):
    __tablename__ = "firewall_actions"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)

    src_ip = Column(String(45), nullable=False)
    action_type = Column(String(16), nullable=False)  # BLOCK / UNBLOCK

    target = Column(String(64))
    description = Column(Text)

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    executed_at = Column(DateTime)
    expires_at = Column(DateTime)

    # Integrity fields (backend -> firewall-controller)
    hmac_ts = Column(BigInteger)
    hmac_nonce = Column(String(64))
    hmac_sig = Column(String(64))

    status = Column(String(16), nullable=False, default="PENDING")
    error_message = Column(Text)

    __table_args__ = (
        UniqueConstraint("hmac_nonce", name="uniq_fw_hmac_nonce"),
    )

class RequestNonce(Base):
    __tablename__ = "request_nonces"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)
    scope = Column(String(64), nullable=False)
    nonce = Column(String(64), nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    expires_at = Column(DateTime, nullable=False)

    __table_args__ = (
        UniqueConstraint("scope", "nonce", name="uniq_scope_nonce"),
    )


# =========================
# Pydantic schemas
# =========================


class TLSEventIn(BaseModel):
    event_time: datetime

    sensor_name: Optional[str] = None
    flow_id: Optional[int] = None
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: str
    dst_port: Optional[int] = None
    proto: Optional[str] = None

    tls_version: Optional[str] = None
    ja3_hash: Optional[str] = None
    ja3_string: Optional[str] = None
    ja3s_string: Optional[str] = None
    sni: Optional[str] = None
    cipher_suites: Optional[str] = None
    tls_groups: Optional[str] = None

    tls_version_enum: Optional[int] = None
    is_legacy_version: Optional[bool] = None
    rule_deprecated_version: Optional[bool] = None

    num_ciphers: Optional[int] = None
    num_strong_ciphers: Optional[int] = None
    num_weak_ciphers: Optional[int] = None
    weak_cipher_ratio: Optional[float] = None
    supports_pfs: Optional[bool] = None
    prefers_pfs: Optional[bool] = None
    pfs_cipher_ratio: Optional[float] = None

    num_groups: Optional[int] = None
    uses_modern_group: Optional[bool] = None
    legacy_group_ratio: Optional[float] = None

    rule_weak_cipher: Optional[bool] = None
    rule_no_pfs: Optional[bool] = None
    rule_cbc_only: Optional[bool] = None

    ae_error: Optional[float] = None
    ae_anom: Optional[bool] = None
    iso_score: Optional[float] = None
    iso_anom: Optional[bool] = None
    is_anomaly: Optional[bool] = None

    verdict: Optional[str] = None
    features_json: Optional[dict] = None

    class Config:
        orm_mode = True


class TLSEventOut(TLSEventIn):
    id: int
    created_at: datetime
    is_anomaly: bool
    verdict: str


# =========================
# Helpers
# =========================


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def canonical_json_bytes(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def use_nonce(db, scope: str, nonce: str, ttl_seconds: int) -> None:
    # cleanup (best-effort)
    try:
        db.query(RequestNonce).filter(RequestNonce.expires_at < datetime.utcnow()).delete()
        db.commit()
    except Exception:
        db.rollback()

    rn = RequestNonce(
        scope=scope,
        nonce=nonce,
        expires_at=datetime.utcnow() + timedelta(seconds=ttl_seconds),
    )
    db.add(rn)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=401, detail="Replay detected (nonce already used)")


def verify_hmac_headers(
    *,
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
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid X-Timestamp")

    now = int(time.time())
    if abs(now - ts) > max_age_sec:
        raise HTTPException(status_code=401, detail="Request expired")

    # replay protection
    use_nonce(db, scope=scope, nonce=nonce_header, ttl_seconds=ttl_sec)

    mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
    mac.update(str(ts).encode("utf-8"))
    mac.update(b".")
    mac.update(nonce_header.encode("utf-8"))
    mac.update(b".")
    mac.update(body_bytes)
    expected = mac.hexdigest()

    if not hmac.compare_digest(expected, sig_header.strip().lower()):
        raise HTTPException(status_code=401, detail="Invalid signature")


def compute_is_anomaly(payload: TLSEventIn) -> bool:
    if payload.is_anomaly is not None:
        return payload.is_anomaly
    flags = []
    if payload.ae_anom is not None:
        flags.append(payload.ae_anom)
    if payload.iso_anom is not None:
        flags.append(payload.iso_anom)
    return any(flags) if flags else False


def compute_verdict(is_anomaly: bool) -> str:
    return "ANOMALOUS" if is_anomaly else "NORMAL"


def compute_severity(payload: TLSEventIn, is_anomaly: bool) -> Optional[str]:
    """Severity used for auto-block decision.

    Giữ tiêu chí giống bản đầy đủ:
    - CRITICAL: deprecated TLS version OR no PFS
    - HIGH: weak cipher OR CBC-only
    - MEDIUM: ML anomaly
    - None: không có vấn đề
    """
    if not is_anomaly and not any(
        [payload.rule_deprecated_version, payload.rule_no_pfs, payload.rule_weak_cipher, payload.rule_cbc_only]
    ):
        return None

    if payload.rule_deprecated_version or payload.rule_no_pfs:
        return "CRITICAL"
    if payload.rule_weak_cipher or payload.rule_cbc_only:
        return "HIGH"
    if is_anomaly:
        return "MEDIUM"
    return "LOW"


def sign_firewall_action(action_type: str, src_ip: str) -> tuple[int, str, str]:
    """Return (ts, nonce, sig).

    Must match firewall-controller.verify_action_hmac() format:
      f"{action_type}|{src_ip}|{ts}|{nonce}"
    """
    if not FW_ACTION_HMAC_SECRET:
        return 0, "", ""

    ts = int(time.time())
    nonce = secrets.token_hex(16)
    msg = f"{action_type}|{src_ip}|{ts}|{nonce}".encode("utf-8")
    sig = hmac.new(FW_ACTION_HMAC_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return ts, nonce, sig


 


# =========================
# App & routes
# =========================


app = FastAPI(title="TLS IDS Backend")


@app.on_event("startup")
def on_startup():
    max_tries = 10
    delay = 3
    for i in range(max_tries):
        try:
            print(f"[startup] Try {i+1}/{max_tries} connect DB...")
            Base.metadata.create_all(bind=engine)
            print("[startup] DB ok, tables ready.")
            break
        except OperationalError as e:
            print(f"[startup] DB not ready: {e}")
            time.sleep(delay)
    else:
        raise RuntimeError("Database not reachable after many retries")


@app.get("/health")
def health():
    return {"status": "ok"}


# -------- Events ingest --------


@app.post("/api/events", response_model=TLSEventOut)
async def create_event(request: Request, payload: TLSEventIn, db=Depends(get_db)):
    # Canonicalize the raw JSON body for HMAC verification.
    # Do NOT use payload.dict() here: Pydantic may convert strings (e.g., event_time) to datetime,
    # which breaks json.dumps() and also changes the bytes that the realtime service signed.
    try:
        raw_obj = await request.json()
    except Exception:
        # Fallback (should rarely happen; FastAPI already validated JSON for TLSEventIn)
        raw_obj = payload.dict()
    body_bytes = canonical_json_bytes(raw_obj)

    # Optional HMAC check (service -> backend)
    if REQUIRE_INGEST_HMAC:
        verify_hmac_headers(
            db=db,
            scope="ingest",
            secret=INGEST_HMAC_SECRET,
            body_bytes=body_bytes,
            ts_header=request.headers.get("X-Timestamp"),
            nonce_header=request.headers.get("X-Nonce"),
            sig_header=request.headers.get("X-Signature"),
            max_age_sec=INGEST_HMAC_MAX_AGE_SEC,
            ttl_sec=INGEST_HMAC_MAX_AGE_SEC,
        )
    else:
        # nếu client gửi HMAC mà sai -> vẫn reject (tránh downgrade)
        if request.headers.get("X-Signature"):
            verify_hmac_headers(
                db=db,
                scope="ingest",
                secret=INGEST_HMAC_SECRET,
                body_bytes=body_bytes,
                ts_header=request.headers.get("X-Timestamp"),
                nonce_header=request.headers.get("X-Nonce"),
                sig_header=request.headers.get("X-Signature"),
                max_age_sec=INGEST_HMAC_MAX_AGE_SEC,
                ttl_sec=INGEST_HMAC_MAX_AGE_SEC,
            )

    is_anom = compute_is_anomaly(payload)
    verdict = payload.verdict or compute_verdict(is_anom)

    evt = TLSEvent(
        event_time=payload.event_time,
        sensor_name=payload.sensor_name,
        flow_id=payload.flow_id,
        src_ip=payload.src_ip,
        src_port=payload.src_port,
        dst_ip=payload.dst_ip,
        dst_port=payload.dst_port,
        proto=payload.proto,
        tls_version=payload.tls_version,
        ja3_hash=payload.ja3_hash,
        ja3_string=payload.ja3_string,
        ja3s_string=payload.ja3s_string,
        sni=payload.sni,
        cipher_suites=payload.cipher_suites,
        tls_groups=payload.tls_groups,
        tls_version_enum=payload.tls_version_enum,
        is_legacy_version=payload.is_legacy_version,
        rule_deprecated_version=payload.rule_deprecated_version,
        num_ciphers=payload.num_ciphers,
        num_strong_ciphers=payload.num_strong_ciphers,
        num_weak_ciphers=payload.num_weak_ciphers,
        weak_cipher_ratio=payload.weak_cipher_ratio,
        supports_pfs=payload.supports_pfs,
        prefers_pfs=payload.prefers_pfs,
        pfs_cipher_ratio=payload.pfs_cipher_ratio,
        num_groups=payload.num_groups,
        uses_modern_group=payload.uses_modern_group,
        legacy_group_ratio=payload.legacy_group_ratio,
        rule_weak_cipher=payload.rule_weak_cipher,
        rule_no_pfs=payload.rule_no_pfs,
        rule_cbc_only=payload.rule_cbc_only,
        ae_error=payload.ae_error,
        ae_anom=payload.ae_anom,
        iso_score=payload.iso_score,
        iso_anom=payload.iso_anom,
        is_anomaly=is_anom,
        verdict=verdict,
        features_json=payload.features_json,
    )

    db.add(evt)
    db.commit()
    db.refresh(evt)

    # Auto-block: tạo record cho firewall-controller polling (không cần Web UI)
    if AUTO_BLOCK_ENABLED:
        severity = compute_severity(payload, is_anom)
        if severity in ("HIGH", "CRITICAL"):
            ts, nonce, sig = sign_firewall_action("BLOCK", evt.src_ip)
            fw = FirewallAction(
                src_ip=evt.src_ip,
                action_type="BLOCK",
                target=FIREWALL_TARGET,
                description=f"Auto-block due to {severity} TLS anomaly",
                status="PENDING",
                expires_at=datetime.utcnow() + timedelta(seconds=FW_ACTION_EXPIRES_SEC),
                hmac_ts=ts or None,
                hmac_nonce=nonce or None,
                hmac_sig=sig or None,
            )
            db.add(fw)
            db.commit()

    return evt


@app.get("/api/events", response_model=List[TLSEventOut])
def list_events(
    only_anomaly: bool = Query(False),
    limit: int = Query(100, ge=1, le=1000),
    db=Depends(get_db),
):
    q = db.query(TLSEvent).order_by(TLSEvent.event_time.desc())
    if only_anomaly:
        q = q.filter(TLSEvent.is_anomaly.is_(True))
    return q.limit(limit).all()





