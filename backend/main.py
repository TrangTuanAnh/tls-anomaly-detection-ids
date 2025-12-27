"""TLS IDS Backend (FastAPI)
- Session token (HMAC-signed) + bcrypt (passlib) + RBAC
- Seed admin mặc định
- Bảo vệ endpoint nhạy cảm (tạo firewall action)
- HMAC + nonce + timestamp (tùy chọn) cho request admin và/hoặc ingest
- Audit log cơ bản

Lưu ý: Project này dùng MySQL schema từ mysql-init/schema.sql.
Nếu bạn đã có DB cũ, hãy re-init (xóa mysql-data) hoặc tự migrate để có các cột mới.
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, Query, HTTPException, Request
from passlib.context import CryptContext

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
    ForeignKey,
    func,
    UniqueConstraint,
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

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

# Login session token (HMAC-signed)
SESSION_HMAC_SECRET = os.getenv("SESSION_HMAC_SECRET", "")
SESSION_TOKEN_PREFIX = os.getenv("SESSION_TOKEN_PREFIX", "HMAC1")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@12345")
ADMIN_FULL_NAME = os.getenv("ADMIN_FULL_NAME", "Default Admin")

# Sensitive endpoints hardening
REQUIRE_ADMIN_HMAC = os.getenv("REQUIRE_ADMIN_HMAC", "false").lower() == "true"
ADMIN_HMAC_SECRET = os.getenv("ADMIN_HMAC_SECRET", "")
ADMIN_HMAC_MAX_AGE_SEC = int(os.getenv("ADMIN_HMAC_MAX_AGE_SEC", "120"))

# Ingest hardening (python-real-time-service -> backend)
REQUIRE_INGEST_HMAC = os.getenv("REQUIRE_INGEST_HMAC", "false").lower() == "true"
INGEST_HMAC_SECRET = os.getenv("INGEST_HMAC_SECRET", "")
INGEST_HMAC_MAX_AGE_SEC = int(os.getenv("INGEST_HMAC_MAX_AGE_SEC", "120"))

# Auto-block
AUTO_BLOCK_ENABLED = os.getenv("AUTO_BLOCK_ENABLED", "false").lower() == "true"
FIREWALL_TARGET = os.getenv("FIREWALL_TARGET", "iptables")

# FirewallAction signature (backend -> firewall-controller)
FW_ACTION_HMAC_SECRET = os.getenv("FW_ACTION_HMAC_SECRET", "")
FW_ACTION_EXPIRES_SEC = int(os.getenv("FW_ACTION_EXPIRES_SEC", "3600"))


engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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

    alerts = relationship("Alert", back_populates="event", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)

    tls_event_id = Column(BigInteger, ForeignKey("tls_events.id", ondelete="CASCADE"), nullable=False)

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    severity = Column(String(16), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)

    status = Column(String(16), nullable=False, default="OPEN")
    resolved_at = Column(DateTime)
    resolved_note = Column(Text)
    assigned_to = Column(String(255))

    event = relationship("TLSEvent", back_populates="alerts")
    firewall_actions = relationship("FirewallAction", back_populates="alert", cascade="all, delete-orphan")


class FirewallAction(Base):
    __tablename__ = "firewall_actions"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)

    alert_id = Column(BigInteger, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)

    src_ip = Column(String(45), nullable=False)
    action_type = Column(String(16), nullable=False)

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

    alert = relationship("Alert", back_populates="firewall_actions")


class User(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)
    username = Column(String(191), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(String(50), nullable=False, default="viewer")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())


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


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    actor = Column(String(191), nullable=False)
    action = Column(String(64), nullable=False)
    detail = Column(Text)
    src_ip = Column(String(64))


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


class AlertOut(BaseModel):
    id: int
    tls_event_id: int
    created_at: datetime
    updated_at: datetime
    severity: str
    title: str
    description: Optional[str] = None
    status: str
    resolved_at: Optional[datetime] = None
    resolved_note: Optional[str] = None

    class Config:
        orm_mode = True


class FirewallActionOut(BaseModel):
    id: int
    alert_id: Optional[int]
    src_ip: str
    action_type: str
    target: Optional[str]
    description: Optional[str]
    created_at: datetime
    executed_at: Optional[datetime]
    expires_at: Optional[datetime]
    status: str
    error_message: Optional[str]

    # integrity fields (exposed để debug)
    hmac_ts: Optional[int] = None
    hmac_nonce: Optional[str] = None
    hmac_sig: Optional[str] = None

    class Config:
        orm_mode = True


class FirewallActionIn(BaseModel):
    src_ip: str
    action_type: str  # BLOCK / UNBLOCK
    target: Optional[str] = None
    description: Optional[str] = None


class LoginIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    username: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True


class UserCreateIn(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None
    role: str = "viewer"


# =========================
# Helpers
# =========================


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    return pwd_context.verify(password, stored_hash)


def create_access_token(data: dict, expires_minutes: int) -> str:
    """Create a compact HMAC-signed session token.

    Format: <prefix>.<payload_b64url>.<sig_hex>
    Payload is canonical JSON and includes: sub, role, iat, exp.
    """
    if not SESSION_HMAC_SECRET:
        raise RuntimeError("SESSION_HMAC_SECRET not configured")

    now = int(time.time())
    payload = dict(data)
    payload.update({
        "iat": now,
        "exp": now + int(expires_minutes) * 60,
    })

    payload_b = canonical_json_bytes(payload)
    payload_b64 = base64.urlsafe_b64encode(payload_b).rstrip(b"=").decode("ascii")

    sig = hmac.new(
        SESSION_HMAC_SECRET.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{SESSION_TOKEN_PREFIX}.{payload_b64}.{sig}"


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def decode_access_token(token: str) -> dict:
    if not SESSION_HMAC_SECRET:
        raise HTTPException(status_code=500, detail="SESSION_HMAC_SECRET not configured")

    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=401, detail="Invalid token")
    prefix, payload_b64, sig = parts
    if prefix != SESSION_TOKEN_PREFIX:
        raise HTTPException(status_code=401, detail="Invalid token")

    expected = hmac.new(
        SESSION_HMAC_SECRET.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, sig.strip().lower()):
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    exp = payload.get("exp")
    if exp is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        exp_i = int(exp)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    if int(time.time()) > exp_i:
        raise HTTPException(status_code=401, detail="Token expired")

    return payload


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
    """Return (ts, nonce, sig)."""
    if not FW_ACTION_HMAC_SECRET:
        # không cấu hình => vẫn tạo record nhưng để trống field; firewall-controller có thể từ chối.
        return 0, "", ""

    ts = int(time.time())
    nonce = secrets.token_hex(16)
    msg = f"{action_type}|{src_ip}|{ts}|{nonce}".encode("utf-8")
    sig = hmac.new(FW_ACTION_HMAC_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return ts, nonce, sig


def audit(db, actor: str, action: str, detail: str, src_ip: Optional[str]) -> None:
    try:
        db.add(AuditLog(actor=actor, action=action, detail=detail, src_ip=src_ip))
        db.commit()
    except Exception:
        db.rollback()


# =========================
# App & routes
# =========================


app = FastAPI(title="TLS IDS Backend (Read-only UI)")


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
    # Optional HMAC check (service -> backend)
    if REQUIRE_INGEST_HMAC:
        verify_hmac_headers(
            db=db,
            scope="ingest",
            secret=INGEST_HMAC_SECRET,
            body_bytes=canonical_json_bytes(payload.dict()),
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
                body_bytes=canonical_json_bytes(payload.dict()),
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

    severity = compute_severity(payload, is_anom)
    if severity:
        alert = Alert(
            tls_event_id=evt.id,
            severity=severity,
            title="TLS anomaly detected",
            description="Automatic alert generated by TLS IDS backend",
            status="OPEN",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        if AUTO_BLOCK_ENABLED and severity in ("HIGH", "CRITICAL"):
            ts, nonce, sig = sign_firewall_action("BLOCK", evt.src_ip)
            fw = FirewallAction(
                alert_id=alert.id,
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


@app.get("/api/alerts", response_model=List[AlertOut])
def list_alerts(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db=Depends(get_db),
):
    q = db.query(Alert).order_by(Alert.created_at.desc())
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    return q.limit(limit).all()


@app.get("/api/firewall-actions", response_model=List[FirewallActionOut])
def list_firewall_actions(
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db=Depends(get_db),
):
    q = db.query(FirewallAction).order_by(FirewallAction.created_at.desc())
    if status:
        q = q.filter(FirewallAction.status == status)
    return q.limit(limit).all()


