from fastapi import FastAPI, Depends, Query
from typing import Optional, List
from datetime import datetime
import os

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
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from pydantic import BaseModel

# ==========================================================
#  Cấu hình DB từ biến môi trường (docker-compose sẽ set)
# ==========================================================
DATABASE_USER = os.getenv("DB_USER", "tls_user")
DATABASE_PASSWORD = os.getenv("DB_PASSWORD", "tls_pass")
DATABASE_HOST = os.getenv("DB_HOST", "db")
DATABASE_PORT = os.getenv("DB_PORT", "3306")
DATABASE_NAME = os.getenv("DB_NAME", "tls_ids")

DATABASE_URL = (
    f"mysql+mysqlconnector://{DATABASE_USER}:{DATABASE_PASSWORD}"
    f"@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==========================================================
#  SQLAlchemy models (match schema.sql)
# ==========================================================


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

    # TLS / JA3
    tls_version = Column(String(16))
    ja3_hash = Column(String(32))
    ja3_string = Column(Text)
    ja3s_string = Column(Text)
    sni = Column(Text)
    cipher_suites = Column(Text)
    tls_groups = Column(Text)

    # Feature từ feature_extractor
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

    # Kết quả model
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

    tls_event_id = Column(
        BigInteger, ForeignKey("tls_events.id", ondelete="CASCADE"), nullable=False
    )

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    severity = Column(String(16), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)

    status = Column(String(16), nullable=False, default="OPEN")
    resolved_at = Column(DateTime)
    resolved_note = Column(Text)

    assigned_to = Column(String(255))

    event = relationship("TLSEvent", back_populates="alerts")
    firewall_actions = relationship(
        "FirewallAction", back_populates="alert", cascade="all, delete-orphan"
    )


class FirewallAction(Base):
    __tablename__ = "firewall_actions"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)

    alert_id = Column(
        BigInteger, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )

    src_ip = Column(String(45), nullable=False)
    action_type = Column(String(16), nullable=False)

    target = Column(String(64))
    description = Column(Text)

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    executed_at = Column(DateTime)
    expires_at = Column(DateTime)

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


# ==========================================================
#  Pydantic schemas (request / response)
# ==========================================================


class TLSEventIn(BaseModel):
    # thời gian & network
    event_time: datetime

    sensor_name: Optional[str] = None
    flow_id: Optional[int] = None
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: str
    dst_port: Optional[int] = None
    proto: Optional[str] = None

    # TLS / JA3
    tls_version: Optional[str] = None
    ja3_hash: Optional[str] = None
    ja3_string: Optional[str] = None
    ja3s_string: Optional[str] = None
    sni: Optional[str] = None
    cipher_suites: Optional[str] = None
    tls_groups: Optional[str] = None

    # Feature
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

    # Model output
    ae_error: Optional[float] = None
    ae_anom: Optional[bool] = None
    iso_score: Optional[float] = None
    iso_anom: Optional[bool] = None
    is_anomaly: Optional[bool] = None  # có thể để trống, backend sẽ tự tính

    verdict: Optional[str] = None      # có thể để trống, backend sẽ set
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

    class Config:
        orm_mode = True


# ==========================================================
#  Config auto-block
# ==========================================================
AUTO_BLOCK_ENABLED = os.getenv("AUTO_BLOCK_ENABLED", "false").lower() == "true"
FIREWALL_TARGET = os.getenv("FIREWALL_TARGET", "iptables")


# ==========================================================
#  Helpers
# ==========================================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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
    # Không bất thường + không rule vi phạm thì khỏi tạo alert
    if not is_anomaly and not any(
        [
            payload.rule_deprecated_version,
            payload.rule_no_pfs,
            payload.rule_weak_cipher,
            payload.rule_cbc_only,
        ]
    ):
        return None

    # Ưu tiên rule nặng hơn
    if payload.rule_deprecated_version or payload.rule_no_pfs:
        return "CRITICAL"
    if payload.rule_weak_cipher or payload.rule_cbc_only:
        return "HIGH"
    if is_anomaly:
        return "MEDIUM"
    return "LOW"


# ==========================================================
#  FastAPI app & routes
# ==========================================================
app = FastAPI(title="TLS IDS Backend")


@app.on_event("startup")
def on_startup():
    # Nếu bảng đã tạo bằng schema.sql rồi thì create_all(checkfirst) sẽ không phá gì
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/events", response_model=TLSEventOut)
def create_event(payload: TLSEventIn, db=Depends(get_db)):
    # Tính anomaly + verdict nếu client không gửi
    is_anom = compute_is_anomaly(payload)
    verdict = compute_verdict(is_anom)

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

    # Tạo alert nếu cần
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

        # Auto-block nếu bật
        if AUTO_BLOCK_ENABLED and severity in ("HIGH", "CRITICAL"):
            fw = FirewallAction(
                alert_id=alert.id,
                src_ip=evt.src_ip,
                action_type="BLOCK",
                target=FIREWALL_TARGET,
                description=f"Auto-block due to {severity} TLS anomaly",
                status="PENDING",
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
    events = q.limit(limit).all()
    return events


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
    alerts = q.limit(limit).all()
    return alerts


@app.get("/api/firewall-actions", response_model=List[FirewallActionOut])
def list_firewall_actions(
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db=Depends(get_db),
):
    q = db.query(FirewallAction).order_by(FirewallAction.created_at.desc())
    if status:
        q = q.filter(FirewallAction.status == status)
    actions = q.limit(limit).all()
    return actions
