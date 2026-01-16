# python-real-time-service/config.py
import os

# CICFlowMeter CSV path inside container (legacy mode)
FLOW_CSV_PATH = os.getenv("FLOW_CSV_PATH", "/shared/flows/flows.csv")

# Ingest mode:
#   - "csv": tail FLOW_CSV_PATH (legacy)
#   - "url": receive flows via HTTP POST /flow (recommended for realtime)
#   - "both": enable both csv tail + http ingest
INGEST_MODE = os.getenv("INGEST_MODE", "url").strip().lower()

# Backend URL (FastAPI backend)
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

# Thresholds for anomaly decision
AE_THRESHOLD = float(os.getenv("AE_THRESHOLD", "0.05"))
ISO_THRESHOLD = float(os.getenv("ISO_THRESHOLD", "-0.1"))

# Follow file poll interval (legacy csv mode)
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "0.2"))

# HTTP listen config (url/both mode)
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "9000"))

# Optional hardening: require signed ingest
REQUIRE_INGEST_HMAC = os.getenv("REQUIRE_INGEST_HMAC", "false").lower() == "true"
INGEST_HMAC_SECRET = os.getenv("INGEST_HMAC_SECRET", "")
INGEST_HMAC_MAX_AGE_SEC = int(os.getenv("INGEST_HMAC_MAX_AGE_SEC", "120"))

# Optional model integrity pinning
AE_MODEL_SHA256 = os.getenv("AE_MODEL_SHA256", "")
SCALER_SHA256 = os.getenv("SCALER_SHA256", "")
