# python-real-time-service/config.py
import os

# Duong dan den file CSV (su dung cho che do doc file truyen thong)
FLOW_CSV_PATH = os.getenv("FLOW_CSV_PATH", "/shared/flows/flows.csv")

# Che do nhan du lieu (Ingest mode):
# - csv: Doc duoi file CSV (legacy)
# - url: Nhan du lieu qua HTTP POST (khuyen nghi cho thoi gian thuc)
# - both: Su dung ca hai che do tren
INGEST_MODE = os.getenv("INGEST_MODE", "url").strip().lower()

# Dia chi URL cua Backend (FastAPI) de gui ket qua phan tich
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

# Thiet lap nguong phat hien bat thuong cho mo hinh AI
# Du an su dung MLP Classifier (dau ra sigmoid 0-1) lam bo loc chinh
# Mac dinh nguong la 0.5; neu tren 0.5 thi coi la bat thuong
MLP_THRESHOLD = float(os.getenv("MLP_THRESHOLD", os.getenv("AE_THRESHOLD", "0.5")))
ISO_THRESHOLD = float(os.getenv("ISO_THRESHOLD", "-0.1"))

# Thoi gian nghi giua cac lan quet file (su dung cho che do CSV)
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "0.2"))

# Cau hinh dia chi va cong lang nghe cua dich vu (Url mode)
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "9000"))

# Cau hinh bao mat HMAC de xac thuc du lieu gui tu Sniffer
REQUIRE_INGEST_HMAC = os.getenv("REQUIRE_INGEST_HMAC", "false").lower() == "true"
INGEST_HMAC_SECRET = os.getenv("INGEST_HMAC_SECRET", "")
INGEST_HMAC_MAX_AGE_SEC = int(os.getenv("INGEST_HMAC_MAX_AGE_SEC", "120"))

# Kiem tra tinh toan ven cua mo hinh AI bang ma bam SHA256
# Dam bao file mo hinh khong bi thay doi trai phep
MLP_MODEL_SHA256 = os.getenv("MLP_MODEL_SHA256", os.getenv("AE_MODEL_SHA256", ""))
SCALER_SHA256 = os.getenv("SCALER_SHA256", "")