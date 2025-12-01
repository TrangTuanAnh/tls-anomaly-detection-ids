# python-real-time-service/config.py
import os

# Đường dẫn trong CONTAINER Python
EVE_PATH = os.getenv("EVE_PATH", "/shared/logs/suricata/eve.json")

ISO_THRESHOLD = -0.1
AE_THRESHOLD = 0.05
POLL_INTERVAL = 0.2
