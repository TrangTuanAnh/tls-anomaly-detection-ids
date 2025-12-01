# python-real-time-service/log_utils.py
import json
import os
import time
from typing import Iterator, Optional, Dict

from config import POLL_INTERVAL


def wait_for_file(path: str, timeout: Optional[float] = None) -> bool:
    start = time.time()
    while not os.path.isfile(path):
        if timeout is not None and (time.time() - start) > timeout:
            return False
        time.sleep(0.5)
    return True


def follow_file(path: str) -> Iterator[str]:
    """
    Tail file giống 'tail -F': luôn chờ và đọc dòng mới.
    """
    if not wait_for_file(path):
        raise FileNotFoundError(f"File không tồn tại: {path}")

    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)  # nhảy tới cuối file hiện tại

        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                continue
            yield line.rstrip("\r\n")


def parse_tls_event(line: str) -> Optional[Dict]:
    """
    Parse 1 dòng eve.json, chỉ trả về nếu là event TLS.
    """
    if not line:
        return None

    try:
        evt = json.loads(line)
    except json.JSONDecodeError:
        return None

    if evt.get("event_type") != "tls":
        return None

    return evt
