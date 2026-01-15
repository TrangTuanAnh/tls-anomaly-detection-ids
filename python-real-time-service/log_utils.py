# python-real-time-service/log_utils.py
import os
import time
import csv
import re
from typing import Dict, Iterator, Optional, Tuple

from config import POLL_INTERVAL

_ws_re = re.compile(r"\s+")


def _normalize_col(name: str) -> str:
    name = (name or "").strip()
    name = _ws_re.sub(" ", name)
    return name


def wait_for_file(path: str, timeout: Optional[float] = None) -> bool:
    start = time.time()
    while not os.path.isfile(path):
        if timeout is not None and (time.time() - start) > timeout:
            return False
        time.sleep(0.5)
    return True


def follow_csv(path: str) -> Iterator[Dict[str, str]]:

    wait_for_file(path)

    last_inode = None
    header: Optional[list] = None
    offset = 0

    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            header = None
            last_inode = None
            offset = 0
            time.sleep(0.5)
            continue

        inode = getattr(st, "st_ino", None)
        size = st.st_size

        rotated = (last_inode is not None and inode != last_inode) or (size < offset)
        if rotated:
            header = None
            offset = 0

        last_inode = inode

        with open(path, "r", newline="", encoding="utf-8", errors="ignore") as f:
            f.seek(offset)

            if header is None:
                while True:
                    pos = f.tell()
                    line = f.readline()
                    if not line:
                        offset = pos
                        time.sleep(POLL_INTERVAL)
                        break
                    if line.strip():

                        reader = csv.reader([line])
                        header = [_normalize_col(h) for h in next(reader)]
                        break

            if header is None:
                continue

            while True:
                pos = f.tell()
                line = f.readline()
                if not line:
                    offset = pos
                    time.sleep(POLL_INTERVAL)
                    break
                if not line.strip():
                    continue

                reader = csv.reader([line])
                row = next(reader)
                if len(row) < len(header):
                    row = row + [""] * (len(header) - len(row))
                if len(row) > len(header):
                    row = row[: len(header)]

                d = {_normalize_col(h): v for h, v in zip(header, row)}
                yield d
