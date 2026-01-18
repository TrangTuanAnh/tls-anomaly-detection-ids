# python-real-time-service/log_utils.py
import os
import time
import csv
import re
from typing import Dict, Iterator, Optional, Tuple

from config import POLL_INTERVAL

# Su dung Regex de chuan hoa khoang trang trong ten cot
_ws_re = re.compile(r"\s+")

# Ham chuan hoa ten cot: loai bo khoang trang dau duoi va ky tu thua
def _normalize_col(name: str) -> str:
    name = (name or "").strip()
    name = _ws_re.sub(" ", name)
    return name

# Ham cho file ton tai: Tranh loi he thong khi Sniffer chua kip tao file log
def wait_for_file(path: str, timeout: Optional[float] = None) -> bool:
    start = time.time()
    while not os.path.isfile(path):
        if timeout is not None and (time.time() - start) > timeout:
            return False
        time.sleep(0.5)
    return True

# Co che Tail file CSV: Theo doi va doc tung hang moi khi file duoc ghi them du lieu
def follow_csv(path: str) -> Iterator[Dict[str, str]]:
    # Cho cho den khi file log xuat hien
    wait_for_file(path)

    last_inode = None
    header: Optional[list] = None
    offset = 0

    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            # Neu file bi xoa thi reset cac thong so va cho doi
            header = None
            last_inode = None
            offset = 0
            time.sleep(0.5)
            continue

        inode = getattr(st, "st_ino", None)
        size = st.st_size

        # Kiem tra neu file bi thay the (Rotation) hoac bi ghi de (Truncated)
        rotated = (last_inode is not None and inode != last_inode) or (size < offset)
        if rotated:
            header = None
            offset = 0

        last_inode = inode

        # Mo file va di chuyen den vi tri cuoi cung da doc de lay du lieu moi
        with open(path, "r", newline="", encoding="utf-8", errors="ignore") as f:
            f.seek(offset)

            # Neu chua co tieu de thi doc dong dau tien va chuan hoa ten cot
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

            # Doc tung dong du lieu moi phat sinh
            while True:
                pos = f.tell()
                line = f.readline()
                if not line:
                    # Neu het du lieu thi luu vi tri offset va tam dung
                    offset = pos
                    time.sleep(POLL_INTERVAL)
                    break
                if not line.strip():
                    continue

                # Chuyen doi hang du lieu thanh Dictionary dua tren tieu de da doc
                reader = csv.reader([line])
                row = next(reader)
                
                # Dam bao so luong cot khop voi tieu de
                if len(row) < len(header):
                    row = row + [""] * (len(header) - len(row))
                if len(row) > len(header):
                    row = row[: len(header)]

                # Tra ve du lieu duoi dang Dictionary de module AI xu ly
                d = {_normalize_col(h): v for h, v in zip(header, row)}
                yield d