"""
Firewall Controller: Module tu dong thuc thi cac lenh chan IP
Co che: Lien tuc quet bang firewall_actions trong MySQL va ap dung vao Iptables
"""

from __future__ import annotations

import os
import time
import subprocess
from typing import Dict, Set, Tuple, Optional

from mysql.connector import pooling


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse common boolean env formats (true/false, 1/0, yes/no, on/off)."""
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _maybe_file(path: Optional[str]) -> Optional[str]:
    """Return path only if non-empty and exists; otherwise None."""
    if not path:
        return None
    p = str(path).strip()
    if not p:
        return None
    return p if os.path.exists(p) else None

# Cau hinh ket noi Database va Iptables tu bien moi truong
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "tls_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "tls_ids")

# MySQL TLS (optional) 
# Use the same env names already documented in docker-compose.firewall.yml.
DB_TLS_ENABLED = _env_bool("DB_TLS_ENABLED", False)
DB_SSL_CA = os.getenv("DB_SSL_CA", "").strip() or None
DB_SSL_CERT = os.getenv("DB_SSL_CERT", "").strip() or None
DB_SSL_KEY = os.getenv("DB_SSL_KEY", "").strip() or None

# Verify server certificate chain against CA (recommended).
DB_SSL_VERIFY_CERT = _env_bool("DB_SSL_VERIFY_CERT", True)

# Verify host identity (SAN / hostname match). Keep default false for
# compatibility with older mysql-connector-python versions.
DB_SSL_VERIFY_IDENTITY = _env_bool("DB_SSL_VERIFY_IDENTITY", False)

IPTABLES_CHAIN = os.getenv("IPTABLES_CHAIN", "FORWARD").strip().upper()
IPTABLES_BASE_CHAIN = os.getenv("IPTABLES_BASE_CHAIN", "FORWARD").strip().upper()
FIREWALL_TARGET = os.getenv("FIREWALL_TARGET", "DROP").strip().upper()
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1.0"))

FW_DRY_RUN = os.getenv("FW_DRY_RUN", "false").lower() == "true"

# Ham thuc thi lenh he thong Iptables thong qua subprocess
def _iptables(args: list[str]) -> Tuple[int, str]:
    cmd = ["iptables"] + args
    if FW_DRY_RUN:
        return 0, "[DRY_RUN] " + " ".join(cmd)

    p = subprocess.run(cmd, capture_output=True, text=True)
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out.strip()

# Khoi tao Chain rieng trong Iptables de quan ly cac luat chan mot cach tap trung
def ensure_chain_exists() -> None:
    builtins = {"INPUT", "OUTPUT", "FORWARD"}
    chain = (IPTABLES_CHAIN or "FORWARD").upper()
    base_chain = (IPTABLES_BASE_CHAIN or "FORWARD").upper()

    if chain in builtins:
        return

    rc, _ = _iptables(["-nL", chain])
    if rc != 0:
        rc2, out2 = _iptables(["-N", chain])
        if rc2 != 0:
            raise RuntimeError(f"Cannot create iptables chain {chain}: {out2}")

    if base_chain not in builtins:
        base_chain = "FORWARD"

    rcj, _ = _iptables(["-C", base_chain, "-j", chain])
    if rcj != 0:
        _iptables(["-I", base_chain, "1", "-j", chain])

# Kiem tra xem mot dia chi IP da bi chan trong Iptables hay chua
def rule_exists(ip: str) -> bool:
    rc, _ = _iptables(["-C", IPTABLES_CHAIN, "-s", ip, "-j", FIREWALL_TARGET])
    return rc == 0

# Them luat chan IP vao dau danh sach cua Chain
def add_rule(ip: str) -> None:
    if rule_exists(ip):
        return
    rc, out = _iptables(["-I", IPTABLES_CHAIN, "1", "-s", ip, "-j", FIREWALL_TARGET])
    if rc != 0:
        raise RuntimeError(out)

# Xoa tat ca cac luat lien quan den mot IP khoi Firewall
def del_rule(ip: str) -> None:
    while True:
        rc, out = _iptables(["-D", IPTABLES_CHAIN, "-s", ip, "-j", FIREWALL_TARGET])
        if rc != 0:
            break

# Thiet lap Connection Pool de toi uu ket noi den Database MySQL
def make_pool():
    cfg = dict(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=True,
    )

    if DB_TLS_ENABLED:
        # Resolve and validate file paths (fail-soft with warnings).
        ca = _maybe_file(DB_SSL_CA)
        cert = _maybe_file(DB_SSL_CERT)
        key = _maybe_file(DB_SSL_KEY)

        if DB_SSL_CA and not ca:
            print(f"[FW][WARN] DB_SSL_CA not found: {DB_SSL_CA}")
        if DB_SSL_CERT and not cert:
            print(f"[FW][WARN] DB_SSL_CERT not found: {DB_SSL_CERT}")
        if DB_SSL_KEY and not key:
            print(f"[FW][WARN] DB_SSL_KEY not found: {DB_SSL_KEY}")

        # mysql-connector-python enables TLS when any ssl_* option is present.
        if ca:
            cfg["ssl_ca"] = ca
        if cert:
            cfg["ssl_cert"] = cert
        if key:
            cfg["ssl_key"] = key
        cfg["ssl_verify_cert"] = bool(DB_SSL_VERIFY_CERT)

        # Optional: verify host identity (requires newer connector).
        if DB_SSL_VERIFY_IDENTITY:
            cfg["ssl_verify_identity"] = True

    try:
        return pooling.MySQLConnectionPool(pool_name="fwpool", pool_size=3, **cfg)
    except TypeError as e:
        # Some connector versions don't support ssl_verify_identity.
        if "ssl_verify_identity" in str(e) and "ssl_verify_identity" in cfg:
            print(
                "[FW][WARN] mysql-connector-python does not support ssl_verify_identity; "
                "continue without identity verification (upgrade connector to enable it)."
            )
            cfg.pop("ssl_verify_identity", None)
            return pooling.MySQLConnectionPool(pool_name="fwpool", pool_size=3, **cfg)
        raise

# Doc lich su cac hanh dong tu DB de khoi phuc danh sach chan khi khoi dong lai module
def bootstrap_blocklist(conn) -> Set[str]:
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, src_ip, action_type FROM firewall_actions ORDER BY id ASC")
    blocked: Set[str] = set()
    last_id = 0
    for row in cur.fetchall():
        last_id = int(row["id"])
        ip = row["src_ip"]
        act = (row["action_type"] or "").upper()
        if act == "BLOCK":
            blocked.add(ip)
        elif act == "UNBLOCK":
            blocked.discard(ip)
    cur.close()
    return blocked, last_id

# Lay cac hanh dong moi nhat chua duoc thuc thi dua vao ID cuoi cung
def fetch_actions_after(conn, last_id: int):
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT id, src_ip, action_type FROM firewall_actions WHERE id > %s ORDER BY id ASC",
        (last_id,),
    )
    rows = cur.fetchall()
    cur.close()
    return rows

def main():
    print(f"[FW] Bat dau Firewall Controller (dry_run={FW_DRY_RUN})")
    ensure_chain_exists()
    pool = make_pool()

    with pool.get_connection() as conn:
        blocked, last_id = bootstrap_blocklist(conn)

    # Thuc thi lai cac luat chan da co trong Database
    for ip in sorted(blocked):
        try:
            add_rule(ip)
        except Exception as e:
            print(f"[FW][WARN] Khong the bootstrap IP {ip}: {e}")

    last_integrity_check = 0.0

    # Vong lap chinh: Kiem tra hanh dong moi tu DB moi 1 giay
    while True:
        try:
            with pool.get_connection() as conn:
                actions = fetch_actions_after(conn, last_id)

            for a in actions:
                last_id = int(a["id"])
                ip = a["src_ip"]
                act = (a["action_type"] or "").upper()

                if act == "BLOCK":
                    try:
                        add_rule(ip)
                        blocked.add(ip)
                        print(f"[FW] DA CHAN IP: {ip}")
                    except Exception as e:
                        print(f"[FW][WARN] Loi khi chan {ip}: {e}")
                elif act == "UNBLOCK":
                    try:
                        del_rule(ip)
                        blocked.discard(ip)
                        print(f"[FW] DA MO CHAN IP: {ip}")
                    except Exception as e:
                        print(f"[FW][WARN] Loi khi mo chan {ip}: {e}")

            # Tu dong kiem tra lai (Anti-tamper) moi 30s de dam bao cac luat chan khong bi xoa thu cong
            now = time.time()
            if now - last_integrity_check >= 30.0:
                last_integrity_check = now
                for ip in list(blocked):
                    if not rule_exists(ip):
                        add_rule(ip)
                        print(f"[FW] Khoi phuc luat chan bi mat cho: {ip}")

        except Exception as e:
            print(f"[FW][WARN] Loi vong lap: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()