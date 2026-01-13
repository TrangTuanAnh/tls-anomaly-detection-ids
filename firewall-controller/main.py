# firewall-controller/main.py
from __future__ import annotations

import os
import time
import subprocess
from typing import Dict, Set, Tuple, Optional

import mysql.connector
from mysql.connector import pooling
from dateutil import parser as dtparser

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "tls_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "tls_ids")

IPTABLES_CHAIN = os.getenv("IPTABLES_CHAIN", "FORWARD")
FIREWALL_TARGET = os.getenv("FIREWALL_TARGET", "DROP")  # DROP / REJECT
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1.0"))

FW_DRY_RUN = os.getenv("FW_DRY_RUN", "false").lower() == "true"

# MySQL TLS (optional)
DB_TLS_ENABLED = os.getenv("DB_TLS_ENABLED", "false").lower() == "true"
DB_SSL_CA = os.getenv("DB_SSL_CA", "")
DB_SSL_CERT = os.getenv("DB_SSL_CERT", "")
DB_SSL_KEY = os.getenv("DB_SSL_KEY", "")
DB_SSL_VERIFY_CERT = os.getenv("DB_SSL_VERIFY_CERT", "true").lower() == "true"


def _iptables(args: list[str]) -> Tuple[int, str]:
    cmd = ["iptables"] + args
    if FW_DRY_RUN:
        return 0, "[DRY_RUN] " + " ".join(cmd)

    p = subprocess.run(cmd, capture_output=True, text=True)
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out.strip()


def ensure_chain_exists() -> None:
    # create chain if not exists (best effort); for built-in chains, it's fine.
    # We won't create FORWARD/INPUT/OUTPUT.
    pass


def rule_exists(ip: str) -> bool:
    rc, _ = _iptables(["-C", IPTABLES_CHAIN, "-s", ip, "-j", FIREWALL_TARGET])
    return rc == 0


def add_rule(ip: str) -> None:
    if rule_exists(ip):
        return
    rc, out = _iptables(["-I", IPTABLES_CHAIN, "1", "-s", ip, "-j", FIREWALL_TARGET])
    if rc != 0:
        raise RuntimeError(out)


def del_rule(ip: str) -> None:
    # delete all matching rules (loop until not found)
    while True:
        rc, out = _iptables(["-D", IPTABLES_CHAIN, "-s", ip, "-j", FIREWALL_TARGET])
        if rc != 0:
            break


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
        cfg["ssl_ca"] = DB_SSL_CA or None
        cfg["ssl_cert"] = DB_SSL_CERT or None
        cfg["ssl_key"] = DB_SSL_KEY or None
        cfg["ssl_verify_cert"] = DB_SSL_VERIFY_CERT

    return pooling.MySQLConnectionPool(pool_name="fwpool", pool_size=3, **cfg)


def bootstrap_blocklist(conn) -> Set[str]:
    """Compute current blocklist by replaying actions in DB."""
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
    print(f"[FW] start firewall-controller (dry_run={FW_DRY_RUN})")
    print(f"[FW] db={DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME} chain={IPTABLES_CHAIN} target={FIREWALL_TARGET}")

    pool = make_pool()

    with pool.get_connection() as conn:
        blocked, last_id = bootstrap_blocklist(conn)

    # Apply bootstrap rules
    for ip in sorted(blocked):
        try:
            add_rule(ip)
            print(f"[FW] bootstrap BLOCK {ip}")
        except Exception as e:
            print(f"[FW][WARN] bootstrap failed {ip}: {e}")

    # Poll loop
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
                        print(f"[FW] BLOCK {ip} (id={last_id})")
                    except Exception as e:
                        print(f"[FW][WARN] block failed {ip}: {e}")
                elif act == "UNBLOCK":
                    try:
                        del_rule(ip)
                        blocked.discard(ip)
                        print(f"[FW] UNBLOCK {ip} (id={last_id})")
                    except Exception as e:
                        print(f"[FW][WARN] unblock failed {ip}: {e}")

            # Integrity check: ensure rules still exist (anti-tamper) every 30s
            if int(time.time()) % 30 == 0:
                for ip in list(blocked):
                    if not rule_exists(ip):
                        try:
                            add_rule(ip)
                            print(f"[FW] re-add missing rule for {ip}")
                        except Exception as e:
                            print(f"[FW][WARN] re-add failed {ip}: {e}")

        except Exception as e:
            print(f"[FW][WARN] loop error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
