import os
import time
import socket
import subprocess
from datetime import datetime, timezone

import mysql.connector
from dateutil import parser as dtparser


POLL_INTERVAL = float(os.getenv("FW_POLL_INTERVAL", "1.0"))  # seconds
DRY_RUN = os.getenv("FW_DRY_RUN", "false").lower() == "true"

# DB env (match backend defaults)
DB_USER = os.getenv("DB_USER", "tls_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "tls_pass")
DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "tls_ids")

# Firewall target
FIREWALL_TARGET = os.getenv("FIREWALL_TARGET", "iptables").lower()
IPTABLES_CHAIN = os.getenv("IPTABLES_CHAIN", "INPUT")  # INPUT by default


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)  # store naive like MySQL DATETIME


def db_connect():
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=False,
    )


def is_ip(ip: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except OSError:
        return False


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    if DRY_RUN:
        return 0, "[DRY_RUN] " + " ".join(cmd), ""
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def iptables_rule_exists(src_ip: str) -> bool:
    # iptables -C INPUT -s <ip> -j DROP
    code, _, _ = run_cmd(["iptables", "-C", IPTABLES_CHAIN, "-s", src_ip, "-j", "DROP"])
    return code == 0


def iptables_block(src_ip: str):
    # Insert at top
    if iptables_rule_exists(src_ip):
        return
    code, out, err = run_cmd(["iptables", "-I", IPTABLES_CHAIN, "1", "-s", src_ip, "-j", "DROP"])
    if code != 0:
        raise RuntimeError(f"iptables block failed: {err or out}")


def iptables_unblock(src_ip: str):
    # Delete rule if exists
    if not iptables_rule_exists(src_ip):
        return
    code, out, err = run_cmd(["iptables", "-D", IPTABLES_CHAIN, "-s", src_ip, "-j", "DROP"])
    if code != 0:
        raise RuntimeError(f"iptables unblock failed: {err or out}")


def execute_action(action_type: str, src_ip: str, target: str | None):
    target = (target or FIREWALL_TARGET).lower()

    if target != "iptables":
        raise RuntimeError(f"Unsupported target: {target} (only iptables implemented)")

    if not is_ip(src_ip):
        raise RuntimeError(f"Invalid IP: {src_ip}")

    if action_type == "BLOCK":
        iptables_block(src_ip)
    elif action_type == "UNBLOCK":
        iptables_unblock(src_ip)
    else:
        raise RuntimeError(f"Unknown action_type: {action_type}")


def fetch_pending_actions(conn, limit: int = 50):
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT id, src_ip, action_type, target, expires_at
        FROM firewall_actions
        WHERE status = 'PENDING'
        ORDER BY created_at ASC
        LIMIT %s
        """,
        (limit,),
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def mark_executed(conn, action_id: int):
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE firewall_actions
        SET status='EXECUTED', executed_at=%s, error_message=NULL
        WHERE id=%s
        """,
        (utc_now(), action_id),
    )
    cur.close()


def mark_failed(conn, action_id: int, error_message: str):
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE firewall_actions
        SET status='FAILED', executed_at=%s, error_message=%s
        WHERE id=%s
        """,
        (utc_now(), error_message[:2000], action_id),
    )
    cur.close()


def is_expired(expires_at) -> bool:
    if not expires_at:
        return False
    # mysql-connector may return datetime already; support str too
    if isinstance(expires_at, str):
        dt = dtparser.parse(expires_at)
    else:
        dt = expires_at
    return dt <= utc_now()


def main():
    print("[FW] Firewall Controller starting...")
    print(f"[FW] DB={DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME} target={FIREWALL_TARGET} chain={IPTABLES_CHAIN}")
    print(f"[FW] DRY_RUN={DRY_RUN} POLL_INTERVAL={POLL_INTERVAL}s")

    while True:
        try:
            conn = db_connect()
        except Exception as e:
            print(f"[FW][WARN] DB connect failed: {e}")
            time.sleep(2.0)
            continue

        try:
            actions = fetch_pending_actions(conn)
            if actions:
                print(f"[FW] Pending actions: {len(actions)}")

            for a in actions:
                aid = int(a["id"])
                src_ip = a["src_ip"]
                action_type = a["action_type"]
                target = a.get("target")
                expires_at = a.get("expires_at")

                if is_expired(expires_at):
                    # nếu action đã hết hạn thì mark FAILED để khỏi chạy mãi
                    try:
                        mark_failed(conn, aid, "Expired before execution")
                        conn.commit()
                    except Exception as e:
                        conn.rollback()
                        print(f"[FW][WARN] mark_failed(expired) action_id={aid}: {e}")
                    continue

                try:
                    execute_action(action_type, src_ip, target)
                    mark_executed(conn, aid)
                    conn.commit()
                    print(f"[FW][OK] {action_type} {src_ip} (id={aid})")
                except Exception as e:
                    conn.rollback()
                    try:
                        mark_failed(conn, aid, str(e))
                        conn.commit()
                    except Exception as e2:
                        conn.rollback()
                        print(f"[FW][ERROR] Cannot mark FAILED id={aid}: {e2}")
                    print(f"[FW][FAIL] id={aid} {action_type} {src_ip}: {e}")

        except Exception as e:
            print(f"[FW][WARN] loop error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
