import os
import time
import socket
import subprocess
import hmac
import hashlib
import shutil
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
IPTABLES_CHAIN = os.getenv("IPTABLES_CHAIN", "FORWARD")  # FORWARD if firewall is gateway

# iptables binaries (to avoid nft/legacy mismatch if needed)
IPTABLES_BIN_V4 = os.getenv("IPTABLES_BIN_V4", "iptables")
IPTABLES_BIN_V6 = os.getenv("IPTABLES_BIN_V6", "ip6tables")
IPTABLES_WAIT = os.getenv("IPTABLES_WAIT", "true").lower() == "true"  # add -w to avoid lock errors

# "Cut session" support
FW_KILL_CONNTRACK = os.getenv("FW_KILL_CONNTRACK", "true").lower() == "true"

# Integrity (backend -> firewall-controller)
FW_ACTION_HMAC_SECRET = os.getenv("FW_ACTION_HMAC_SECRET", "")
ALLOW_UNSIGNED_FW_ACTIONS = os.getenv("ALLOW_UNSIGNED_FW_ACTIONS", "false").lower() == "true"
FW_ACTION_MAX_AGE_SEC = int(os.getenv("FW_ACTION_MAX_AGE_SEC", "86400"))  # 24h

# Reconcilation: phát hiện rule iptables bị thêm thủ công ngoài hệ thống
FW_RECONCILE_INTERVAL_SEC = float(os.getenv("FW_RECONCILE_INTERVAL_SEC", "60"))
FW_RECONCILE_REMOVE_UNKNOWN = os.getenv("FW_RECONCILE_REMOVE_UNKNOWN", "false").lower() == "true"


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


def is_ipv4(ip: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        return False


def is_ipv6(ip: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except OSError:
        return False


def is_ip(ip: str) -> bool:
    return is_ipv4(ip) or is_ipv6(ip)


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    if DRY_RUN:
        return 0, "[DRY_RUN] " + " ".join(cmd), ""
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def ipt_bin_for_ip(ip: str) -> str:
    if is_ipv6(ip):
        return IPTABLES_BIN_V6
    return IPTABLES_BIN_V4


def ipt(ip: str, *args: str) -> list[str]:
    """
    Build iptables/ip6tables command; add -w if enabled to avoid xtables lock issue.
    """
    bin_ = ipt_bin_for_ip(ip)
    if IPTABLES_WAIT:
        return [bin_, "-w", *args]
    return [bin_, *args]


def rule_exists(cmd: list[str]) -> bool:
    code, _, _ = run_cmd(cmd)
    return code == 0


def kill_conntrack(ip: str):
    """
    Best-effort: delete conntrack entries so established sessions drop faster.
    Works only if conntrack tool exists and container has needed privileges.
    """
    if not FW_KILL_CONNTRACK:
        return
    if shutil.which("conntrack") is None:
        print("[FW][WARN] conntrack not installed -> cannot actively drop existing sessions")
        return

    # delete entries by source and destination
    for args in (["conntrack", "-D", "-s", ip], ["conntrack", "-D", "-d", ip]):
        code, out, err = run_cmd(args)
        # conntrack returns non-zero if nothing to delete; don't treat as fatal
        msg = (err or out or "").lower()
        if code != 0 and ("0 flow entries" not in msg) and ("no such file" not in msg):
            print(f"[FW][WARN] conntrack delete issue for {ip}: {err or out}")


# -----------------------------
# IPTABLES: block/unblock 2-way + cut TCP sessions
# -----------------------------

def iptables_block(ip: str):
    """
    Block 2 chiều + ngắt phiên TCP:
      - TCP: REJECT tcp-reset cho cả -s và -d (đứt nhanh)
      - All proto: DROP cho cả -s và -d (chặn chắc)
      - Xóa conntrack (best-effort) để dập session đang ESTABLISHED
    """
    if not is_ip(ip):
        raise RuntimeError(f"Invalid IP: {ip}")

    # kill sessions first (best-effort)
    kill_conntrack(ip)

    # Desired top-down order (final):
    # 1) -s ip -p tcp REJECT tcp-reset
    # 2) -d ip -p tcp REJECT tcp-reset
    # 3) -s ip DROP
    # 4) -d ip DROP
    #
    # To get that order, insert reverse with -I 1.
    checks = [
        ipt(ip, "-C", IPTABLES_CHAIN, "-s", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"),
        ipt(ip, "-C", IPTABLES_CHAIN, "-d", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"),
        ipt(ip, "-C", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"),
        ipt(ip, "-C", IPTABLES_CHAIN, "-d", ip, "-j", "DROP"),
    ]

    inserts = [
        ipt(ip, "-I", IPTABLES_CHAIN, "1", "-d", ip, "-j", "DROP"),
        ipt(ip, "-I", IPTABLES_CHAIN, "1", "-s", ip, "-j", "DROP"),
        ipt(ip, "-I", IPTABLES_CHAIN, "1", "-d", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"),
        ipt(ip, "-I", IPTABLES_CHAIN, "1", "-s", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"),
    ]

    # Insert in reverse-check order so final rules end up in the desired order
    for chk, ins in zip(reversed(checks), inserts):
        if not rule_exists(chk):
            code, out, err = run_cmd(ins)
            if code != 0:
                raise RuntimeError(f"iptables insert failed: {err or out}")


def iptables_unblock(ip: str):
    """
    Remove both directions and both kinds of rules.
    Use while loops to clean duplicates if they exist.
    """
    if not is_ip(ip):
        raise RuntimeError(f"Invalid IP: {ip}")

    # Exact match check+delete pairs
    pairs = [
        (
            ipt(ip, "-C", IPTABLES_CHAIN, "-s", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"),
            ipt(ip, "-D", IPTABLES_CHAIN, "-s", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"),
        ),
        (
            ipt(ip, "-C", IPTABLES_CHAIN, "-d", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"),
            ipt(ip, "-D", IPTABLES_CHAIN, "-d", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"),
        ),
        (
            ipt(ip, "-C", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"),
            ipt(ip, "-D", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"),
        ),
        (
            ipt(ip, "-C", IPTABLES_CHAIN, "-d", ip, "-j", "DROP"),
            ipt(ip, "-D", IPTABLES_CHAIN, "-d", ip, "-j", "DROP"),
        ),
    ]

    for chk, dele in pairs:
        while rule_exists(chk):
            code, out, err = run_cmd(dele)
            if code != 0:
                raise RuntimeError(f"iptables delete failed: {err or out}")


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


# -----------------------------
# DB fetch + HMAC verify
# -----------------------------

def fetch_pending_actions(conn, limit: int = 50):
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT id, src_ip, action_type, target, expires_at, hmac_ts, hmac_nonce, hmac_sig
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


def verify_action_hmac(action_type: str, src_ip: str, hmac_ts, hmac_nonce, hmac_sig) -> None:
    """Raise RuntimeError if signature invalid.

    Message format must match backend.sign_firewall_action():
      f"{action_type}|{src_ip}|{ts}|{nonce}"
    """
    if not FW_ACTION_HMAC_SECRET:
        if ALLOW_UNSIGNED_FW_ACTIONS:
            return
        raise RuntimeError("FW_ACTION_HMAC_SECRET not configured")

    if not (hmac_ts and hmac_nonce and hmac_sig):
        if ALLOW_UNSIGNED_FW_ACTIONS:
            return
        raise RuntimeError("Missing firewall action signature fields")

    try:
        ts = int(hmac_ts)
    except Exception:
        raise RuntimeError("Invalid hmac_ts")

    now = int(time.time())
    if ts <= 0 or abs(now - ts) > FW_ACTION_MAX_AGE_SEC:
        raise RuntimeError("Signature expired")

    msg = f"{action_type}|{src_ip}|{ts}|{hmac_nonce}".encode("utf-8")
    expected = hmac.new(FW_ACTION_HMAC_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(hmac_sig).strip().lower()):
        raise RuntimeError("Invalid signature")


# -----------------------------
# Reconcile logic updated for 2-way + REJECT/DROP
# -----------------------------

def iptables_list_blocked_ips() -> set[str]:
    """
    Parse rules in IPTABLES_CHAIN to find IPs blocked by either:
      - -s ip -j DROP / REJECT
      - -d ip -j DROP / REJECT
    Works for both iptables and ip6tables by parsing from the v4 binary output only.
    (If you use IPv6 blocks, keep IPTABLES_BIN_V6 consistent with host.)
    """
    # list rules from v4 binary (covers most cases). If you want full v6 reconcile, run both.
    code, out, err = run_cmd([IPTABLES_BIN_V4, "-S", IPTABLES_CHAIN])
    if code != 0:
        raise RuntimeError(f"iptables -S failed: {err or out}")

    blocked: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if "-j" not in parts:
            continue
        try:
            j_idx = parts.index("-j")
            target = parts[j_idx + 1]
            if target not in ("DROP", "REJECT"):
                continue

            for flag in ("-s", "-d"):
                if flag in parts:
                    idx = parts.index(flag)
                    val = parts[idx + 1]
                    ip = val.split("/")[0]
                    if is_ip(ip):
                        blocked.add(ip)
        except Exception:
            continue

    return blocked


def db_current_blocked_ips(conn, limit: int = 5000) -> set[str]:
    """Tính trạng thái cuối cùng của từng IP dựa trên lịch sử EXECUTED."""
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT src_ip, action_type, executed_at
        FROM firewall_actions
        WHERE status='EXECUTED' AND executed_at IS NOT NULL
        ORDER BY executed_at ASC
        LIMIT %s
        """,
        (limit,),
    )
    rows = cur.fetchall()
    cur.close()

    state: dict[str, str] = {}
    for r in rows:
        state[r["src_ip"]] = r["action_type"]

    return {ip for ip, last in state.items() if last == "BLOCK"}


def reconcile_iptables(conn) -> None:
    """Detect (and optionally remove) iptables rules not reflected in DB."""
    try:
        blocked_db = db_current_blocked_ips(conn)
        blocked_fw = iptables_list_blocked_ips()
        extra = blocked_fw - blocked_db
        if extra:
            print(f"[FW][WARN] Unauthorized/unknown iptables block rules: {sorted(extra)[:20]}")
            if FW_RECONCILE_REMOVE_UNKNOWN:
                for ip in extra:
                    try:
                        iptables_unblock(ip)
                        print(f"[FW][OK] Removed unknown block rules for {ip}")
                    except Exception as e:
                        print(f"[FW][WARN] Cannot remove unknown rules {ip}: {e}")
    except Exception as e:
        print(f"[FW][WARN] reconcile failed: {e}")


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
    print(f"[FW] IPTABLES_BIN_V4={IPTABLES_BIN_V4} IPTABLES_BIN_V6={IPTABLES_BIN_V6} WAIT={IPTABLES_WAIT}")
    print(f"[FW] CUT_SESSION: tcp-reset + conntrack={FW_KILL_CONNTRACK} (best-effort)")

    last_reconcile = 0.0

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

                # verify integrity before executing
                try:
                    verify_action_hmac(
                        action_type=action_type,
                        src_ip=src_ip,
                        hmac_ts=a.get("hmac_ts"),
                        hmac_nonce=a.get("hmac_nonce"),
                        hmac_sig=a.get("hmac_sig"),
                    )
                except Exception as e:
                    conn.rollback()
                    try:
                        mark_failed(conn, aid, f"Integrity check failed: {e}")
                        conn.commit()
                    except Exception as e2:
                        conn.rollback()
                        print(f"[FW][ERROR] Cannot mark FAILED id={aid}: {e2}")
                    print(f"[FW][FAIL] id={aid} rejected by integrity check: {e}")
                    continue

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

        # periodic reconciliation
        now = time.time()
        if now - last_reconcile >= FW_RECONCILE_INTERVAL_SEC:
            try:
                conn2 = db_connect()
                try:
                    reconcile_iptables(conn2)
                finally:
                    conn2.close()
            except Exception as e:
                print(f"[FW][WARN] reconcile loop DB error: {e}")
            last_reconcile = now

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
