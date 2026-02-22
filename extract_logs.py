#!/usr/bin/env python3
# =========================================
# File: ssh-monitor/extract_logs.py
# Task 8: store only useful logs (SSH auth + Apache login/admin/suspicious)
# Cursor-based ingestion (NO hash) + SSH event parsing
# + FTP: ingest /var/log/vsftpd.log into logs table
# + FTP brute-force rule: >=5 real auth failures from same IP within 60s -> SEVERITY=HIGH (tagged in message)
#
# FIXES INCLUDED:
# ✅ FTP uses REAL vsftpd timestamp (not datetime.now)
# ✅ FTP severity always uppercase (LOW/HIGH)
# ✅ Optional FTP noise filter (default ON: keep only useful FTP events)
# =========================================

from __future__ import annotations

import os
import re
import glob
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Iterable, Optional, Tuple
from collections import defaultdict

import psycopg2

# ---------------------------
# DB / runtime config
# ---------------------------

DB_NAME = os.environ.get("DB_NAME", "logdb")
DB_USER = os.environ.get("DB_USER", "hero")
DB_PASS = os.environ.get("DB_PASS", "hero")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))

# Default agent label for this script (SSH ingestion)
AGENT_NAME = os.environ.get("AGENT_NAME", "SSH").strip()
if AGENT_NAME.lower() == "raven":
    AGENT_NAME = "SSH"

LOG_LIMIT = int(os.environ.get("LOG_LIMIT", "20000"))

# Noisy in many systems; keep off by default
INCLUDE_SSH_SESSION_EVENTS = os.environ.get("INCLUDE_SSH_SESSION_EVENTS", "0").strip() != "0"

# Cursor behaviors
FIRST_RUN_START_AT_END = os.environ.get("FIRST_RUN_START_AT_END", "0").strip() != "0"
ON_ROTATION_START_AT_END = os.environ.get("ON_ROTATION_START_AT_END", "1").strip() != "0"

# Watch only these logs (Option A) + FTP
AUTH_GLOB = "/var/log/auth.log*"
APACHE_ACCESS_GLOB = "/var/log/apache2/access.log*"
APACHE_ERROR_GLOB = "/var/log/apache2/error.log*"
VSFTPD_LOG = "/var/log/vsftpd.log"  # <-- FTP protocol log

WATCH_GLOBS = (AUTH_GLOB, APACHE_ACCESS_GLOB, APACHE_ERROR_GLOB, VSFTPD_LOG)

AUTH_PREFIX = "auth.log"
ACCESS_PREFIX = "access.log"
ERROR_PREFIX = "error.log"
VSFTPD_BASENAME = "vsftpd.log"

# Tunables for “useful web traffic”
WEB_KEEP_KEYWORDS = tuple(
    x.strip().lower()
    for x in os.environ.get(
        "WEB_KEEP_KEYWORDS",
        "/login,/logout,/signin,/signout,/admin,/wp-login.php,/phpmyadmin,/phppgadmin,/wp-admin",
    ).split(",")
    if x.strip()
)
WEB_KEEP_STATUSES = set(
    int(x.strip())
    for x in os.environ.get("WEB_KEEP_STATUSES", "401,403,404,429,500,501,502,503,504").split(",")
    if x.strip().isdigit()
)
WEB_KEEP_POST_ALWAYS = os.environ.get("WEB_KEEP_POST_ALWAYS", "0").strip() != "0"
MAX_UA_LEN = int(os.environ.get("MAX_UA_LEN", "240"))

# ---------------------------
# FTP brute-force tracker (in-memory per run)
# ---------------------------
ftp_fail_tracker = defaultdict(list)  # ip -> [datetime, datetime, ...]

# Optional FTP noise filtering (recommended ON by default)
# If INCLUDE_FTP_NOISE=1, we ingest every vsftpd line (can flood DB).
INCLUDE_FTP_NOISE = os.environ.get("INCLUDE_FTP_NOISE", "0").strip() != "0"

# “Useful” FTP signals to keep when noise filter is ON
_FTP_KEEP_NEEDLES = (
    "FAIL LOGIN",
    "OK LOGIN",
    "530 Login incorrect",
    "UPLOAD",
    "DOWNLOAD",
    "FAIL UPLOAD",
    "FAIL DOWNLOAD",
    "FAIL DELETE",
    "FAIL RENAME",
    "FAIL MKDIR",
    "FAIL RMDIR",
    # command keywords (often appear in FTP command lines)
    "STOR ",
    "RETR ",
    "DELE ",
    "RNFR ",
    "RNTO ",
    "MKD ",
    "RMD ",
)

# ---------------------------
# Shared helpers
# ---------------------------

def _safe_strip(s: str) -> str:
    return (s or "").replace("\x00", "").strip()


def _clean_ip(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    ip = raw.strip()
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None


def _norm_user(u: Optional[str]) -> Optional[str]:
    if not u:
        return None
    u = u.strip()
    if not u:
        return None
    if "(" in u:
        u = u.split("(", 1)[0].strip()
    return u or None


# ---------------------------
# SSH/auth.log: normalize + keep only useful
# ---------------------------

_RE_ISO_PREFIX = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
)
_RE_HOST_PREFIX = re.compile(r"^[A-Za-z0-9_.-]+\s+(?=\w+\[\d+\]:)")
_RE_MSG_REPEATED = re.compile(
    r"message repeated\s+(?P<count>\d+)\s+times:\s+\[(?P<inner>.*)\]$",
    re.IGNORECASE,
)

DROP_IF_CONTAINS_SSH = (
    "server listening on :: port 22",
    "server listening on 0.0.0.0 port 22",
)

_AUTH_KEEP_RE = re.compile(
    r"(Accepted\s+|Failed\s+(?:password|publickey)\s+|Invalid\s+user\s+|pam_unix\(sshd:auth\):\s+authentication\s+failure|"
    r"PAM\s+\d+\s+more\s+authentication\s+failures|maximum authentication attempts exceeded|"
    r"Connection\s+reset\s+by\s+authenticating\s+user|Received\s+disconnect\s+from|Disconnected\s+from\s+user|"
    r"Connection\s+closed|Did not receive identification string)",
    re.IGNORECASE,
)
_AUTH_SESSION_RE = re.compile(
    r"pam_unix\(sshd:session\):\s+session\s+(opened|closed)\s+for\s+user",
    re.IGNORECASE,
)

def _parse_time_from_line_iso(line: str) -> Optional[datetime]:
    m = _RE_ISO_PREFIX.match(line or "")
    if not m:
        return None
    iso = m.group("iso")
    try:
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso)
        return dt.replace(tzinfo=None)
    except Exception:
        return None


def normalize_auth_message(raw_line: str) -> str:
    msg = _safe_strip(raw_line)
    if not msg:
        return ""

    m_rep = _RE_MSG_REPEATED.search(msg)
    if m_rep:
        count = m_rep.group("count")
        inner = m_rep.group("inner")
        inner_norm = normalize_auth_message(inner)
        return f"repeated {count}x: {inner_norm}"

    msg = _RE_ISO_PREFIX.sub("", msg)
    msg = _RE_HOST_PREFIX.sub("", msg)
    return msg.strip()


def should_store_auth_message(normalized_msg: str) -> bool:
    msg_l = (normalized_msg or "").lower()
    if not msg_l:
        return False

    for s in DROP_IF_CONTAINS_SSH:
        if s in msg_l:
            return False

    if _AUTH_SESSION_RE.search(normalized_msg):
        return INCLUDE_SSH_SESSION_EVENTS

    return bool(_AUTH_KEEP_RE.search(normalized_msg))


# ---------------------------
# SSH event parsing (structured table)
# ---------------------------

_SSHD_PREFIX = r"(?:sshd\[\d+\]:\s+)?"

_RE_ACCEPTED = re.compile(
    _SSHD_PREFIX + r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_FAILED_PASSWORD = re.compile(
    _SSHD_PREFIX + r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_FAILED_PUBLICKEY = re.compile(
    _SSHD_PREFIX + r"Failed\s+publickey\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_INVALID_USER = re.compile(
    _SSHD_PREFIX + r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_PAM_AUTH_FAIL = re.compile(
    r"pam_unix\(sshd:auth\):\s+authentication\s+failure;.*rhost=(?P<ip>\S+).*user=(?P<user>\S*)",
    re.IGNORECASE,
)
_RE_PAM_MORE_FAIL = re.compile(
    r"PAM\s+\d+\s+more\s+authentication\s+failures;.*rhost=(?P<ip>\S+).*user=(?P<user>\S*)",
    re.IGNORECASE,
)
_RE_CONN_RESET_PREAUTH = re.compile(
    _SSHD_PREFIX + r"Connection\s+reset\s+by\s+authenticating\s+user\s+(?P<user>\S+)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)\s+\[preauth\]",
    re.IGNORECASE,
)
_RE_RECEIVED_DISCONNECT = re.compile(
    _SSHD_PREFIX + r"Received\s+disconnect\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_DISCONNECTED_FROM_USER = re.compile(
    _SSHD_PREFIX + r"Disconnected\s+from\s+user\s+(?P<user>\S+)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_CONN_CLOSED = re.compile(
    _SSHD_PREFIX + r"(?:Connection\s+closed|Disconnected\s+from)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
_RE_NO_IDENT = re.compile(
    _SSHD_PREFIX + r"Did not receive identification string from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
_RE_SESSION_OPEN = re.compile(
    _SSHD_PREFIX + r"pam_unix\(sshd:session\):\s+session\s+opened\s+for\s+user\s+(?P<user>\S+)",
    re.IGNORECASE,
)
_RE_SESSION_CLOSE = re.compile(
    _SSHD_PREFIX + r"pam_unix\(sshd:session\):\s+session\s+closed\s+for\s+user\s+(?P<user>\S+)",
    re.IGNORECASE,
)

def parse_ssh_event(message: str) -> Optional[dict]:
    msg = message or ""

    m = _RE_ACCEPTED.search(msg)
    if m:
        return {
            "event_type": "login_success",
            "outcome": "success",
            "auth_method": (m.group("method") or "unknown").lower(),
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_FAILED_PASSWORD.search(msg)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "password",
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_FAILED_PUBLICKEY.search(msg)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "publickey",
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_INVALID_USER.search(msg)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "unknown",
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_PAM_AUTH_FAIL.search(msg) or _RE_PAM_MORE_FAIL.search(msg)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "unknown",
            "username": _norm_user(m.group("user") or None),
            "ip": _clean_ip(m.group("ip")),
            "port": None,
        }

    m = _RE_CONN_RESET_PREAUTH.search(msg)
    if m:
        return {
            "event_type": "login_fail",
            "outcome": "fail",
            "auth_method": "unknown",
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_DISCONNECTED_FROM_USER.search(msg)
    if m:
        return {
            "event_type": "disconnect",
            "outcome": "info",
            "auth_method": None,
            "username": _norm_user(m.group("user")),
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_RECEIVED_DISCONNECT.search(msg) or _RE_CONN_CLOSED.search(msg)
    if m:
        return {
            "event_type": "disconnect",
            "outcome": "info",
            "auth_method": None,
            "username": None,
            "ip": _clean_ip(m.group("ip")),
            "port": int(m.group("port")),
        }

    m = _RE_NO_IDENT.search(msg)
    if m:
        return {
            "event_type": "disconnect",
            "outcome": "info",
            "auth_method": None,
            "username": None,
            "ip": _clean_ip(m.group("ip")),
            "port": None,
        }

    if INCLUDE_SSH_SESSION_EVENTS:
        m = _RE_SESSION_OPEN.search(msg)
        if m:
            return {
                "event_type": "session_open",
                "outcome": "info",
                "auth_method": None,
                "username": _norm_user(m.group("user")),
                "ip": None,
                "port": None,
            }
        m = _RE_SESSION_CLOSE.search(msg)
        if m:
            return {
                "event_type": "session_close",
                "outcome": "info",
                "auth_method": None,
                "username": _norm_user(m.group("user")),
                "ip": None,
                "port": None,
            }

    return None


# ---------------------------
# Apache access parsing + keep rules
# ---------------------------

_APACHE_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)
_APACHE_COMMON_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+'
)

_RE_APACHE_ERROR_SEV = re.compile(r"\[(error|crit|alert|emerg)\]", re.IGNORECASE)

def _parse_apache_time(ts_raw: str) -> Optional[datetime]:
    # 10/Oct/2000:13:55:36 -0700
    try:
        ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
        # store naive UTC-ish to keep ordering stable
        return ts.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    except Exception:
        return None

def parse_apache_access(line: str) -> Optional[dict]:
    raw = _safe_strip(line)
    if not raw:
        return None
    m = _APACHE_COMBINED_RE.match(raw) or _APACHE_COMMON_RE.match(raw)
    if not m:
        return None
    ts = _parse_apache_time(m.group("ts")) or datetime.now()
    ua = (m.groupdict().get("ua") or "").strip()
    if len(ua) > MAX_UA_LEN:
        ua = ua[:MAX_UA_LEN] + "…"
    return {
        "dt": ts,
        "ip": m.group("ip"),
        "method": (m.group("method") or "").upper(),
        "url": (m.group("url") or ""),
        "status": int(m.group("status")),
        "ua": ua,
        "raw": raw,
    }

def should_store_apache_access(parsed: dict) -> bool:
    url_l = (parsed.get("url") or "").lower()
    method = (parsed.get("method") or "").upper()
    status = int(parsed.get("status") or 0)

    keyword_hit = any(k in url_l for k in WEB_KEEP_KEYWORDS)
    status_hit = status in WEB_KEEP_STATUSES or (500 <= status <= 599)

    if WEB_KEEP_POST_ALWAYS and method == "POST":
        return True

    # keep sensitive URLs always; keep suspicious status always
    if keyword_hit or status_hit:
        return True

    # keep POST to sensitive urls even if status not suspicious
    if method == "POST" and keyword_hit:
        return True

    return False


# ---------------------------
# vsftpd timestamp parsing (FIX)
# ---------------------------

_RE_VSFTPD_TS = re.compile(
    r"^(?P<dow>\w+)\s+(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<year>\d{4})"
)
_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

def _parse_vsftpd_time(line: str) -> Optional[datetime]:
    m = _RE_VSFTPD_TS.match(line or "")
    if not m:
        return None
    mon = _MONTHS.get(m.group("mon"))
    if not mon:
        return None
    hh, mm, ss = map(int, m.group("time").split(":"))
    return datetime(int(m.group("year")), mon, int(m.group("day")), hh, mm, ss)


# ---------------------------
# Cursor ingestion / DB
# ---------------------------

@dataclass(frozen=True)
class CursorState:
    inode: Optional[int]
    byte_offset: int

def get_conn():
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT
    )

def upsert_agent_heartbeat(conn, agent: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.agent_status (agent_name, last_heartbeat)
            VALUES (%s, NOW())
            ON CONFLICT (agent_name)
            DO UPDATE SET last_heartbeat = NOW();
            """,
            (agent,),
        )

def agent_for_path(path: str) -> str:
    base = os.path.basename(path)
    if base.startswith(AUTH_PREFIX):
        return "SSH"
    if base.startswith(ACCESS_PREFIX) or base.startswith(ERROR_PREFIX):
        return "APACHE"
    if base == VSFTPD_BASENAME:
        return "FTP"
    return AGENT_NAME

def load_cursor(conn, path: str) -> CursorState:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT inode, byte_offset
            FROM public.log_cursors
            WHERE agent_name = %s AND path = %s;
            """,
            (AGENT_NAME, path),
        )
        row = cur.fetchone()
    if not row:
        return CursorState(inode=None, byte_offset=0)
    inode, byte_offset = row
    return CursorState(inode=int(inode) if inode is not None else None, byte_offset=int(byte_offset or 0))

def save_cursor(conn, path: str, inode: Optional[int], byte_offset: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.log_cursors (agent_name, path, inode, byte_offset, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (agent_name, path)
            DO UPDATE SET inode = EXCLUDED.inode,
                          byte_offset = EXCLUDED.byte_offset,
                          updated_at = NOW();
            """,
            (AGENT_NAME, path, inode, int(byte_offset)),
        )
    conn.commit()

def compute_start(prev: CursorState, current_inode: Optional[int], current_size: int) -> int:
    if prev.inode is None:
        return current_size if FIRST_RUN_START_AT_END else 0

    rotated_or_truncated = (
        (current_inode is not None and prev.inode != current_inode) or current_size < prev.byte_offset
    )
    if rotated_or_truncated:
        return current_size if ON_ROTATION_START_AT_END else 0

    return min(prev.byte_offset, current_size)

def insert_log_row(
    conn,
    file_path: str,
    log_time: datetime,
    message: str,
    agent_name: Optional[str] = None,
) -> Optional[int]:

    agent = agent_name or AGENT_NAME

    # 🔥 Update heartbeat for the actual agent inserting logs
    upsert_agent_heartbeat(conn, agent)

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.logs (filename, log_time, source, message, agent_name)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (os.path.basename(file_path), log_time, file_path, message, agent),
        )
        return int(cur.fetchone()[0])

def insert_ssh_event(conn, log_id: Optional[int], event_time: datetime, ev: dict, raw: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.ssh_events
              (log_id, agent_name, event_time, event_type, outcome, auth_method, username, ip, port, raw)
            VALUES
              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (log_id) DO NOTHING;
            """,
            (
                log_id,
                AGENT_NAME,
                event_time,
                ev["event_type"],
                ev.get("outcome"),
                ev.get("auth_method"),
                ev.get("username"),
                ev.get("ip"),
                ev.get("port"),
                raw,
            ),
        )

def iter_watch_files() -> Iterable[str]:
    seen = set()
    for pattern in WATCH_GLOBS:
        for path in glob.glob(pattern):
            if path in seen:
                continue
            seen.add(path)
            if path.endswith((".gz", ".xz", ".zip")):
                continue
            if os.path.isfile(path):
                yield path

def ingest_file(conn, path: str) -> Tuple[int, int]:
    """
    returns (inserted_logs, dropped_lines)
    """
    try:
        st = os.stat(path)
        inode = int(st.st_ino)
        size = int(st.st_size)
    except Exception:
        return (0, 0)

    prev = load_cursor(conn, path)
    start = compute_start(prev, inode, size)

    inserted = 0
    dropped = 0
    base = os.path.basename(path)
    upsert_agent_heartbeat(conn, agent_for_path(path))# heartbeat even if no new lines are inserted

    try:
        with open(path, "r", errors="ignore") as f:
            f.seek(start)
            for raw_line in f:
                if not raw_line or not raw_line.strip():
                    continue

                # SSH/auth.log*
                if base.startswith(AUTH_PREFIX):
                    dt = _parse_time_from_line_iso(raw_line) or datetime.now()
                    msg_norm = normalize_auth_message(raw_line)
                    if not should_store_auth_message(msg_norm):
                        dropped += 1
                        continue

                    log_id = insert_log_row(conn, path, dt, msg_norm, agent_name="SSH")
                    ev = parse_ssh_event(msg_norm)
                    if ev:
                        insert_ssh_event(conn, log_id, dt, ev, msg_norm)
                    inserted += 1
                    continue

                # Apache access.log*
                if base.startswith(ACCESS_PREFIX):
                    parsed = parse_apache_access(raw_line)
                    if not parsed:
                        dropped += 1
                        continue
                    if not should_store_apache_access(parsed):
                        dropped += 1
                        continue
                    insert_log_row(conn, path, parsed["dt"], parsed["raw"], agent_name="APACHE")
                    inserted += 1
                    continue

                # vsftpd.log (FTP) + brute force detection (FIXED)
                if base == VSFTPD_BASENAME:
                    msg = _safe_strip(raw_line)
                    if not msg:
                        dropped += 1
                        continue

                    msg_l = msg.lower()

                    # Optional noise filter: keep only meaningful FTP lines
                    if not INCLUDE_FTP_NOISE:
                        if not any(n.lower() in msg_l for n in _FTP_KEEP_NEEDLES):
                            dropped += 1
                            continue

                    # Use REAL timestamp from line if present (FIX)
                    dt = _parse_vsftpd_time(msg) or datetime.now().replace(microsecond=0)

                    # Extract IPv4 even if log shows ::ffff:x.x.x.x
                    ip_match = re.search(r"::ffff:(\d+\.\d+\.\d+\.\d+)", msg) or re.search(r"(\d+\.\d+\.\d+\.\d+)", msg)
                    ip = ip_match.group(1) if ip_match else "unknown"

                    # Always uppercase severity (FIX)
                    severity = "LOW"

                    # Count only real auth failures (NOT "Please login with USER and PASS")
                    is_fail = (
                        "fail login" in msg_l
                        or "530 login incorrect" in msg_l
                        or ("530" in msg_l and "login incorrect" in msg_l)
                        or "authentication failure" in msg_l
                        or "login failed" in msg_l
                    )

                    if is_fail:
                        ftp_fail_tracker[ip].append(dt)

                        one_minute_ago = dt - timedelta(seconds=60)
                        ftp_fail_tracker[ip] = [t for t in ftp_fail_tracker[ip] if t > one_minute_ago]

                        if len(ftp_fail_tracker[ip]) >= 5:
                            severity = "HIGH"

                    msg_out = f"{msg} [SEVERITY={severity}]"

                    insert_log_row(
                        conn,
                        path,
                        dt,
                        msg_out,
                        agent_name="FTP",
                    )

                    inserted += 1
                    continue

                # Apache error.log*
                if base.startswith(ERROR_PREFIX):
                    msg = _safe_strip(raw_line)
                    if not msg:
                        dropped += 1
                        continue
                    if not _RE_APACHE_ERROR_SEV.search(msg):
                        dropped += 1
                        continue
                    insert_log_row(conn, path, datetime.now().replace(microsecond=0), msg, agent_name="APACHE")
                    inserted += 1
                    continue

                # Should never reach here under Option A, but safe:
                dropped += 1

            conn.commit()
            end_offset = f.tell()

        save_cursor(conn, path, inode, end_offset)
        return (inserted, dropped)

    except Exception as e:
        # Don't fail silently—print the error so you can debug quickly
        print(f"[ERROR] ingest_file failed for {path}: {e}")
        conn.rollback()
        return (0, 0)

def trim_logs(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM public.logs;")
        total = int(cur.fetchone()[0] or 0)
        if total <= LOG_LIMIT:
            return
        excess = total - LOG_LIMIT
        cur.execute(
            """
            DELETE FROM public.logs
            WHERE id IN (
              SELECT id FROM public.logs
              ORDER BY log_time ASC
              LIMIT %s
            );
            """,
            (excess,),
        )
    conn.commit()

def main():
    conn = get_conn()
    try:
        watched = 0
        inserted_total = 0
        dropped_total = 0

        for path in iter_watch_files():
            watched += 1
            ins, drop = ingest_file(conn, path)
            inserted_total += ins
            dropped_total += drop

        trim_logs(conn)

        print(
            f"✅ Done. agent={AGENT_NAME} watched={watched} inserted={inserted_total} "
            f"dropped={dropped_total} db={DB_HOST}:{DB_PORT}/{DB_NAME}"
        )
    finally:
        conn.close()

if __name__ == "__main__":
    main()