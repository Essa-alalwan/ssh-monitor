#!/usr/bin/env python3
# =========================================
# File: ssh-monitor/api_server.py
# Enforces "allowed sources only" across all endpoints
# Allowed sources: auth.log*, apache2/access.log*, apache2/error.log*, vsftpd.log
# + Adds /api/ftp_logs endpoint for FTP view
# =========================================

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from flask import Flask, jsonify, request, Response
import psycopg2.extras
import csv
import io
from flask_cors import CORS
import ipaddress

# -----------------------------
# Flask
# -----------------------------

app = Flask(__name__)
CORS(app)

# -----------------------------
# DB config
# -----------------------------

DB_CONFIG = {
    "dbname": os.environ.get("DB_NAME", "logdb"),
    "user": os.environ.get("DB_USER", "hero"),
    "password": os.environ.get("DB_PASS", "hero"),
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", "5432")),
}


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


# -----------------------------
# Allowed sources (Task 8 safety)
# -----------------------------
# We only expose rows from these sources.
ALLOWED_AUTH_PREFIX = "/var/log/auth.log"
ALLOWED_APACHE_ACCESS_PREFIX = "/var/log/apache2/access.log"
ALLOWED_APACHE_ERROR_PREFIX = "/var/log/apache2/error.log"
ALLOWED_VSFTPD_PREFIX = "/var/log/vsftpd.log"


def allowed_logs_where_sql(alias: str = "l") -> str:
    """
    Returns SQL condition limiting rows to allowed sources only.
    Uses LIKE prefix matching so it includes rotated logs (.1, .2, etc).
    """
    col = f"{alias}.source"
    return f"({col} LIKE %s OR {col} LIKE %s OR {col} LIKE %s OR {col} LIKE %s)"


def allowed_logs_where_params() -> Tuple[str, str, str, str]:
    return (
        f"{ALLOWED_AUTH_PREFIX}%",
        f"{ALLOWED_APACHE_ACCESS_PREFIX}%",
        f"{ALLOWED_APACHE_ERROR_PREFIX}%",
        f"{ALLOWED_VSFTPD_PREFIX}%",
    )


def _safe_int(value, default: int, min_value: int = 1, max_value: Optional[int] = None) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    if v < min_value:
        v = min_value
    if max_value is not None and v > max_value:
        v = max_value
    return v


def _parse_dt_param(s: Optional[str]) -> Optional[datetime]:
    """
    Accepts:
      - 'YYYY-MM-DD'
      - 'YYYY-MM-DD HH:MM:SS'
      - ISO-ish
    Returns naive datetime (server local).
    """
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    try:
        # try isoformat, allow trailing Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        # make naive
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None


def _format_dt(dt: Any) -> str:
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        return dt.replace(microsecond=0).isoformat(sep=" ")
    return str(dt)


# -----------------------------
# Apache parsing (access.log)
# -----------------------------

_APACHE_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)
_APACHE_COMMON_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)'
    r'(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+\S+'
)


def _parse_apache_time(ts_raw: str) -> Optional[datetime]:
    try:
        ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
        return ts.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    except Exception:
        return None


def _parse_apache_access_line(line: str, fallback_time: Optional[datetime]) -> Optional[dict]:
    raw = (line or "").replace("\x00", "").strip()
    if not raw:
        return None

    m = _APACHE_COMBINED_RE.match(raw) or _APACHE_COMMON_RE.match(raw)
    if not m:
        return None

    ts = fallback_time
    ts_raw = m.group("ts")
    parsed = _parse_apache_time(ts_raw)
    if parsed is not None:
        ts = parsed

    ua = m.groupdict().get("ua", "") or ""
    return {
        "timestamp": _format_dt(ts),
        "ip": m.group("ip"),
        "method": m.group("method"),
        "url": m.group("url"),
        "status": int(m.group("status")),
        "user_agent": ua,
        "raw": raw,
    }


# -----------------------------
# Web severity (kept for now)
# -----------------------------

INTERNAL_NETS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
]

_SUSPICIOUS_PATHS = (
    "/phpmyadmin",
    "/phppgadmin",
    "/wp-login.php",
    "/wp-admin",
    "/admin",
    "/login",
    "/signin",
)

_SUSPICIOUS_STATUSES = {401, 403, 404, 429}
_HIGH_STATUSES = {500, 501, 502, 503, 504}


def _is_internal_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        for cidr in INTERNAL_NETS:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        return False
    except Exception:
        return False


def compute_web_severity(
    ip: str,
    method: str,
    url: str,
    status: int,
    is_rate_anomalous: bool,
) -> str:
    url_l = (url or "").lower()
    method_u = (method or "").upper()
    internal = _is_internal_ip(ip)

    suspicious_path = any(p in url_l for p in _SUSPICIOUS_PATHS)

    # Low: internal access to pgadmin/phpmyadmin with OK
    if internal and status == 200 and ("/phppgadmin" in url_l or "/phpmyadmin" in url_l):
        return "low"

    # High signals
    if status in _HIGH_STATUSES:
        return "high"
    if is_rate_anomalous:
        return "high"
    if method_u == "POST" and suspicious_path:
        return "high"

    # Medium signals
    if status in _SUSPICIOUS_STATUSES:
        return "medium"
    if suspicious_path and status != 200:
        return "medium"

    return "low"


# -----------------------------
# Helpers for SQL filters
# -----------------------------

def _apply_time_range(where: List[str], params: List[Any], col: str, dt_from: Optional[datetime], dt_to: Optional[datetime]) -> None:
    if dt_from is not None:
        where.append(f"{col} >= %s")
        params.append(dt_from)
    if dt_to is not None:
        where.append(f"{col} <= %s")
        params.append(dt_to)


# -----------------------------
# API: agents
# -----------------------------

@app.route("/api/agents", methods=["GET"])
def get_agents():
    """
    Returns only the collector agents:
      SSH / FTP / APACHE / NMAP

    Status is computed from last_heartbeat (we ignore agent_status.status column).
    Thresholds are slightly different:
      - SSH/FTP/APACHE: active <= 5 min, warning <= 15 min
      - NMAP: active <= 15 min, warning <= 60 min
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Only these agents should appear in the dashboard
        allowed_agents = ["SSH", "FTP", "APACHE", "NMAP"]

        cur.execute(
            """
            SELECT agent_name, last_heartbeat
            FROM public.agent_status
            WHERE agent_name = ANY(%s)
            ORDER BY agent_name;
            """,
            (allowed_agents,),
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        now = datetime.utcnow()

        def compute_status(agent: str, last_hb: Optional[datetime]) -> str:
            if not last_hb:
                return "inactive"

            # last_hb is naive timestamp from postgres; treat it as server-local naive.
            # We compare using naive UTC now; for dashboard status this is fine
            # because we're only measuring "age".
            age = now - last_hb

            if agent == "NMAP":
                if age <= timedelta(minutes=15):
                    return "active"
                if age <= timedelta(minutes=60):
                    return "warning"
                return "inactive"

            # SSH/FTP/APACHE
            if age <= timedelta(minutes=5):
                return "active"
            if age <= timedelta(minutes=15):
                return "warning"
            return "inactive"

        agents = []
        for r in rows:
            agent = r["agent_name"]
            hb = r["last_heartbeat"]
            agents.append(
                {
                    "agent_name": agent,
                    "last_heartbeat": _format_dt(hb),
                    "status": compute_status(agent, hb),
                }
            )

        return jsonify(agents)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: metrics (allowed logs only)
# -----------------------------

@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """
    totalLogs: count of allowed-source rows in public.logs
    activeAgents: heartbeat in last 120 seconds
    anomalies: (ssh login_fail + web suspicious status) in last 24h
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        allowed_where = allowed_logs_where_sql("l")
        allowed_params = list(allowed_logs_where_params())

        # Total useful logs (allowed sources only)
        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM public.logs l
            WHERE {allowed_where};
            """,
            allowed_params,
        )
        total_logs = cur.fetchone()[0] or 0

        # Active agents via heartbeat
        cur.execute(
            """
            SELECT COUNT(*)
            FROM public.agent_status
            WHERE last_heartbeat >= NOW() - INTERVAL '120 seconds';
            """
        )
        active_agents = cur.fetchone()[0] or 0

        # SSH anomalies from ssh_events (best signal)
        cur.execute(
            """
            SELECT COUNT(*)
            FROM public.ssh_events
            WHERE event_time >= NOW() - INTERVAL '24 hours'
              AND event_type = 'login_fail';
            """
        )
        ssh_anom = cur.fetchone()[0] or 0

        # Web anomalies from access logs (allowed + apache access prefix)
        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM public.logs l
            WHERE {allowed_where}
              AND l.source LIKE %s
              AND (
                l.message ~* '\"\\s+(401|403|404|429|5\\d\\d)\\s+'
                OR l.message ILIKE %s
                OR l.message ILIKE %s
              )
              AND l.log_time >= NOW() - INTERVAL '24 hours';
            """,
            allowed_params + [f"{ALLOWED_APACHE_ACCESS_PREFIX}%", "%/phpmyadmin/%", "%/phppgadmin/%"],
        )
        web_anom = cur.fetchone()[0] or 0

        anomalies = int(ssh_anom) + int(web_anom)

        cur.close()
        conn.close()

        return jsonify(
            {"totalLogs": int(total_logs), "activeAgents": int(active_agents), "anomalies": int(anomalies)}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: chart (allowed logs only)
# -----------------------------

@app.route("/api/chart", methods=["GET"])
def get_chart_data():
    """
    Log volume per hour (last 24 hours), allowed sources only.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        allowed_where = allowed_logs_where_sql("l")
        allowed_params = list(allowed_logs_where_params())

        cur.execute(
            f"""
            SELECT DATE_TRUNC('hour', l.log_time) AS hour, COUNT(*)
            FROM public.logs l
            WHERE l.log_time >= NOW() - INTERVAL '24 hours'
              AND {allowed_where}
            GROUP BY hour
            ORDER BY hour DESC
            LIMIT 24;
            """,
            allowed_params,
        )
        rows = cur.fetchall()

        cur.close()
        conn.close()

        data = [{"time": r[0].strftime("%H:%M"), "logs": int(r[1])} for r in reversed(rows)]
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: SSH raw logs page (auth.log only)
# -----------------------------

@app.route("/api/logs", methods=["GET"])
def get_logs():
    """
    Server-side pagination + filters for SSH logs page.
    Restricts to allowed sources AND auth.log only (SSH).
    Query params:
      page, limit
      q (search in message/source)
      source (optional exact-ish, still restricted)
      from, to
      sort (log_time|source) order (asc|desc)
    """
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 20, min_value=1, max_value=200)
        offset = (page - 1) * limit

        q = (request.args.get("q") or "").strip()
        source_filter = (request.args.get("source") or "").strip()
        dt_from = _parse_dt_param(request.args.get("from"))
        dt_to = _parse_dt_param(request.args.get("to"))

        sort = (request.args.get("sort") or "log_time").strip().lower()
        order = (request.args.get("order") or "desc").strip().lower()
        if sort not in {"log_time", "source"}:
            sort = "log_time"
        if order not in {"asc", "desc"}:
            order = "desc"

        where = [allowed_logs_where_sql("l"), "l.source LIKE %s"]
        params: List[Any] = list(allowed_logs_where_params()) + [f"{ALLOWED_AUTH_PREFIX}%"]

        if q:
            where.append("(l.message ILIKE %s OR l.source ILIKE %s)")
            params.extend([f"%{q}%", f"%{q}%"])

        if source_filter:
            # still safe because we keep auth prefix in where
            where.append("l.source ILIKE %s")
            params.append(f"%{source_filter}%")

        _apply_time_range(where, params, "l.log_time", dt_from, dt_to)

        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()

        # total
        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM public.logs l
            WHERE {where_sql};
            """,
            params,
        )
        total = int(cur.fetchone()[0] or 0)

        # page
        cur.execute(
            f"""
            SELECT l.log_time, l.source, l.message, l.agent_name
            FROM public.logs l
            WHERE {where_sql}
            ORDER BY l.{sort} {order}
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()

        cur.close()
        conn.close()

        def classify(msg: str) -> str:
            m = (msg or "").lower()
            if "failed password" in m or "authentication failure" in m or "invalid user" in m:
                return "high"
            if "error" in m or "denied" in m or "refused" in m:
                return "medium"
            return "low"

        logs = [
            {
                "timestamp": _format_dt(r[0]),
                "source": r[1],
                "message": r[2],
                "agent_name": r[3],
                "severity": classify(r[2]),
            }
            for r in rows
        ]

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify({"logs": logs, "total": total, "totalPages": total_pages, "page": page})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: SSH structured events (task 6)
# -----------------------------

@app.route("/api/ssh_events", methods=["GET"])
def get_ssh_events():
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 20, min_value=1, max_value=200)
        offset = (page - 1) * limit

        q = (request.args.get("q") or "").strip()

        # ✅ FRONTEND sends: user, event
        user = (request.args.get("user") or "").strip()
        ip = (request.args.get("ip") or "").strip()
        event = (request.args.get("event") or "").strip()
        outcome = (request.args.get("outcome") or "").strip()

        dt_from = _parse_dt_param(request.args.get("from"))
        dt_to = _parse_dt_param(request.args.get("to"))

        sort = (request.args.get("sort") or "event_time").strip().lower()
        order = (request.args.get("order") or "desc").strip().lower()
        allowed_sorts = {"event_time", "username", "ip", "event_type", "outcome"}
        if sort not in allowed_sorts:
            sort = "event_time"
        if order not in {"asc", "desc"}:
            order = "desc"

        where = ["1=1"]
        params: List[Any] = []

        if q:
            where.append("""
              (
                COALESCE(raw,'') ILIKE %s OR
                COALESCE(username,'') ILIKE %s OR
                COALESCE(ip,'') ILIKE %s
              )
            """)
            params.extend([f"%{q}%"] * 3)

        if user:
            where.append("username ILIKE %s")
            params.append(f"%{user}%")

        if ip:
            where.append("ip = %s")
            params.append(ip)

        if event and event.lower() != "all":
            where.append("event_type = %s")
            params.append(event)

        if outcome and outcome.lower() != "all":
            where.append("outcome = %s")
            params.append(outcome)

        _apply_time_range(where, params, "event_time", dt_from, dt_to)

        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()

        # total
        cur.execute(f"SELECT COUNT(*) FROM public.ssh_events WHERE {where_sql};", params)
        total = int(cur.fetchone()[0] or 0)

        # ✅ IMPORTANT: include id + alias fields that frontend expects:
        cur.execute(
            f"""
            SELECT
                id,
                event_time,
                username,
                ip,
                event_type,
                outcome,
                auth_method,
                raw
            FROM public.ssh_events
            WHERE {where_sql}
            ORDER BY {sort} {order}
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        # ✅ Match frontend keys exactly:
        events = [
            {
                "id": r[0],
                "timestamp": _format_dt(r[1]),   # Time column uses r.timestamp
                "username": r[2],
                "ip": r[3],
                "event_type": r[4],
                "outcome": r[5],
                "auth_method": r[6],            # Method column uses r.auth_method
                "message": r[7],                # Raw column uses r.message
            }
            for r in rows
        ]

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify({"events": events, "total": total, "totalPages": total_pages, "page": page})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: Web traffic (apache access only; allowed + server-side filters)
# -----------------------------

@app.route("/api/web_logs", methods=["GET"])
def get_web_logs():
    """
    Reads from public.logs but ONLY apache access.log (and allowed sources).
    Server-side: page/limit + q/status/severity/from/to + sort.

    Returns:
      { logs: [{timestamp, ip, method, url, status, user_agent, severity}], total, totalPages, page }
    """
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 50, min_value=1, max_value=200)
        offset = (page - 1) * limit

        q = (request.args.get("q") or "").strip()
        status = (request.args.get("status") or "").strip()
        severity = (request.args.get("severity") or "").strip().lower()

        dt_from = _parse_dt_param(request.args.get("from"))
        dt_to = _parse_dt_param(request.args.get("to"))

        sort = (request.args.get("sort") or "log_time").strip().lower()
        order = (request.args.get("order") or "desc").strip().lower()
        if sort not in {"log_time"}:
            sort = "log_time"
        if order not in {"asc", "desc"}:
            order = "desc"

        where = [allowed_logs_where_sql("l"), "l.source LIKE %s"]
        params: List[Any] = list(allowed_logs_where_params()) + [f"{ALLOWED_APACHE_ACCESS_PREFIX}%"]

        if q:
            # search raw message (covers url/ip/ua)
            where.append("l.message ILIKE %s")
            params.append(f"%{q}%")

        if status and status.isdigit():
            where.append("l.message ~ %s")
            params.append(rf'"\s+{status}\s+')

        _apply_time_range(where, params, "l.log_time", dt_from, dt_to)

        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()

        # total rows
        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM public.logs l
            WHERE {where_sql};
            """,
            params,
        )
        total = int(cur.fetchone()[0] or 0)

        # fetch page
        cur.execute(
            f"""
            SELECT l.log_time, l.message
            FROM public.logs l
            WHERE {where_sql}
            ORDER BY l.{sort} {order}
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()

        # rate context: compute per-IP rate over the last 60s up to newest row in page (cheap, bounded)
        newest_dt = rows[0][0] if rows else None
        rate_ip_counts: Dict[str, Tuple[int, int]] = {}
        # (requests, distinct_urls)

        if newest_dt is not None:
            window_start = newest_dt - timedelta(seconds=60)
            cur.execute(
                f"""
                SELECT l.log_time, l.message
                FROM public.logs l
                WHERE {allowed_logs_where_sql("l")}
                  AND l.source LIKE %s
                  AND l.log_time >= %s AND l.log_time <= %s
                ORDER BY l.log_time DESC
                LIMIT 5000;
                """,
                list(allowed_logs_where_params()) + [f"{ALLOWED_APACHE_ACCESS_PREFIX}%", window_start, newest_dt],
            )
            ctx_rows = cur.fetchall()

            tmp_urls: Dict[str, set] = {}
            tmp_counts: Dict[str, int] = {}
            for lt, msg in ctx_rows:
                parsed = _parse_apache_access_line(msg, lt)
                if not parsed:
                    continue
                ip_ = parsed["ip"]
                tmp_counts[ip_] = tmp_counts.get(ip_, 0) + 1
                tmp_urls.setdefault(ip_, set()).add(parsed["url"])

            for ip_, c in tmp_counts.items():
                rate_ip_counts[ip_] = (c, len(tmp_urls.get(ip_, set())))

        cur.close()
        conn.close()

        parsed_logs: List[dict] = []
        for log_time, message in rows:
            item = _parse_apache_access_line(message, log_time)
            if item is None:
                continue

            ip_ = item["ip"]
            reqs, uniq = rate_ip_counts.get(ip_, (0, 0))
            is_rate_anom = (reqs >= 30) or (uniq >= 20)

            sev = compute_web_severity(ip_, item["method"], item["url"], int(item["status"]), is_rate_anom)
            item["severity"] = sev

            if severity and severity != "all" and sev != severity:
                continue

            parsed_logs.append(item)

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify({"logs": parsed_logs, "total": total, "totalPages": total_pages, "page": page})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: FTP logs (vsftpd.log only)
# -----------------------------

@app.route("/api/ftp_logs", methods=["GET"])
def get_ftp_logs():
    """
    Reads from public.ftp_events (structured).
    Server-side pagination + filters.

    Query params:
      page, limit
      q (search raw/file_target/username/ip)
      username
      ip
      action
      from, to   (event_time)
      sort (event_time|username|ip|action) order (asc|desc)

    Returns:
      { logs: [{timestamp,user,ip,action,file_target,raw}], total, totalPages, page }
    """
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 50, min_value=1, max_value=200)
        offset = (page - 1) * limit

        q = (request.args.get("q") or "").strip()
        username = (request.args.get("username") or "").strip()
        ip = (request.args.get("ip") or "").strip()
        action = (request.args.get("action") or "").strip().upper()

        dt_from = _parse_dt_param(request.args.get("from"))
        dt_to = _parse_dt_param(request.args.get("to"))

        sort = (request.args.get("sort") or "event_time").strip().lower()
        order = (request.args.get("order") or "desc").strip().lower()
        if sort not in {"event_time", "username", "ip", "action"}:
            sort = "event_time"
        if order not in {"asc", "desc"}:
            order = "desc"

        where = ["1=1"]
        params: List[Any] = []

        if q:
            where.append("""
              (
                COALESCE(raw,'') ILIKE %s OR
                COALESCE(file_target,'') ILIKE %s OR
                COALESCE(username,'') ILIKE %s OR
                COALESCE(ip,'') ILIKE %s
              )
            """)
            params.extend([f"%{q}%"] * 4)

        if username:
            where.append("username ILIKE %s")
            params.append(f"%{username}%")

        if ip:
            where.append("ip = %s")
            params.append(ip)

        if action and action != "ALL":
            where.append("action = %s")
            params.append(action)

        _apply_time_range(where, params, "event_time", dt_from, dt_to)

        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()

        # total
        cur.execute(
            f"SELECT COUNT(*) FROM public.ftp_events WHERE {where_sql};",
            params,
        )
        total = int(cur.fetchone()[0] or 0)

        # page
        cur.execute(
            f"""
            SELECT event_time, username, ip, action, file_target, raw
            FROM public.ftp_events
            WHERE {where_sql}
            ORDER BY {sort} {order}
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        logs = [
            {
                "timestamp": _format_dt(r[0]),
                "user": r[1],
                "ip": r[2],
                "action": r[3],
                "file_target": r[4],
                "raw": r[5],
            }
            for r in rows
        ]

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify({"logs": logs, "total": total, "totalPages": total_pages, "page": page})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: nmap logs 
# -----------------------------

@app.route("/api/nmap_findings", methods=["GET"])
def get_nmap_findings():
    """
    Reads from public.nmap_findings.
    Server-side pagination + filters.

    Query params:
      page, limit
      q (search target/host/service/product/version/extra)
      target
      host
      port
      state
      service
      from, to (scan_time)
      sort (scan_time|target|host|port|state|service) order (asc|desc)

    Returns:
      { items: [...], total, totalPages, page }
    """
    try:
        page = _safe_int(request.args.get("page"), 1, min_value=1)
        limit = _safe_int(request.args.get("limit"), 50, min_value=1, max_value=200)
        offset = (page - 1) * limit

        q = (request.args.get("q") or "").strip()
        target = (request.args.get("target") or "").strip()
        host = (request.args.get("host") or "").strip()
        port = (request.args.get("port") or "").strip()
        state = (request.args.get("state") or "").strip().lower()
        service = (request.args.get("service") or "").strip().lower()

        dt_from = _parse_dt_param(request.args.get("from"))
        dt_to = _parse_dt_param(request.args.get("to"))

        sort = (request.args.get("sort") or "scan_time").strip().lower()
        order = (request.args.get("order") or "desc").strip().lower()
        allowed_sorts = {"scan_time", "target", "host", "port", "state", "service"}
        if sort not in allowed_sorts:
            sort = "scan_time"
        if order not in {"asc", "desc"}:
            order = "desc"

        where = ["1=1"]
        params: List[Any] = []

        if q:
            where.append("""
                (
                  COALESCE(target,'') ILIKE %s OR
                  COALESCE(host,'') ILIKE %s OR
                  COALESCE(service,'') ILIKE %s OR
                  COALESCE(product,'') ILIKE %s OR
                  COALESCE(version,'') ILIKE %s OR
                  COALESCE(extra,'') ILIKE %s
                )
            """)
            params.extend([f"%{q}%"] * 6)

        if target:
            where.append("target ILIKE %s")
            params.append(f"%{target}%")

        if host:
            where.append("host = %s")
            params.append(host)

        if port and port.isdigit():
            where.append("port = %s")
            params.append(int(port))

        if state and state != "all":
            where.append("LOWER(state) = %s")
            params.append(state)

        if service and service != "all":
            where.append("LOWER(service) = %s")
            params.append(service)

        _apply_time_range(where, params, "scan_time", dt_from, dt_to)

        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(f"SELECT COUNT(*) FROM public.nmap_findings WHERE {where_sql};", params)
        total = int(cur.fetchone()[0] or 0)

        cur.execute(
            f"""
            SELECT id, scan_time, agent_name, target, host, port, proto, state, service, product, version, extra
            FROM public.nmap_findings
            WHERE {where_sql}
            ORDER BY {sort} {order}
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()

        cur.close()
        conn.close()

        items = [
            {
                "id": r[0],
                "scan_time": _format_dt(r[1]),
                "agent_name": r[2],
                "target": r[3],
                "host": r[4],
                "port": r[5],
                "proto": r[6],
                "state": r[7],
                "service": r[8],
                "product": r[9],
                "version": r[10],
                "extra": r[11],
            }
            for r in rows
        ]

        total_pages = (total + limit - 1) // limit if total else 1
        return jsonify({"items": items, "total": total, "totalPages": total_pages, "page": page})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: export (allowed sources only)
# -----------------------------

@app.route("/api/export", methods=["GET"])
def export_logs():
    """
    Exports ONLY allowed sources.
    Optional: service=ssh|web|apache_error|ftp
    """
    try:
        service = (request.args.get("service") or "").strip().lower()

        where = [allowed_logs_where_sql("l")]
        params: List[Any] = list(allowed_logs_where_params())

        if service == "ssh":
            where.append("l.source LIKE %s")
            params.append(f"{ALLOWED_AUTH_PREFIX}%")
        elif service == "web":
            where.append("l.source LIKE %s")
            params.append(f"{ALLOWED_APACHE_ACCESS_PREFIX}%")
        elif service in {"apache_error", "error"}:
            where.append("l.source LIKE %s")
            params.append(f"{ALLOWED_APACHE_ERROR_PREFIX}%")
        elif service == "ftp":
            where.append("l.source LIKE %s")
            params.append(f"{ALLOWED_VSFTPD_PREFIX}%")

        where_sql = " AND ".join(where)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT l.log_time, l.agent_name, l.source, l.message
            FROM public.logs l
            WHERE {where_sql}
            ORDER BY l.log_time DESC;
            """,
            params,
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        lines = ["timestamp,agent,source,message"]
        for r in rows:
            ts = _format_dt(r[0]).replace(",", " ")
            agent = (r[1] or "").replace(",", " ")
            source = (r[2] or "").replace(",", " ")
            message = (r[3] or "").replace(",", " ")
            lines.append(f"{ts},{agent},{source},{message}")

        csv_data = "\n".join(lines)
        return (
            csv_data,
            200,
            {
                "Content-Type": "text/csv",
                "Content-Disposition": "attachment; filename=logs_export.csv",
            },
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def home():
    return jsonify(
        {
            "message": "Raven API is running",
            "db": f"{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}",
            "allowed_sources": [
                f"{ALLOWED_AUTH_PREFIX}*",
                f"{ALLOWED_APACHE_ACCESS_PREFIX}*",
                f"{ALLOWED_APACHE_ERROR_PREFIX}*",
                f"{ALLOWED_VSFTPD_PREFIX}*",
            ],
            "endpoints": [
                "/api/logs",
                "/api/agents",
                "/api/metrics",
                "/api/chart",
                "/api/web_logs",
                "/api/ftp_logs",
                "/api/ssh_events",
                "/api/export",
            ],
        }
    )


# -----------------------------
# alerts 
# -----------------------------

@app.get("/api/alerts")
def list_alerts():
    page = max(int(request.args.get("page", 1)), 1)
    limit = min(max(int(request.args.get("limit", 20)), 1), 200)
    offset = (page - 1) * limit

    priority = request.args.get("priority")
    status = request.args.get("status")
    source = request.args.get("source")
    q = request.args.get("q")

    include_internal = request.args.get("include_internal", "1")
    include_internal = str(include_internal).strip().lower() not in {"0", "false", "no", "off"}

    where = []
    params = {}

    if priority:
        where.append("priority = %(priority)s")
        params["priority"] = priority

    if status:
        where.append("status = %(status)s")
        params["status"] = status

    if source:
        where.append("source = %(source)s")
        params["source"] = source

    if q:
        where.append("(title ILIKE %(q)s OR description ILIKE %(q)s)")
        params["q"] = f"%{q}%"

    # Optional: hide internal/loopback demo traffic
    if not include_internal:
        where.append("(ip_address IS NULL OR ip_address NOT IN ('127.0.0.1', '::1'))")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # total count
            cur.execute(f"SELECT COUNT(*) AS cnt FROM alerts {where_sql}", params)
            total = cur.fetchone()["cnt"]

            # page rows
            cur.execute(
                f"""
                SELECT id, created_at, source, priority, title, description,
                       user_name, ip_address, file_target, status
                FROM alerts
                {where_sql}
                ORDER BY created_at DESC
                LIMIT %(limit)s OFFSET %(offset)s
                """,
                {**params, "limit": limit, "offset": offset}
            )
            rows = cur.fetchall()

        return jsonify({
            "page": page,
            "limit": limit,
            "total": total,
            "items": rows
        })
    finally:
        conn.close()


@app.get("/api/alerts/<int:alert_id>")
def get_alert(alert_id: int):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # 1) alert row
            cur.execute("""
                SELECT id, created_at, source, priority, title, description,
                       user_name, ip_address, file_target, status
                FROM alerts
                WHERE id = %s
            """, (alert_id,))
            alert = cur.fetchone()
            if not alert:
                return jsonify({"error": "Alert not found"}), 404

            # 2) links (all types)
            cur.execute("""
                SELECT log_type, log_id
                FROM alert_log_links
                WHERE alert_id = %s
                ORDER BY id ASC
            """, (alert_id,))
            links = cur.fetchall()

            ids_by_type = {}
            for row in links:
                ids_by_type.setdefault(row["log_type"], []).append(row["log_id"])

            linked_items = []

            def add_item(log_type: str, time_val, source_val, message_val, extra=None):
                item = {
                    "log_type": log_type,
                    "time": _format_dt(time_val),
                    "source": source_val or "",
                    "message": message_val or "",
                }
                if extra:
                    item.update(extra)
                linked_items.append(item)

            # 3) logs (Task 8 safety)
            if ids_by_type.get("logs"):
                allowed_where = allowed_logs_where_sql("l")
                allowed_params = list(allowed_logs_where_params())

                cur.execute(
                    f"""
                    SELECT l.id, l.log_time, l.source, l.message, l.agent_name
                    FROM logs l
                    WHERE l.id = ANY(%s)
                      AND {allowed_where}
                    ORDER BY l.log_time DESC
                    """,
                    (ids_by_type["logs"], *allowed_params),
                )
                for r in cur.fetchall():
                    add_item(
                        "logs",
                        r["log_time"],
                        r["source"],
                        r["message"],
                        {"id": r["id"], "agent_name": r.get("agent_name") or ""},
                    )

            # 4) ftp_events
            if ids_by_type.get("ftp_events"):
                cur.execute(
                    """
                    SELECT id, event_time, ip, username, action, file_target, raw
                    FROM ftp_events
                    WHERE id = ANY(%s)
                    ORDER BY event_time DESC
                    """,
                    (ids_by_type["ftp_events"],),
                )
                for r in cur.fetchall():
                    msg = f"{r.get('action') or ''} user={r.get('username') or ''} ip={r.get('ip') or ''} target={r.get('file_target') or ''}"
                    add_item(
                        "ftp_events",
                        r["event_time"],
                        r.get("ip") or "",
                        msg.strip(),
                        {"id": r["id"], "raw": r.get("raw") or "", "action": r.get("action") or ""},
                    )

            # 5) ssh_events
            if ids_by_type.get("ssh_events"):
                cur.execute(
                    """
                    SELECT id, event_time, ip, username, event_type, outcome, auth_method, raw
                    FROM ssh_events
                    WHERE id = ANY(%s)
                    ORDER BY event_time DESC
                    """,
                    (ids_by_type["ssh_events"],),
                )
                for r in cur.fetchall():
                    msg = f"{r.get('event_type')} outcome={r.get('outcome')} user={r.get('username') or ''} ip={r.get('ip') or ''}"
                    add_item(
                        "ssh_events",
                        r["event_time"],
                        r.get("ip") or "",
                        msg.strip(),
                        {"id": r["id"], "raw": r.get("raw") or "", "auth_method": r.get("auth_method") or ""},
                    )

            # 6) nmap_findings
            if ids_by_type.get("nmap_findings"):
                cur.execute(
                    """
                    SELECT id, scan_time, agent_name, target, host, port, proto, state, service, product, version, extra
                    FROM nmap_findings
                    WHERE id = ANY(%s)
                    ORDER BY scan_time DESC, port ASC
                    """,
                    (ids_by_type["nmap_findings"],),
                )
                for r in cur.fetchall():
                    msg = (
                        f"host={r.get('host')}, port={r.get('port')}/{r.get('proto')}, "
                        f"target={r.get('target')}, state={r.get('state')}, service={r.get('service')}"
                    )
                    add_item(
                        "nmap_findings",
                        r["scan_time"],
                        r.get("host") or "",
                        msg,
                        {"id": r["id"], "port": r.get("port"), "proto": r.get("proto"),
                         "state": r.get("state"), "service": r.get("service")},
                    )

            # Backwards-compatible "linked_logs" (logs table only)
            linked_logs = []
            for it in linked_items:
                if it["log_type"] == "logs":
                    linked_logs.append({
                        "id": it.get("id"),
                        "log_time": it.get("time"),
                        "source": it.get("source"),
                        "message": it.get("message"),
                        "agent_name": it.get("agent_name"),
                    })

            return jsonify({"alert": alert, "linked_logs": linked_logs, "linked_items": linked_items})
    finally:
        conn.close()


@app.patch("/api/alerts/<int:alert_id>")
def update_alert_status(alert_id: int):
    data = request.get_json(silent=True) or {}
    new_status = (data.get("status") or "").strip().lower()

    allowed = {"new", "acknowledged", "resolved"}
    if new_status not in allowed:
        return jsonify({"error": f"Invalid status. Allowed: {sorted(allowed)}"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE alerts SET status=%s WHERE id=%s", (new_status, alert_id))
        if cur.rowcount == 0:
            cur.close()
            conn.close()
            return jsonify({"error": "Alert not found"}), 404

        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True, "id": alert_id, "status": new_status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/alerts/<int:alert_id>/export_csv")
def export_alert_logs_csv(alert_id: int):
    """
    Export linked items for this alert as CSV (supports logs/ssh_events/ftp_events/nmap_findings).
    Keeps Task 8 safety when exporting logs.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cur.execute("SELECT id, title FROM alerts WHERE id=%s", (alert_id,))
        alert = cur.fetchone()
        if not alert:
            cur.close()
            conn.close()
            return jsonify({"error": "Alert not found"}), 404

        cur.execute("""
            SELECT log_type, log_id
            FROM alert_log_links
            WHERE alert_id = %s
            ORDER BY id ASC
        """, (alert_id,))
        links = cur.fetchall()

        ids_by_type = {}
        for row in links:
            ids_by_type.setdefault(row["log_type"], []).append(row["log_id"])

        rows_out = []

        # logs (Task 8 safety)
        if ids_by_type.get("logs"):
            allowed_where = allowed_logs_where_sql("l")
            allowed_params = list(allowed_logs_where_params())
            cur.execute(
                f"""
                SELECT l.id, l.log_time AS time, l.source, l.message, l.agent_name
                FROM logs l
                WHERE l.id = ANY(%s)
                  AND {allowed_where}
                ORDER BY l.log_time DESC
                """,
                (ids_by_type["logs"], *allowed_params),
            )
            for r in cur.fetchall():
                rows_out.append({
                    "log_type": "logs",
                    "id": r["id"],
                    "time": _format_dt(r["time"]),
                    "source": r["source"],
                    "message": r["message"],
                })

        # ftp_events
        if ids_by_type.get("ftp_events"):
            cur.execute(
                """
                SELECT id, event_time AS time, ip AS source, raw AS message
                FROM ftp_events
                WHERE id = ANY(%s)
                ORDER BY event_time DESC
                """,
                (ids_by_type["ftp_events"],),
            )
            for r in cur.fetchall():
                rows_out.append({
                    "log_type": "ftp_events",
                    "id": r["id"],
                    "time": _format_dt(r["time"]),
                    "source": r["source"] or "",
                    "message": r["message"] or "",
                })

        # ssh_events
        if ids_by_type.get("ssh_events"):
            cur.execute(
                """
                SELECT id, event_time AS time, ip AS source, raw AS message
                FROM ssh_events
                WHERE id = ANY(%s)
                ORDER BY event_time DESC
                """,
                (ids_by_type["ssh_events"],),
            )
            for r in cur.fetchall():
                rows_out.append({
                    "log_type": "ssh_events",
                    "id": r["id"],
                    "time": _format_dt(r["time"]),
                    "source": r["source"] or "",
                    "message": r["message"] or "",
                })

        # nmap_findings
        if ids_by_type.get("nmap_findings"):
            cur.execute(
                """
                SELECT id,
                       scan_time AS time,
                       host AS source,
                       ('target=' || target || ' host=' || host || ' port=' || port || '/' || proto || ' state=' || state || ' service=' || COALESCE(service,'')) AS message
                FROM nmap_findings
                WHERE id = ANY(%s)
                ORDER BY scan_time DESC, port ASC
                """,
                (ids_by_type["nmap_findings"],),
            )
            for r in cur.fetchall():
                rows_out.append({
                    "log_type": "nmap_findings",
                    "id": r["id"],
                    "time": _format_dt(r["time"]),
                    "source": r["source"] or "",
                    "message": r["message"] or "",
                })

        cur.close()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["log_type", "id", "time", "source", "message"])
        for r in rows_out:
            writer.writerow([r["log_type"], r["id"], r["time"], r["source"], r["message"]])

        csv_data = output.getvalue()
        output.close()

        filename = f"alert_{alert_id}_linked_items.csv"
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)