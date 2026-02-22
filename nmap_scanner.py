#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import socket
import subprocess
from datetime import datetime
import xml.etree.ElementTree as ET

import psycopg2

# ----------------------------
# Config (env vars)
# ----------------------------
DB_NAME = os.environ.get("DB_NAME", "logdb")
DB_USER = os.environ.get("DB_USER", "hero")
DB_PASS = os.environ.get("DB_PASS", "hero")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))

# XML output path (stored like your other files, not in /data/nmap/)
NMAP_XML_PATH = os.environ.get("NMAP_XML_PATH", "/home/hero/ssh-monitor/nmap_scan.xml")

# Whitelist of approved targets (comma-separated)
# Example: NMAP_TARGETS="localhost,127.0.0.1,192.168.56.104"
NMAP_TARGETS = os.environ.get("NMAP_TARGETS", "localhost,127.0.0.1")

# Target to scan
NMAP_TARGET = os.environ.get("NMAP_TARGET", "localhost")

# If true, do NOT run nmap; just parse existing XML file (useful for testing)
NMAP_PARSE_ONLY = os.environ.get("NMAP_PARSE_ONLY", "0") == "1"

# Dedupe window for same alert (minutes)
ALERT_DEDUPE_MINUTES = int(os.environ.get("NMAP_ALERT_DEDUPE_MINUTES", "10"))


def get_conn():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT,
    )

def upsert_agent_heartbeat(cur, agent: str) -> None:
    cur.execute(
        """
        INSERT INTO public.agent_status (agent_name, last_heartbeat)
        VALUES (%s, NOW())
        ON CONFLICT (agent_name)
        DO UPDATE SET last_heartbeat = NOW();
        """,
        (agent,),
    )

def parse_allowed_targets(raw: str) -> set[str]:
    return {t.strip() for t in raw.split(",") if t.strip()}


def run_nmap_to_xml(xml_path: str, target: str) -> None:
    """
    Run nmap and write XML output to xml_path.

    Safety: only runs if target is in NMAP_TARGETS whitelist.
    """
    allowed = parse_allowed_targets(NMAP_TARGETS)
    if target not in allowed:
        raise ValueError(f"Target '{target}' not allowed. Allowed: {sorted(allowed)}")

    # Fast scan. Keep your options controlled.
    cmd = ["nmap", "-T4", "-F", target, "-oX", xml_path]

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=180,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Nmap failed (code={result.returncode}): {result.stderr.strip()}")


def extract_target_from_nmaprun(root: ET.Element) -> str:
    args = (root.get("args") or "").strip()
    if not args:
        return NMAP_TARGET

    tokens = [t for t in args.split() if t.strip()]
    candidates = [t for t in tokens if not t.startswith("-")]
    if not candidates:
        return NMAP_TARGET

    # last non-flag token is usually the target
    return candidates[-1]


def parse_nmap_xml(xml_text: str) -> tuple[str, list[dict]]:
    root = ET.fromstring(xml_text)
    target = extract_target_from_nmaprun(root)

    findings: list[dict] = []

    for host in root.findall("host"):
        addr_el = host.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else "unknown"

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            proto = (port_el.get("protocol") or "").strip() or "tcp"
            port = int((port_el.get("portid") or "0").strip() or 0)

            state_el = port_el.find("state")
            state = (state_el.get("state") if state_el is not None else "unknown") or "unknown"
            reason = state_el.get("reason") if state_el is not None else None

            service_el = port_el.find("service")
            service = service_el.get("name") if service_el is not None else None
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None
            extrainfo = service_el.get("extrainfo") if service_el is not None else None

            extra_parts = []
            if reason:
                extra_parts.append(f"reason={reason}")
            if extrainfo:
                extra_parts.append(f"extrainfo={extrainfo}")
            extra = ", ".join(extra_parts) if extra_parts else None

            findings.append(
                {
                    "target": target,
                    "host": host_ip,
                    "port": port,
                    "proto": proto,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extra": extra,
                }
            )

    return target, findings


def alert_exists_recently(cur, title: str, target: str, host: str, port: int, proto: str) -> bool:
    """
    Dedupe by title + (host/port/proto) in description (simple + practical).
    We store host/port/proto inside description and use ILIKE match.
    """
    marker = f"host={host}, port={port}/{proto}, target={target}"
    cur.execute(
        """
        SELECT 1
        FROM alerts
        WHERE title = %s
          AND description ILIKE %s
          AND status <> 'resolved'
          AND created_at >= NOW() - (%s || ' minutes')::interval
        LIMIT 1;
        """,
        (title, f"%{marker}%", ALERT_DEDUPE_MINUTES),
    )
    return cur.fetchone() is not None


def create_alert(cur, *, priority: str, title: str, description: str, source: str = "nmap",
                 ip_address: str | None = None, user_name: str | None = None, file_target: str | None = None) -> int:
    cur.execute(
        """
        INSERT INTO alerts (source, priority, title, description, user_name, ip_address, file_target)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
        """,
        (source, priority, title, description, user_name, ip_address, file_target),
    )
    return cur.fetchone()[0]


def link_alert(cur, alert_id: int, log_type: str, log_id: int) -> None:
    # If you later add unique constraint, you can switch to ON CONFLICT DO NOTHING.
    cur.execute(
        """
        INSERT INTO alert_log_links (alert_id, log_type, log_id)
        VALUES (%s, %s, %s);
        """,
        (alert_id, log_type, log_id),
    )


def main():
    target_to_scan = (NMAP_TARGET or "localhost").strip() or "localhost"
    allowed = parse_allowed_targets(NMAP_TARGETS)

    if target_to_scan not in allowed:
        print(f"BLOCKED: target '{target_to_scan}' not in whitelist: {sorted(allowed)}", file=sys.stderr)
        sys.exit(4)

    # 1) Run nmap (unless parse-only)
    if not NMAP_PARSE_ONLY:
        try:
            run_nmap_to_xml(NMAP_XML_PATH, target_to_scan)
        except FileNotFoundError:
            print("ERROR: nmap binary not found. Install nmap or set NMAP_PARSE_ONLY=1.", file=sys.stderr)
            sys.exit(2)
        except Exception as e:
            print(f"ERROR: failed to run nmap: {e}", file=sys.stderr)
            sys.exit(2)

    # 2) Load XML
    if not os.path.exists(NMAP_XML_PATH):
        print(f"ERROR: XML file not found: {NMAP_XML_PATH}", file=sys.stderr)
        sys.exit(2)

    with open(NMAP_XML_PATH, "r", encoding="utf-8", errors="ignore") as f:
        xml_text = f.read().strip()

    if not xml_text:
        print("ERROR: XML file is empty.", file=sys.stderr)
        sys.exit(3)

    # 3) Parse XML
    parsed_target, findings = parse_nmap_xml(xml_text)

    # whitelist check (defense-in-depth)
    if parsed_target not in allowed:
        print(f"BLOCKED: parsed target '{parsed_target}' not in whitelist: {sorted(allowed)}", file=sys.stderr)
        sys.exit(4)

    scan_time = datetime.now()
    agent_name = os.environ.get("AGENT_NAME", "NMAP")  # keep consistent like your other agents

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:

                # 🔥 Update NMAP heartbeat
                upsert_agent_heartbeat(cur, agent_name)
                
                inserted_rows: list[tuple[int, str, int, str, str, str | None]] = []
                # (finding_id, host, port, proto, state, service)

                # 4) Insert findings
                for item in findings:
                    cur.execute(
                        """
                        INSERT INTO public.nmap_findings
                          (scan_time, agent_name, target, host, port, proto, state, service, product, version, extra)
                        VALUES
                          (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        RETURNING id;
                        """,
                        (
                            scan_time,
                            agent_name,
                            parsed_target,
                            item["host"],
                            item["port"],
                            item["proto"],
                            item["state"],
                            item["service"],
                            item["product"],
                            item["version"],
                            item["extra"],
                        ),
                    )
                    fid = cur.fetchone()[0]
                    inserted_rows.append((fid, item["host"], item["port"], item["proto"], item["state"], item["service"]))

                # 5) Compare against baseline + create alerts
                # Load baseline for this target (all hosts)
                cur.execute(
                    """
                    SELECT target, host, port, proto, state, service
                    FROM public.nmap_port_baseline
                    WHERE target = %s;
                    """,
                    (parsed_target,),
                )
                baseline = {(h, p, pr): (st, svc) for (_, h, p, pr, st, svc) in cur.fetchall()}

                for fid, host, port, proto, state, service in inserted_rows:
                    key = (host, port, proto)
                    old = baseline.get(key)

                    # NEW port (first time ever seen)
                    if old is None:
                        title = "Nmap: New Port Detected"
                        if not alert_exists_recently(cur, title, parsed_target, host, port, proto):
                            desc = (
                                f"New port detected. host={host}, port={port}/{proto}, target={parsed_target}, "
                                f"state={state}, service={service or ''}"
                            )
                            alert_id = create_alert(
                                cur,
                                priority="high" if state == "open" else "medium",
                                title=title,
                                description=desc,
                                source="nmap",
                                ip_address=host,      # useful filter field
                                file_target=parsed_target,
                            )
                            link_alert(cur, alert_id, "nmap_findings", fid)

                    # State changed (e.g., open -> closed)
                    else:
                        old_state, old_service = old
                        if old_state != state:
                            title = "Nmap: Port State Changed"
                            if not alert_exists_recently(cur, title, parsed_target, host, port, proto):
                                desc = (
                                    f"Port state changed. host={host}, port={port}/{proto}, target={parsed_target}, "
                                    f"{old_state} -> {state}, service={service or old_service or ''}"
                                )
                                alert_id = create_alert(
                                    cur,
                                    priority="high" if state == "open" else "medium",
                                    title=title,
                                    description=desc,
                                    source="nmap",
                                    ip_address=host,
                                    file_target=parsed_target,
                                )
                                link_alert(cur, alert_id, "nmap_findings", fid)

                    # 6) Upsert baseline
                    cur.execute(
                        """
                        INSERT INTO public.nmap_port_baseline (target, host, port, proto, state, service, last_seen)
                        VALUES (%s,%s,%s,%s,%s,%s,NOW())
                        ON CONFLICT (target, host, port, proto)
                        DO UPDATE SET state=EXCLUDED.state, service=EXCLUDED.service, last_seen=NOW();
                        """,
                        (parsed_target, host, port, proto, state, service),
                    )

        print(f"OK: inserted {len(findings)} rows into nmap_findings (target={parsed_target}, agent={agent_name})")
    finally:
        conn.close()


if __name__ == "__main__":
    main()