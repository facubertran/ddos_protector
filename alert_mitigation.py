import os
import time
import json
import logging
import urllib3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(override=False)

# Suppress InsecureRequestWarning for self-signed certs on RouterOS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("anti-ddos-alert-mitigation")


def env(name: str, default: Optional[str] = None) -> str:
    v = os.getenv(name, default)
    if v is None or v == "":
        raise RuntimeError(f"Missing env var: {name}")
    return v


# ── ClickHouse ──────────────────────────────────────────────────────────────
CH_URL = env("CH_URL")  # e.g. http://10.199.0.15:8123
CH_USER = env("CH_USER", "default")
CH_PASSWORD = os.getenv("CH_PASSWORD", "")
CH_DB = env("CH_DB", "default")

# ── Telegram ────────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = env("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = env("TELEGRAM_CHAT_ID")

# ── General ─────────────────────────────────────────────────────────────────
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "10"))
MAX_CANDIDATES_PER_TICK = int(os.getenv("MAX_CANDIDATES_PER_TICK", "100"))
DEDUP_TTL_SECONDS = int(os.getenv("DEDUP_TTL_SECONDS", "600"))

# ── RouterOS REST API ───────────────────────────────────────────────────────
ROUTERS_CONFIG_PATH = os.getenv("ROUTERS_CONFIG_PATH", "routers.json")
ADDRESS_LIST_NAME = os.getenv("ADDRESS_LIST_NAME", "ddos_detected")
ADDRESS_LIST_COMMENT = os.getenv("ADDRESS_LIST_COMMENT", "Mitigation")


# ── Helpers ─────────────────────────────────────────────────────────────────

def load_routers(path: str) -> List[Dict[str, Any]]:
    """Load router list from JSON config file."""
    config_path = Path(path)
    if not config_path.exists():
        log.warning("Router config file not found: %s — mitigation disabled", path)
        return []
    with open(config_path, "r", encoding="utf-8") as f:
        routers = json.load(f)
    log.info("Loaded %d router(s) from %s", len(routers), path)
    return routers


def ch_request(sql: str, *, body: Optional[bytes] = None, timeout: int = 20) -> requests.Response:
    url = CH_URL.rstrip("/") + "/"
    params = {"database": CH_DB, "query": sql}
    auth = (CH_USER, CH_PASSWORD if CH_PASSWORD is not None else "")
    headers = {"Content-Type": "text/plain; charset=utf-8"}

    r = requests.post(url, params=params, data=body, auth=auth, headers=headers, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"ClickHouse HTTP error {r.status_code}: {r.text[:500]}")
    return r


def ch_select_json(sql: str) -> List[Dict[str, Any]]:
    if "FORMAT" not in sql.upper():
        sql = sql.rstrip().rstrip(";") + " FORMAT JSON"
    r = ch_request(sql)
    payload = r.json()
    return payload.get("data", [])


def ch_insert_jsoneachrow(table: str, columns: List[str], rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    cols_sql = ", ".join(columns)
    sql = f"INSERT INTO {table} ({cols_sql}) FORMAT JSONEachRow"
    body = ("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n").encode("utf-8")
    ch_request(sql, body=body)


def tg_send(text: str) -> None:
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "disable_web_page_preview": True,
    }
    r = requests.post(url, json=payload, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"Telegram sendMessage failed: {r.status_code} {r.text[:500]}")


def fmt_alert(c: Dict[str, Any]) -> str:
    return (
        "🚨 Anti-DDoS (salida) - Candidato\n"
        f"• window_start: {c['window_start']}\n"
        f"• src_ip: {c['src_ip']}\n"
        f"• action: {c['action']}\n"
        f"• reason: {c['reason']}\n"
        f"• score: {c['score']}\n"
        f"• target: {c.get('target_dst_ip')} proto={c.get('target_proto')} port={c.get('target_dst_port')}\n"
    )


def candidate_key(c: Dict[str, Any]) -> str:
    return "|".join([
        str(c["src_ip"]),
        str(c.get("action", "")),
        str(c.get("target_dst_ip", "")),
        str(c.get("target_proto", "")),
        str(c.get("target_dst_port", "")),
    ])


def fetch_candidates() -> List[Dict[str, Any]]:
    sql = f"""
    SELECT
      window_start,
      src_ip,
      action,
      reason,
      score,
      target_dst_ip,
      target_proto,
      target_dst_port
    FROM {CH_DB}.v_actions_candidates
    ORDER BY window_start DESC, score DESC
    LIMIT {MAX_CANDIDATES_PER_TICK}
    """
    return ch_select_json(sql)


def enqueue_action(c: Dict[str, Any]) -> None:
    now_local = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    details = {
        "alert_channel": "telegram",
        "alert_sent_at": datetime.now(timezone.utc).isoformat(),
    }

    row = {
        "window_start": c["window_start"],
        "src_ip": c["src_ip"],
        "action": c["action"],
        "reason": c["reason"],
        "score": int(c["score"]),
        "target_dst_ip": c.get("target_dst_ip", "0.0.0.0"),
        "target_proto": int(c.get("target_proto") or 0),
        "target_dst_port": int(c.get("target_dst_port") or 0),
        "status": "pending",
        "last_update": now_local,
        "details": json.dumps(details, ensure_ascii=False),
    }

    columns = [
        "window_start",
        "src_ip",
        "action",
        "reason",
        "score",
        "target_dst_ip",
        "target_proto",
        "target_dst_port",
        "status",
        "last_update",
        "details",
    ]

    ch_insert_jsoneachrow(f"{CH_DB}.mitigation_actions", columns, [row])


# ── RouterOS REST API ───────────────────────────────────────────────────────

def add_to_address_list(src_ip: str, routers: List[Dict[str, Any]]) -> None:
    """Add the attacker IP to the address-list on every configured router."""
    if not routers:
        return

    for router in routers:
        host = router["host"]
        port = router.get("port", 8741)
        username = router.get("username", "admin")
        password = router.get("password", "")
        use_ssl = router.get("use_ssl", True)

        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{port}/rest/ip/firewall/address-list"

        body = {
            "address": src_ip,
            "list": ADDRESS_LIST_NAME,
            "comment": ADDRESS_LIST_COMMENT,
        }

        try:
            r = requests.put(
                url,
                json=body,
                auth=(username, password),
                verify=False,
                timeout=10,
            )
            if r.status_code in (200, 201):
                log.info(
                    "RouterOS [%s:%s] address-list OK: %s → %s",
                    host, port, src_ip, ADDRESS_LIST_NAME,
                )
            else:
                log.error(
                    "RouterOS [%s:%s] address-list FAILED (%d): %s",
                    host, port, r.status_code, r.text[:300],
                )
        except Exception as e:
            log.error(
                "RouterOS [%s:%s] connection error: %s",
                host, port, e,
            )


# ── Main loop ───────────────────────────────────────────────────────────────

def main():
    # smoke test
    ch_select_json("SELECT 1 AS ok")
    log.info("Connected to ClickHouse over HTTP: %s db=%s", CH_URL, CH_DB)

    # load routers
    routers = load_routers(ROUTERS_CONFIG_PATH)

    seen: Dict[str, float] = {}

    while True:
        try:
            candidates = fetch_candidates()
            now = time.time()

            # purge old keys
            for k, ts in list(seen.items()):
                if now - ts > DEDUP_TTL_SECONDS:
                    del seen[k]

            for c in candidates:
                k = candidate_key(c)
                if k in seen:
                    continue

                enqueue_action(c)

                try:
                    tg_send(fmt_alert(c))
                except Exception as tg_err:
                    log.error("Telegram send failed: %s", tg_err)
                add_to_address_list(c["src_ip"], routers)

                seen[k] = now
                log.info("Queued + alerted + mitigated: src=%s action=%s", c["src_ip"], c["action"])

        except Exception as e:
            log.exception("Loop error: %s", e)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
