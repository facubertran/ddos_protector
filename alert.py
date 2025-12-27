import os
import time
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

load_dotenv(override=False)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("anti-ddos-alert-worker-http")


def env(name: str, default: Optional[str] = None) -> str:
    v = os.getenv(name, default)
    if v is None or v == "":
        raise RuntimeError(f"Missing env var: {name}")
    return v


CH_URL = env("CH_URL")  # e.g. http://10.199.0.15:8123
CH_USER = env("CH_USER", "default")
CH_PASSWORD = os.getenv("CH_PASSWORD", "")
CH_DB = env("CH_DB", "default")

TELEGRAM_BOT_TOKEN = env("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = env("TELEGRAM_CHAT_ID")

POLL_SECONDS = int(os.getenv("POLL_SECONDS", "10"))
MAX_CANDIDATES_PER_TICK = int(os.getenv("MAX_CANDIDATES_PER_TICK", "100"))
DEDUP_TTL_SECONDS = int(os.getenv("DEDUP_TTL_SECONDS", "600"))


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
    # Tu tabla:
    # created_at DEFAULT now()
    # status DEFAULT 'pending'
    # last_update DEFAULT now()
    # details DEFAULT ''
    #
    # Para que sea explícito y auditable, seteamos status/last_update/details,
    # y dejamos created_at por default.
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


def main():
    # smoke test
    ch_select_json("SELECT 1 AS ok")
    log.info("Connected to ClickHouse over HTTP: %s db=%s", CH_URL, CH_DB)

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
                tg_send(fmt_alert(c))

                seen[k] = now
                log.info("Queued + alerted: src=%s action=%s", c["src_ip"], c["action"])

        except Exception as e:
            log.exception("Loop error: %s", e)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
