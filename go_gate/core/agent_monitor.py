"""
core/agent_monitor.py - Self-monitoring og health ping
Sender Telegram-varsel når systemet restarter eller feiler.
"""

import logging
import os
import sqlite3
import threading
from datetime import date, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_INFERENCE_GATE = threading.Semaphore(1)
_SHUTDOWN_EVENT = threading.Event()
DB_PATH = Path.home() / ".config/aeris/agent_state.db"


def _init_state_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
        """)
        conn.commit()


def get_state(key: str) -> str | None:
    try:
        with sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10) as conn:
            row = conn.execute("SELECT value FROM agent_state WHERE key=?", (key,)).fetchone()
            return row[0] if row else None
    except Exception as e:
        logger.error(f"[MONITOR] get_state failed: {e}")
        return None


def set_state(key: str, value: str):
    try:
        with sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO agent_state (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (key, value, int(datetime.now().timestamp())))
            conn.commit()
    except Exception as e:
        logger.error(f"[MONITOR] set_state failed: {e}")


def send_startup_ping():
    """Send Telegram-varsel når systemet starter."""
    try:
        import requests
        token = os.environ.get("ZEPH_TELEGRAM_TOKEN")
        chat_id = os.environ.get("ADMIN_USER_ID")
        if not token or not chat_id:
            logger.warning("[MONITOR] Telegram credentials missing — no ping sent")
            return
        msg = f"🛡️ Agent Gateway startet — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": msg},
            timeout=10
        )
        logger.info("[MONITOR] Startup ping sent")
    except Exception as e:
        logger.error(f"[MONITOR] Startup ping failed: {e}")


def get_inference_gate() -> threading.Semaphore:
    return _INFERENCE_GATE


def get_shutdown_event() -> threading.Event:
    return _SHUTDOWN_EVENT


def shutdown():
    _SHUTDOWN_EVENT.set()


def send_daily_report():
    """
    Send daily morning report to William via Telegram.
    Runs at 07:00 Europe/Olo via systemd timer.
    Fail-silent: logs errors, never crashes.
    """
    try:
        from datetime import datetime
        from core.config import config
        import requests
        
        # Get Telegram credentials
        token = os.environ.get("AERIS_TELEGRAM_TOKEN")
        chat_id = os.environ.get("ADMIN_USER_ID")
        if not token or not chat_id:
            logger.warning("[DAILY_REPORT] Telegram credentials missing")
            return
        
        today = datetime.now().strftime("%Y-%m-%d")
        
        # 1. ChromaDB vector count
        chroma_count = "?"
        try:
            import chromadb
            from pathlib import Path
            chroma_path = Path('/home/william/AgentProject_CLEAN/aeris-gateway/data/aeris_vector_db')
            client = chromadb.PersistentClient(path=str(chroma_path))
            collection = client.get_collection("system_knowledge")
            if collection:
                chroma_count = str(collection.count())
        except Exception as e:
            logger.warning(f"[DAILY_REPORT] ChromaDB check failed: {e}")
            chroma_count = "error"
        
        # 2. Ingest status (from journalctl)
        ingest_status = "?"
        try:
            import subprocess
            result = subprocess.run(
                ['journalctl', '--user', '-u', 'aeris-ingest', '-n', '1', '--no-pager'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout:
                # Parse line like: "Feb 24 19:45:41 ... aeris-ingest.service: ..."
                line = result.stdout.strip().split('\n')[-1]
                parts = line.split()
                if len(parts) >= 3:
                    time_str = f"{parts[2]} {parts[0]} {parts[1]}"
                    # Check if running or result
                    if 'IDLE' in line:
                        ingest_status = f"{time_str[:16]} / IDLE"
                    elif 'SUCCESS' in line:
                        ingest_status = f"{time_str[:16]} / OK"
                    elif 'RUNNING' in line:
                        ingest_status = f"{time_str[:16]} / RUNNING"
                    else:
                        ingest_status = f"{time_str[:16]} / active"
                else:
                    ingest_status = "unknown / unknown"
            else:
                ingest_status = "no logs / inactive"
        except Exception as e:
            logger.warning(f"[DAILY_REPORT] Ingest check failed: {e}")
            ingest_status = "error"
        
        # 3. GO-GATE pending transactions
        pending_count = "?"
        try:
            from pathlib import Path
            go_gate_db = Path('/home/william/AgentProject_CLEAN/aeris-gateway/data/go_gate.db')
            if go_gate_db.exists():
                with sqlite3.connect(go_gate_db, timeout=5) as conn:
                    row = conn.execute("""
                        SELECT COUNT(*) FROM go_transactions 
                        WHERE status = 'PENDING'
                    """).fetchone()
                    pending_count = str(row[0]) if row else "0"
        except Exception as e:
            logger.warning(f"[DAILY_REPORT] GO-GATE check failed: {e}")
            pending_count = "error"
        
        # 4. Legion health check
        legion_status = "offline"
        try:
            ollama_url = os.environ.get("OLLAMA_HOST", "http://192.168.68.110:11434")
            resp = requests.get(f"{ollama_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                legion_status = "ok"
        except Exception:
            legion_status = "offline"
        
        # Format report
        report = f"""🐾 Morgenstatus – {today}
📚 ChromaDB: {chroma_count} vektorer
⚙️ Ingest: {ingest_status}
🔐 GO-GATE: {pending_count} venter
🖥️ System: Z620 ok | Legion {legion_status}"""
        
        # Send via Telegram (fail-silent)
        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": report},
                timeout=15
            )
            if resp.status_code == 200:
                logger.info("[DAILY_REPORT] Morning report sent successfully")
            else:
                logger.warning(f"[DAILY_REPORT] Telegram send failed: {resp.status_code}")
        except Exception as e:
            logger.error(f"[DAILY_REPORT] Telegram send error: {e}")
        
    except Exception as e:
        # Ultimate fail-silent: catch everything
        logger.error(f"[DAILY_REPORT] Unexpected error: {e}")


_init_state_db()
