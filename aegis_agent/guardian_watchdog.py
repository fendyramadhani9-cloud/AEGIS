"""
AEGIS4 Host-Side User-Space Integrity Watchdog (Sidecar).

Environment-agnostic daemon designed for any Linux server deployment
(enterprise cloud, banking, defense, industrial, or on-premise).

Safety & Sandboxing Guarantees:
1. 100% User-Space: Zero kernel modules, zero ring-0 hooks (zero Kernel Panic risk).
2. Read-Only Observation: Reads watched host logs and agent code via read-only access.
3. Confined Write Scope: Writes ONLY its local baseline state inside AEGIS's own state dir.
4. Low Footprint: Periodic lightweight polling; no AI calls on the host node.
"""

import hashlib
import json
import logging
import os
import signal
import socket
import time
from pathlib import Path
from typing import Dict, List

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aegis_agent.guardian_watchdog")


class GuardianWatchdog:
    """User-space anti-tamper watchdog for AEGIS collector and critical log streams."""

    def __init__(self):
        self.running = True
        self.api_url = os.getenv("AEGIS_API_URL", "http://127.0.0.1:1709/api").rstrip("/")
        self.agent_token = os.getenv("AGENT_INGEST_TOKEN", "aegis-agent-dev-secret-token")
        self.host_id = os.getenv("AEGIS_HOST_ID", socket.gethostname())
        self.interval_sec = max(10, int(os.getenv("AEGIS_GUARDIAN_INTERVAL", "30")))

        default_state = Path(__file__).resolve().parent.parent / "data" / ".guardian_watchdog_state.json"
        self.state_file = Path(os.getenv("AEGIS_GUARDIAN_WATCHDOG_STATE", str(default_state)))
        self.cursor_file = Path(
            os.getenv("AEGIS_CURSOR_FILE", str(Path(__file__).resolve().parent.parent / ".collector_cursor"))
        )
        raw_logs = os.getenv("AEGIS_WATCH_LOGS", "/var/log/auth.log,/var/log/audit/audit.log")
        self.watch_logs: List[Path] = [Path(p.strip()) for p in raw_logs.split(",") if p.strip()]

        self.agent_dir = Path(__file__).resolve().parent
        self.file_hashes: Dict[str, str] = {}
        self.log_sizes: Dict[str, int] = {}
        self.cursor_seen = False

        signal.signal(signal.SIGINT, self._stop)
        signal.signal(signal.SIGTERM, self._stop)

    def _stop(self, *_args):
        self.running = False

    def _hash_agent_files(self) -> Dict[str, str]:
        hashes: Dict[str, str] = {}
        for py in sorted(self.agent_dir.glob("*.py")):
            try:
                hashes[py.name] = hashlib.sha256(py.read_bytes()).hexdigest()
            except Exception:
                continue
        return hashes

    def _report_tamper(self, reason: str, details: Dict):
        url = f"{self.api_url}/guardian/tamper-report"
        headers = {"X-Agent-Token": self.agent_token, "Content-Type": "application/json"}
        try:
            requests.post(
                url,
                json={"host_id": self.host_id, "reason": reason, "details": details},
                headers=headers,
                timeout=8,
            )
            logger.warning("Reported tamper event to AEGIS backend: %s", reason)
        except Exception as exc:
            logger.error("Failed to report tamper event: %s", exc)

    def run_once(self) -> None:
        current_hashes = self._hash_agent_files()
        if not self.file_hashes:
            self.file_hashes = current_hashes
        else:
            changed = [k for k, v in self.file_hashes.items() if current_hashes.get(k) != v]
            if changed:
                self._report_tamper(
                    "AEGIS collector script integrity modified",
                    {"modified_files": changed},
                )
                self.file_hashes = current_hashes

        # Check for sudden log truncation (size dropped to 0 from significant non-zero size)
        for lp in self.watch_logs:
            try:
                if lp.exists() and lp.is_file():
                    sz = lp.stat().st_size
                    prev = self.log_sizes.get(str(lp))
                    if prev is not None and prev > 1024 and sz == 0:
                        self._report_tamper(
                            f"Log truncation anomaly detected on {lp}",
                            {"log_path": str(lp), "previous_size": prev, "current_size": sz},
                        )
                    self.log_sizes[str(lp)] = sz
            except Exception:
                continue

        # Check collector cursor tampering
        if self.cursor_file.exists():
            self.cursor_seen = True
        elif self.cursor_seen:
            self._report_tamper(
                "Collector journal cursor file removed unexpectedly",
                {"cursor_file": str(self.cursor_file)},
            )
            self.cursor_seen = False

        # Persist watchdog local state strictly inside AEGIS internal state dir
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(
                json.dumps({"host_id": self.host_id, "tracked_files": len(self.file_hashes), "ts": time.time()}),
                encoding="utf-8",
            )
        except Exception:
            pass

    def run_forever(self) -> None:
        logger.info("AEGIS4 User-Space Guardian Watchdog started (host=%s, interval=%ss)", self.host_id, self.interval_sec)
        while self.running:
            self.run_once()
            for _ in range(self.interval_sec):
                if not self.running:
                    break
                time.sleep(1)


if __name__ == "__main__":
    GuardianWatchdog().run_forever()
