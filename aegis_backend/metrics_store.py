"""
Host System Resource Metrics Collector & Store (CPU %, RAM, Disk, Network Mbps, Load).
Uses standard Linux /proc interfaces (zero external dependencies, pure user-space).
"""

import json
import os
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


class HostMetricsStore:
    """Stores per-host resource telemetry and provides live Linux /proc sampling."""

    def __init__(self, state_file: Optional[str] = None):
        self._lock = threading.Lock()
        default_file = Path(__file__).resolve().parent.parent / "data" / ".aegis_host_metrics.json"
        self.state_file = Path(os.getenv("AEGIS_METRICS_FILE", state_file or str(default_file)))
        self._metrics: Dict[str, Dict[str, Any]] = {}
        self._prev_cpu: Optional[Tuple[int, int]] = None
        self._prev_net: Optional[Tuple[float, int, int]] = None
        self._load()

    def _load(self) -> None:
        try:
            if self.state_file.exists():
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._metrics = data
        except Exception:
            pass

    def _save(self) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(json.dumps(self._metrics, indent=2), encoding="utf-8")
        except Exception:
            pass

    def update(self, host_id: str, metrics: Dict[str, Any]) -> None:
        if not host_id or not metrics:
            return
        with self._lock:
            entry = dict(metrics)
            entry.setdefault("sampled_at", datetime.now(timezone.utc).isoformat())
            self._metrics[host_id] = entry
            self._save()

    def get(self, host_id: str, fallback_live: bool = True) -> Optional[Dict[str, Any]]:
        with self._lock:
            cached = self._metrics.get(host_id)
        if cached:
            # Refresh if stale (> 20s) and local /proc is available
            if fallback_live:
                try:
                    ts = datetime.fromisoformat(str(cached.get("sampled_at", "")).replace("Z", "+00:00"))
                    if (datetime.now(timezone.utc) - ts).total_seconds() <= 20:
                        return cached
                except Exception:
                    return cached
            else:
                return cached
        if fallback_live:
            live = self.sample_local_proc()
            if live:
                self.update(host_id, live)
                return live
        return cached

    def sample_local_proc(self) -> Optional[Dict[str, Any]]:
        """Reads live CPU %, RAM, Disk, Network RX/TX Mbps, Load Avg, and Uptime from Linux /proc."""
        try:
            # CPU %
            cpu_pct = 0.0
            stat_path = Path("/proc/stat")
            if stat_path.exists():
                first = stat_path.read_text(encoding="utf-8").splitlines()[0].split()
                if first[0] == "cpu":
                    vals = [int(x) for x in first[1:8]]
                    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
                    total = sum(vals)
                    if self._prev_cpu is not None:
                        d_total = max(1, total - self._prev_cpu[0])
                        d_idle = max(0, idle - self._prev_cpu[1])
                        cpu_pct = round(100.0 * (1.0 - d_idle / d_total), 1)
                    self._prev_cpu = (total, idle)

            # RAM MB & %
            ram_total_mb = 0.0
            ram_used_mb = 0.0
            ram_pct = 0.0
            mem_path = Path("/proc/meminfo")
            if mem_path.exists():
                mem_kv: Dict[str, int] = {}
                for ln in mem_path.read_text(encoding="utf-8").splitlines():
                    parts = ln.split(":")
                    if len(parts) == 2:
                        num = parts[1].strip().split()[0]
                        if num.isdigit():
                            mem_kv[parts[0]] = int(num)
                tot_kb = mem_kv.get("MemTotal", 0)
                avail_kb = mem_kv.get("MemAvailable", mem_kv.get("MemFree", 0))
                if tot_kb > 0:
                    used_kb = max(0, tot_kb - avail_kb)
                    ram_total_mb = round(tot_kb / 1024.0, 1)
                    ram_used_mb = round(used_kb / 1024.0, 1)
                    ram_pct = round(100.0 * used_kb / tot_kb, 1)

            # Disk GB & %
            du = shutil.disk_usage("/")
            disk_total_gb = round(du.total / (1024 ** 3), 1)
            disk_used_gb = round(du.used / (1024 ** 3), 1)
            disk_pct = round(100.0 * du.used / max(1, du.total), 1)

            # Network RX/TX Mbps
            rx_mbps = 0.0
            tx_mbps = 0.0
            net_path = Path("/proc/net/dev")
            if net_path.exists():
                rx_bytes = 0
                tx_bytes = 0
                for ln in net_path.read_text(encoding="utf-8").splitlines()[2:]:
                    if ":" not in ln:
                        continue
                    iface, data = ln.split(":", 1)
                    if iface.strip() == "lo":
                        continue
                    cols = data.split()
                    if len(cols) >= 9:
                        rx_bytes += int(cols[0])
                        tx_bytes += int(cols[8])
                now_t = time.monotonic()
                if self._prev_net is not None:
                    dt = max(0.2, now_t - self._prev_net[0])
                    rx_mbps = round(max(0, rx_bytes - self._prev_net[1]) * 8.0 / (dt * 1_000_000), 2)
                    tx_mbps = round(max(0, tx_bytes - self._prev_net[2]) * 8.0 / (dt * 1_000_000), 2)
                self._prev_net = (now_t, rx_bytes, tx_bytes)

            # Load avg & uptime
            load_1m = 0.0
            if hasattr(os, "getloadavg"):
                load_1m = round(os.getloadavg()[0], 2)
            uptime_h = 0.0
            up_path = Path("/proc/uptime")
            if up_path.exists():
                uptime_h = round(float(up_path.read_text(encoding="utf-8").split()[0]) / 3600.0, 1)

            return {
                "cpu_percent": cpu_pct,
                "ram_used_mb": ram_used_mb,
                "ram_total_mb": ram_total_mb,
                "ram_percent": ram_pct,
                "disk_used_gb": disk_used_gb,
                "disk_total_gb": disk_total_gb,
                "disk_percent": disk_pct,
                "net_rx_mbps": rx_mbps,
                "net_tx_mbps": tx_mbps,
                "load_avg_1m": load_1m,
                "uptime_hours": uptime_h,
                "sampled_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            return None


metrics_store = HostMetricsStore()
