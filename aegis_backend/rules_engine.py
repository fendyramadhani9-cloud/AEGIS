"""
Deterministic Security Rules Engine for AEGIS.
Enforces PRD §7.5 and Prioritas 3 Detection Specifications.

Design Principles:
1. Purely deterministic and 100% independent of AI availability.
2. Evaluates normalized, sanitized telemetry events from database pipeline.
3. Sliding time window correlation with out-of-order and delayed event resilience.
4. Strict separate correlation for source_ip and target_user to avoid cross-identity pollution.
5. Idempotent alert generation with stable fingerprint hashing (zero duplicate alerts on re-eval).
6. Strict cross-host evidence binding (trigger and supporting events match alert host_id).
"""

import re
import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional, Set

logger = logging.getLogger("aegis_backend.rules_engine")


class RulesEngine:
    """
    Deterministic detection engine evaluating normalized telemetry streams.
    Generates structured Alert records and AlertEvidence links without modifying severity.
    """

    # Suspicious Sudo execution patterns
    _RE_SUDO_SHELL = re.compile(
        r"(?:^|[\s/;])(?:bash|sh|zsh|dash|su|ksh)\b",
        re.IGNORECASE,
    )
    _RE_SUDO_REMOTE_SCRIPT = re.compile(
        r"(?:curl|wget)\s+.*?(?:\|\s*(?:bash|sh)|\-O|\.sh|\-s)\b",
        re.IGNORECASE,
    )
    _RE_SUDO_CODE_EXEC = re.compile(
        r"(?:python[23]?|perl|ruby)\s+-c\b",
        re.IGNORECASE,
    )
    _RE_SUDO_RISKY_PERM = re.compile(
        r"(?:chmod\s+(?:-[a-zA-Z0-9]+\s+)?(?:777|a\+[rwx]{3})|chown\s+(?:-[a-zA-Z0-9]+\s+)?root(?::root)?\s+/)\b",
        re.IGNORECASE,
    )

    def __init__(
        self,
        ssh_brute_threshold: int = 3,
        ssh_brute_window_sec: int = 300,        # 5 minutes
        auth_success_window_sec: int = 600,     # 10 minutes
        sudo_auth_threshold: int = 3,
        sudo_auth_window_sec: int = 300,        # 5 minutes
    ):
        self.ssh_brute_threshold = ssh_brute_threshold
        self.ssh_brute_window_sec = ssh_brute_window_sec
        self.auth_success_window_sec = auth_success_window_sec
        self.sudo_auth_threshold = sudo_auth_threshold
        self.sudo_auth_window_sec = sudo_auth_window_sec

    def _parse_timestamp(self, ts_str: Optional[str]) -> datetime:
        """Parses ISO timestamp into timezone-aware UTC datetime."""
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    def evaluate_events(
        self,
        events: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Evaluates a batch of normalized telemetry events against all active rules.

        Returns:
            (alerts, alert_evidence_links)
            Both lists conform directly to the database schema for public.alerts
            and public.alert_evidence.
        """
        if not events:
            return [], []

        # Step 1: Ensure events are chronologically sorted (resilience against out-of-order logs)
        sorted_events = sorted(events, key=lambda ev: self._parse_timestamp(ev.get("event_timestamp")))

        alerts: List[Dict[str, Any]] = []
        alert_evidence: List[Dict[str, Any]] = []
        generated_alert_ids: Set[str] = set()

        # Step 2: Evaluate RULE-SSH-BRUTE (Separate IP & User grouping)
        brute_alerts, brute_ev = self._evaluate_ssh_brute(sorted_events, generated_alert_ids)
        alerts.extend(brute_alerts)
        alert_evidence.extend(brute_ev)

        # Step 3: Evaluate RULE-AUTH-003 (Multiple failed logins followed by success)
        auth03_alerts, auth03_ev = self._evaluate_auth_003(sorted_events, generated_alert_ids)
        alerts.extend(auth03_alerts)
        alert_evidence.extend(auth03_ev)

        # Step 4: Evaluate RULE-SUSP-SUDO (Shell escape, remote script, risky chmod, sudo auth failure)
        sudo_alerts, sudo_ev = self._evaluate_suspicious_sudo(sorted_events, generated_alert_ids)
        alerts.extend(sudo_alerts)
        alert_evidence.extend(sudo_ev)

        return alerts, alert_evidence

    def _evaluate_ssh_brute(
        self,
        events: List[Dict[str, Any]],
        generated_ids: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        RULE-SSH-BRUTE:
        Minimal 3 auth_failure dalam 5 menit. Severity High.
        Korelasi terpisah berdasarkan host + source_ip ATAU host + target_user.
        """
        alerts = []
        evidence_links = []

        ssh_failures = [
            ev for ev in events
            if ev.get("event_type") == "auth_failure" and str(ev.get("source_id", "")).startswith("ssh")
        ]
        if len(ssh_failures) < self.ssh_brute_threshold:
            return [], []

        # Build correlation clusters separately
        ip_clusters: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        user_clusters: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

        for ev in ssh_failures:
            h_id = ev.get("host_id", "")
            src_ip = ev.get("source_ip")
            user = ev.get("user_name")

            if src_ip and src_ip not in ["unknown", ""]:
                key_ip = (h_id, src_ip)
                ip_clusters.setdefault(key_ip, []).append(ev)

            if user and user not in ["unknown", ""]:
                key_user = (h_id, user)
                user_clusters.setdefault(key_user, []).append(ev)

        covered_trigger_events: Set[str] = set()

        def process_clusters(group_type: str, clusters: Dict[Tuple[str, str], List[Dict[str, Any]]]):
            for (h_id, key_val), ev_list in clusters.items():
                if len(ev_list) < self.ssh_brute_threshold:
                    continue

                # Cluster consecutive failures within sliding window
                incident_seqs = []
                current_seq = [ev_list[0]]
                for ev in ev_list[1:]:
                    prev_t = self._parse_timestamp(current_seq[-1].get("event_timestamp"))
                    curr_t = self._parse_timestamp(ev.get("event_timestamp"))
                    if 0 <= (curr_t - prev_t).total_seconds() <= self.ssh_brute_window_sec:
                        current_seq.append(ev)
                    else:
                        if len(current_seq) >= self.ssh_brute_threshold:
                            incident_seqs.append(current_seq)
                        current_seq = [ev]
                if len(current_seq) >= self.ssh_brute_threshold:
                    incident_seqs.append(current_seq)

                for seq in incident_seqs:
                    trigger_ev = seq[-1]
                    if trigger_ev["id"] in covered_trigger_events:
                        continue
                    covered_trigger_events.add(trigger_ev["id"])

                    first_ev = seq[0]
                    fp_raw = f"{h_id}:RULE-SSH-BRUTE:{group_type}:{key_val}:{first_ev['id']}"
                    alert_id = f"ALT-BRUTE-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"

                    if alert_id in generated_ids:
                        continue
                    generated_ids.add(alert_id)

                    t_start = self._parse_timestamp(first_ev.get("event_timestamp"))
                    t_end = self._parse_timestamp(trigger_ev.get("event_timestamp"))
                    diff_sec = max(1.0, (t_end - t_start).total_seconds())

                    now_iso = datetime.now(timezone.utc).isoformat()
                    target_label = f"source IP '{key_val}'" if group_type == "source_ip" else f"target username '{key_val}'"
                    alert_row = {
                        "id": alert_id,
                        "host_id": h_id,
                        "rule_id": "RULE-SSH-BRUTE",
                        "rule_version": "1.0",
                        "title": "SSH Repeated Authentication Failures (Brute-Force)",
                        "severity": "high",
                        "detected_at": trigger_ev.get("event_timestamp") or now_iso,
                        "reason": f"Observed {len(seq)} consecutive SSH authentication failures within {diff_sec:.0f}s correlated by {target_label}.",
                        "created_at": now_iso,
                    }
                    alerts.append(alert_row)

                    for ev in seq:
                        evidence_links.append({
                            "alert_id": alert_id,
                            "event_id": ev["id"],
                            "citation_role": "trigger" if ev["id"] == trigger_ev["id"] else "supporting",
                        })

        process_clusters("source_ip", ip_clusters)
        process_clusters("target_user", user_clusters)

        return alerts, evidence_links

    def _evaluate_auth_003(
        self,
        events: List[Dict[str, Any]],
        generated_ids: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        RULE-AUTH-003:
        Minimal 1 auth_failure diikuti auth_success dalam 10 menit.
        Severity High.
        Korelasi harus menggunakan host dan identitas yang konsisten.
        Jangan membuat korelasi jika identitas sumber tidak tersedia.
        """
        alerts = []
        evidence_links = []

        success_events = [ev for ev in events if ev.get("event_type") == "auth_success"]
        failure_events = [ev for ev in events if ev.get("event_type") == "auth_failure"]

        if not success_events or not failure_events:
            return [], []

        for s_ev in success_events:
            h_id = s_ev.get("host_id", "")
            s_ip = s_ev.get("source_ip")
            s_user = s_ev.get("user_name")

            has_ip = s_ip and s_ip not in ["unknown", ""]
            has_user = s_user and s_user not in ["unknown", ""]
            if not has_ip and not has_user:
                continue

            t_success = self._parse_timestamp(s_ev.get("event_timestamp"))

            matching_failures = []
            for f_ev in failure_events:
                if f_ev.get("host_id") != h_id:
                    continue

                t_fail = self._parse_timestamp(f_ev.get("event_timestamp"))
                diff_sec = (t_success - t_fail).total_seconds()

                if 0 <= diff_sec <= self.auth_success_window_sec:
                    f_ip = f_ev.get("source_ip")
                    f_user = f_ev.get("user_name")

                    matches_ip = has_ip and f_ip == s_ip
                    matches_user = has_user and f_user == s_user

                    if matches_ip or matches_user:
                        matching_failures.append(f_ev)

            if matching_failures:
                id_tag = f"{s_ip or 'noip'}:{s_user or 'nouser'}"
                fp_raw = f"{h_id}:RULE-AUTH-003:{id_tag}:{s_ev['id']}"
                alert_id = f"ALT-AUTH-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"

                if alert_id in generated_ids:
                    continue
                generated_ids.add(alert_id)

                now_iso = datetime.now(timezone.utc).isoformat()
                first_fail_time = self._parse_timestamp(matching_failures[0].get("event_timestamp"))
                total_window = max(1.0, (t_success - first_fail_time).total_seconds())

                corr_desc = []
                if has_ip:
                    corr_desc.append(f"IP '{s_ip}'")
                if has_user:
                    corr_desc.append(f"user '{s_user}'")

                alert_row = {
                    "id": alert_id,
                    "host_id": h_id,
                    "rule_id": "RULE-AUTH-003",
                    "rule_version": "1.0",
                    "title": "Multiple Failed Logins Followed by Success",
                    "severity": "high",
                    "detected_at": s_ev.get("event_timestamp") or now_iso,
                    "reason": (
                        f"Authentication success on host '{h_id}' for {', '.join(corr_desc)} "
                        f"preceded by {len(matching_failures)} failed attempt(s) within {total_window:.0f}s."
                    ),
                    "created_at": now_iso,
                }
                alerts.append(alert_row)

                for f in matching_failures:
                    evidence_links.append({
                        "alert_id": alert_id,
                        "event_id": f["id"],
                        "citation_role": "supporting",
                    })
                evidence_links.append({
                    "alert_id": alert_id,
                    "event_id": s_ev["id"],
                    "citation_role": "trigger",
                })

        return alerts, evidence_links

    def _evaluate_suspicious_sudo(
        self,
        events: List[Dict[str, Any]],
        generated_ids: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        RULE-SUSP-SUDO:
        - Minimal 3 kegagalan autentikasi sudo berturut-turut: High.
        - Eksekusi root shell atau remote script melalui sudo: High.
        - Perubahan permission berisiko seperti chmod 777: Medium.
        - Sudo administratif normal tidak menghasilkan alert.
        """
        alerts = []
        evidence_links = []

        # 1. Sudo Executions
        sudo_exec_events = [ev for ev in events if ev.get("event_type") == "sudo_execution"]
        for ev in sudo_exec_events:
            h_id = ev.get("host_id", "")
            user = ev.get("user_name", "unknown")
            details = ev.get("details", {}) or {}
            cmd = details.get("command", "").strip()

            if not cmd:
                continue

            is_shell = bool(self._RE_SUDO_SHELL.search(cmd))
            is_script = bool(self._RE_SUDO_REMOTE_SCRIPT.search(cmd) or self._RE_SUDO_CODE_EXEC.search(cmd))
            is_perm = bool(self._RE_SUDO_RISKY_PERM.search(cmd))

            if is_shell or is_script:
                fp_raw = f"{h_id}:RULE-SUSP-SUDO:SHELL:{ev['id']}"
                alert_id = f"ALT-SUDO-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                if alert_id in generated_ids:
                    continue
                generated_ids.add(alert_id)

                now_iso = datetime.now(timezone.utc).isoformat()
                alert_row = {
                    "id": alert_id,
                    "host_id": h_id,
                    "rule_id": "RULE-SUSP-SUDO",
                    "rule_version": "1.0",
                    "title": "Suspicious Root Shell / Script Execution via Sudo",
                    "severity": "high",
                    "detected_at": ev.get("event_timestamp") or now_iso,
                    "reason": f"Privileged execution of interactive shell or remote script by user '{user}': '{cmd}'.",
                    "created_at": now_iso,
                }
                alerts.append(alert_row)
                evidence_links.append({
                    "alert_id": alert_id,
                    "event_id": ev["id"],
                    "citation_role": "trigger",
                })

            elif is_perm:
                fp_raw = f"{h_id}:RULE-SUSP-SUDO:PERM:{ev['id']}"
                alert_id = f"ALT-SUDO-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                if alert_id in generated_ids:
                    continue
                generated_ids.add(alert_id)

                now_iso = datetime.now(timezone.utc).isoformat()
                alert_row = {
                    "id": alert_id,
                    "host_id": h_id,
                    "rule_id": "RULE-SUSP-SUDO",
                    "rule_version": "1.0",
                    "title": "Permissive Access Permission Alteration via Sudo",
                    "severity": "medium",
                    "detected_at": ev.get("event_timestamp") or now_iso,
                    "reason": f"Overly permissive file permission modification executed via sudo by user '{user}': '{cmd}'.",
                    "created_at": now_iso,
                }
                alerts.append(alert_row)
                evidence_links.append({
                    "alert_id": alert_id,
                    "event_id": ev["id"],
                    "citation_role": "trigger",
                })

        # 2. Sudo Authentication Failures (>= 3 in 5 minutes -> High)
        sudo_fails = [ev for ev in events if ev.get("event_type") == "sudo_auth_failure"]
        if len(sudo_fails) >= self.sudo_auth_threshold:
            fail_groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
            for ev in sudo_fails:
                key = (ev.get("host_id", ""), ev.get("user_name", "unknown"))
                fail_groups.setdefault(key, []).append(ev)

            for (h_id, usr), cluster in fail_groups.items():
                if len(cluster) < self.sudo_auth_threshold:
                    continue

                for i in range(len(cluster) - self.sudo_auth_threshold + 1):
                    window = cluster[i : i + self.sudo_auth_threshold]
                    t_start = self._parse_timestamp(window[0].get("event_timestamp"))
                    t_end = self._parse_timestamp(window[-1].get("event_timestamp"))
                    diff_sec = (t_end - t_start).total_seconds()

                    if 0 <= diff_sec <= self.sudo_auth_window_sec:
                        trigger_ev = window[-1]
                        fp_raw = f"{h_id}:RULE-SUSP-SUDO:FAIL:{usr}:{trigger_ev['id']}"
                        alert_id = f"ALT-SUDO-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                        if alert_id in generated_ids:
                            continue
                        generated_ids.add(alert_id)

                        now_iso = datetime.now(timezone.utc).isoformat()
                        alert_row = {
                            "id": alert_id,
                            "host_id": h_id,
                            "rule_id": "RULE-SUSP-SUDO",
                            "rule_version": "1.0",
                            "title": "Repeated Sudo Authentication Failures",
                            "severity": "high",
                            "detected_at": trigger_ev.get("event_timestamp") or now_iso,
                            "reason": f"Observed {len(window)} consecutive sudo password authentication failures for user '{usr}' within {diff_sec:.0f}s.",
                            "created_at": now_iso,
                        }
                        alerts.append(alert_row)

                        for ev in window:
                            evidence_links.append({
                                "alert_id": alert_id,
                                "event_id": ev["id"],
                                "citation_role": "trigger" if ev["id"] == trigger_ev["id"] else "supporting",
                            })

        return alerts, evidence_links
