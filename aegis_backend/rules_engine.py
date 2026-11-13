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
    _RE_SUSPICIOUS_CRON = re.compile(
        r"(?:curl|wget|nc\b|ncat|bash\s+-i|/dev/tcp/|base64\s+-d|chmod\s+(?:\+x|777)|/tmp/|/dev/shm/|python[23]?\s+-c)",
        re.IGNORECASE,
    )
    _PRIVILEGED_GROUPS = {"sudo", "root", "wheel", "admin", "docker", "shadow", "adm"}
    _CRITICAL_SERVICES = {
        "ufw", "ufw.service",
        "auditd", "auditd.service",
        "ssh", "ssh.service", "sshd", "sshd.service",
        "fail2ban", "fail2ban.service",
        "apparmor", "apparmor.service",
        "aegis-collector", "aegis-collector.service",
        "rsyslog", "rsyslog.service",
    }

    def __init__(
        self,
        ssh_brute_threshold: int = 3,
        ssh_brute_window_sec: int = 300,        # 5 minutes
        auth_success_window_sec: int = 600,     # 10 minutes
        sudo_auth_threshold: int = 3,
        sudo_auth_window_sec: int = 300,        # 5 minutes
        fw_scan_threshold: int = 4,
        fw_scan_window_sec: int = 300,          # 5 minutes
        web_error_threshold: int = 4,
        web_error_window_sec: int = 300,        # 5 minutes
    ):
        self.ssh_brute_threshold = ssh_brute_threshold
        self.ssh_brute_window_sec = ssh_brute_window_sec
        self.auth_success_window_sec = auth_success_window_sec
        self.sudo_auth_threshold = sudo_auth_threshold
        self.sudo_auth_window_sec = sudo_auth_window_sec
        self.fw_scan_threshold = fw_scan_threshold
        self.fw_scan_window_sec = fw_scan_window_sec
        self.web_error_threshold = web_error_threshold
        self.web_error_window_sec = web_error_window_sec

    def _parse_timestamp(self, ts_str: Optional[str]) -> datetime:
        """Parses ISO timestamp into timezone-aware UTC datetime."""
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
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

        # Step 5: Evaluate RULE-WEB-ATTACK (Web LFI/SQLi/RCE/Env probes & HTTP auth bursts)
        web_alerts, web_ev = self._evaluate_web_attacks(sorted_events, generated_alert_ids)
        alerts.extend(web_alerts)
        alert_evidence.extend(web_ev)

        # Step 6: Evaluate RULE-ACCT-BACKDOOR (Backdoor account creation & privileged group escalation)
        acct_alerts, acct_ev = self._evaluate_account_backdoor(sorted_events, generated_alert_ids)
        alerts.extend(acct_alerts)
        alert_evidence.extend(acct_ev)

        # Step 7: Evaluate RULE-FW-PORTSCAN & RULE-KERNEL-EXPLOIT (UFW port scan bursts & kernel segfaults)
        fw_alerts, fw_ev = self._evaluate_firewall_and_kernel(sorted_events, generated_alert_ids)
        alerts.extend(fw_alerts)
        alert_evidence.extend(fw_ev)

        # Step 8: Evaluate RULE-CRON-PERSIST & RULE-DEFENSE-EVASION (Cron persistence & stopping security daemons)
        cron_alerts, cron_ev = self._evaluate_cron_and_systemd(sorted_events, generated_alert_ids)
        alerts.extend(cron_alerts)
        alert_evidence.extend(cron_ev)

        # Step 9: Evaluate RULE-SSH-KEY-BACKDOOR (Critical file & SSH authorized_keys tampering)
        tamper_alerts, tamper_ev = self._evaluate_critical_file_tamper(sorted_events, generated_alert_ids)
        alerts.extend(tamper_alerts)
        alert_evidence.extend(tamper_ev)

        # Step 10: Evaluate Defense-Grade APT Rules (RULE-ANTI-FORENSICS, RULE-DATA-EXFIL, RULE-ROOTKIT-SNIFF)
        apt_alerts, apt_ev = self._evaluate_defense_apt_rules(sorted_events, generated_alert_ids)
        alerts.extend(apt_alerts)
        alert_evidence.extend(apt_ev)

        # Step 11: Evaluate Container & Kubernetes Runtime/Audit Rules
        ck_alerts, ck_ev = self._evaluate_container_and_k8s_rules(sorted_events, generated_alert_ids)
        alerts.extend(ck_alerts)
        alert_evidence.extend(ck_ev)

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

    def _evaluate_web_attacks(
        self,
        events: List[Dict[str, Any]],
        generated_ids: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        RULE-WEB-ATTACK:
        - High-signal web attack probes (path traversal, SQLi, command injection, sensitive file probe): High/Critical.
        - Repeated HTTP 401/403 authentication errors (>=4 within 5m from same IP): Medium.
        """
        alerts: List[Dict[str, Any]] = []
        evidence_links: List[Dict[str, Any]] = []

        probe_events = [ev for ev in events if ev.get("event_type") == "web_attack_probe"]
        for ev in probe_events:
            h_id = ev.get("host_id", "")
            src_ip = ev.get("source_ip") or "unknown"
            details = ev.get("details", {}) or {}
            category = details.get("attack_category", "web_probe")
            uri = details.get("uri", "/")
            status_code = details.get("status_code", 0)

            fp_raw = f"{h_id}:RULE-WEB-ATTACK:PROBE:{ev['id']}"
            alert_id = f"ALT-WEB-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
            if alert_id in generated_ids:
                continue
            generated_ids.add(alert_id)

            severity = "critical" if category in {"command_injection", "sql_injection"} else "high"
            now_iso = datetime.now(timezone.utc).isoformat()
            alerts.append({
                "id": alert_id,
                "host_id": h_id,
                "rule_id": "RULE-WEB-ATTACK",
                "rule_version": "1.0",
                "title": f"Web Application Attack Probe ({category.replace('_', ' ').title()})",
                "severity": severity,
                "detected_at": ev.get("event_timestamp") or now_iso,
                "reason": (
                    f"Detected high-signal web attack probe ({category}) from {src_ip} "
                    f"targeting URI '{uri}' (HTTP {status_code})."
                ),
                "created_at": now_iso,
            })
            evidence_links.append({
                "alert_id": alert_id,
                "event_id": ev["id"],
                "citation_role": "trigger",
            })

        http_errors = [
            ev for ev in events
            if ev.get("event_type") == "web_http_error"
            and (ev.get("details") or {}).get("status_code") in (401, 403)
        ]
        if len(http_errors) >= self.web_error_threshold:
            ip_groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
            for ev in http_errors:
                src_ip = ev.get("source_ip")
                if src_ip and src_ip not in ("unknown", ""):
                    ip_groups.setdefault((ev.get("host_id", ""), src_ip), []).append(ev)

            for (h_id, src_ip), cluster in ip_groups.items():
                if len(cluster) < self.web_error_threshold:
                    continue
                t_start = self._parse_timestamp(cluster[0].get("event_timestamp"))
                t_end = self._parse_timestamp(cluster[-1].get("event_timestamp"))
                diff_sec = (t_end - t_start).total_seconds()
                if 0 <= diff_sec <= self.web_error_window_sec:
                    trigger_ev = cluster[-1]
                    fp_raw = f"{h_id}:RULE-WEB-ATTACK:AUTH-BURST:{src_ip}:{cluster[0]['id']}"
                    alert_id = f"ALT-WEB-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                    if alert_id not in generated_ids:
                        generated_ids.add(alert_id)
                        now_iso = datetime.now(timezone.utc).isoformat()
                        alerts.append({
                            "id": alert_id,
                            "host_id": h_id,
                            "rule_id": "RULE-WEB-ATTACK",
                            "rule_version": "1.0",
                            "title": "Repeated Web HTTP 401/403 Access Denials",
                            "severity": "medium",
                            "detected_at": trigger_ev.get("event_timestamp") or now_iso,
                            "reason": f"Observed {len(cluster)} HTTP 401/403 responses for source IP '{src_ip}' within {diff_sec:.0f}s.",
                            "created_at": now_iso,
                        })
                        for ev in cluster:
                            evidence_links.append({
                                "alert_id": alert_id,
                                "event_id": ev["id"],
                                "citation_role": "trigger" if ev["id"] == trigger_ev["id"] else "supporting",
                            })

        return alerts, evidence_links

    def _evaluate_account_backdoor(
        self,
        events: List[Dict[str, Any]],
        generated_ids: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        RULE-ACCT-BACKDOOR:
        - Local user creation (useradd/adduser): High (Critical if UID=0).
        - Adding user to privileged group (sudo, root, wheel, admin, docker): High.
        """
        alerts: List[Dict[str, Any]] = []
        evidence_links: List[Dict[str, Any]] = []

        for ev in events:
            ev_type = ev.get("event_type")
            h_id = ev.get("host_id", "")
            user = ev.get("user_name") or "unknown"
            details = ev.get("details", {}) or {}

            if ev_type == "account_created":
                uid = str(details.get("uid", ""))
                fp_raw = f"{h_id}:RULE-ACCT-BACKDOOR:CREATE:{ev['id']}"
                alert_id = f"ALT-ACCT-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                if alert_id in generated_ids:
                    continue
                generated_ids.add(alert_id)

                severity = "critical" if uid == "0" else "high"
                now_iso = datetime.now(timezone.utc).isoformat()
                alerts.append({
                    "id": alert_id,
                    "host_id": h_id,
                    "rule_id": "RULE-ACCT-BACKDOOR",
                    "rule_version": "1.0",
                    "title": "Unauthorized Local User Account Creation",
                    "severity": severity,
                    "detected_at": ev.get("event_timestamp") or now_iso,
                    "reason": f"New local account '{user}' (UID={uid or 'unassigned'}) created on host '{h_id}'.",
                    "created_at": now_iso,
                })
                evidence_links.append({
                    "alert_id": alert_id,
                    "event_id": ev["id"],
                    "citation_role": "trigger",
                })

            elif ev_type == "privilege_group_added":
                group_name = str(details.get("group", "")).lower()
                if group_name in self._PRIVILEGED_GROUPS:
                    fp_raw = f"{h_id}:RULE-ACCT-BACKDOOR:GROUP:{ev['id']}"
                    alert_id = f"ALT-ACCT-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                    if alert_id in generated_ids:
                        continue
                    generated_ids.add(alert_id)

                    now_iso = datetime.now(timezone.utc).isoformat()
                    alerts.append({
                        "id": alert_id,
                        "host_id": h_id,
                        "rule_id": "RULE-ACCT-BACKDOOR",
                        "rule_version": "1.0",
                        "title": f"Privilege Escalation via Group Membership ({group_name})",
                        "severity": "high",
                        "detected_at": ev.get("event_timestamp") or now_iso,
                        "reason": f"User '{user}' was added to privileged group '{group_name}' on host '{h_id}'.",
                        "created_at": now_iso,
                    })
                    evidence_links.append({
                        "alert_id": alert_id,
                        "event_id": ev["id"],
                        "citation_role": "trigger",
                    })

        return alerts, evidence_links

    def _evaluate_firewall_and_kernel(
        self,
        events: List[Dict[str, Any]],
        generated_ids: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        RULE-FW-PORTSCAN & RULE-KERNEL-EXPLOIT:
        - >= 4 UFW firewall blocks from same source IP within 5 minutes: Medium (RULE-FW-PORTSCAN).
        - Kernel segmentation fault in binary: High (RULE-KERNEL-EXPLOIT).
        """
        alerts: List[Dict[str, Any]] = []
        evidence_links: List[Dict[str, Any]] = []

        fw_blocks = [ev for ev in events if ev.get("event_type") == "firewall_block"]
        if len(fw_blocks) >= self.fw_scan_threshold:
            ip_groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
            for ev in fw_blocks:
                src_ip = ev.get("source_ip")
                if src_ip and src_ip not in ("unknown", ""):
                    ip_groups.setdefault((ev.get("host_id", ""), src_ip), []).append(ev)

            for (h_id, src_ip), cluster in ip_groups.items():
                if len(cluster) < self.fw_scan_threshold:
                    continue
                t_start = self._parse_timestamp(cluster[0].get("event_timestamp"))
                t_end = self._parse_timestamp(cluster[-1].get("event_timestamp"))
                diff_sec = (t_end - t_start).total_seconds()
                if 0 <= diff_sec <= self.fw_scan_window_sec:
                    trigger_ev = cluster[-1]
                    ports = sorted({
                        str((ev.get("details") or {}).get("dest_port", ""))
                        for ev in cluster
                        if (ev.get("details") or {}).get("dest_port")
                    })
                    fp_raw = f"{h_id}:RULE-FW-PORTSCAN:{src_ip}:{cluster[0]['id']}"
                    alert_id = f"ALT-FW-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                    if alert_id not in generated_ids:
                        generated_ids.add(alert_id)
                        now_iso = datetime.now(timezone.utc).isoformat()
                        port_desc = f" targeting ports {', '.join(ports[:6])}" if ports else ""
                        alerts.append({
                            "id": alert_id,
                            "host_id": h_id,
                            "rule_id": "RULE-FW-PORTSCAN",
                            "rule_version": "1.0",
                            "title": "Firewall Port Scan / Lateral Probe Blocked",
                            "severity": "medium",
                            "detected_at": trigger_ev.get("event_timestamp") or now_iso,
                            "reason": f"UFW blocked {len(cluster)} inbound packets from '{src_ip}'{port_desc} within {diff_sec:.0f}s.",
                            "created_at": now_iso,
                        })
                        for ev in cluster:
                            evidence_links.append({
                                "alert_id": alert_id,
                                "event_id": ev["id"],
                                "citation_role": "trigger" if ev["id"] == trigger_ev["id"] else "supporting",
                            })

        segfaults = [ev for ev in events if ev.get("event_type") == "kernel_segfault"]
        for ev in segfaults:
            h_id = ev.get("host_id", "")
            details = ev.get("details", {}) or {}
            proc = details.get("process_name", "unknown")
            lib = details.get("library", "unknown")
            fp_raw = f"{h_id}:RULE-KERNEL-EXPLOIT:{ev['id']}"
            alert_id = f"ALT-KRN-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
            if alert_id in generated_ids:
                continue
            generated_ids.add(alert_id)

            now_iso = datetime.now(timezone.utc).isoformat()
            alerts.append({
                "id": alert_id,
                "host_id": h_id,
                "rule_id": "RULE-KERNEL-EXPLOIT",
                "rule_version": "1.0",
                "title": "Kernel Segmentation Fault / Binary Crash Anomaly",
                "severity": "high",
                "detected_at": ev.get("event_timestamp") or now_iso,
                "reason": f"Kernel reported segmentation fault in process '{proc}' (module '{lib}'), indicating potential memory corruption or exploit attempt.",
                "created_at": now_iso,
            })
            evidence_links.append({
                "alert_id": alert_id,
                "event_id": ev["id"],
                "citation_role": "trigger",
            })

        return alerts, evidence_links

    def _evaluate_cron_and_systemd(
        self,
        events: List[Dict[str, Any]],
        generated_ids: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        RULE-CRON-PERSIST & RULE-DEFENSE-EVASION:
        - Cron execution matching suspicious payload (curl/wget/nc/reverse-shell/tmp): High (RULE-CRON-PERSIST).
        - Systemd stopping critical security service (ufw, auditd, ssh, fail2ban): Critical (RULE-DEFENSE-EVASION).
        """
        alerts: List[Dict[str, Any]] = []
        evidence_links: List[Dict[str, Any]] = []

        for ev in events:
            ev_type = ev.get("event_type")
            h_id = ev.get("host_id", "")
            user = ev.get("user_name") or "unknown"
            details = ev.get("details", {}) or {}

            if ev_type == "cron_execution":
                cmd = str(details.get("command", "")).strip()
                if cmd and self._RE_SUSPICIOUS_CRON.search(cmd):
                    fp_raw = f"{h_id}:RULE-CRON-PERSIST:{ev['id']}"
                    alert_id = f"ALT-CRON-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                    if alert_id in generated_ids:
                        continue
                    generated_ids.add(alert_id)

                    now_iso = datetime.now(timezone.utc).isoformat()
                    alerts.append({
                        "id": alert_id,
                        "host_id": h_id,
                        "rule_id": "RULE-CRON-PERSIST",
                        "rule_version": "1.0",
                        "title": "Suspicious Scheduled Cron Persistence Execution",
                        "severity": "high",
                        "detected_at": ev.get("event_timestamp") or now_iso,
                        "reason": f"Suspicious scheduled cron command executed under user '{user}': '{cmd}'.",
                        "created_at": now_iso,
                    })
                    evidence_links.append({
                        "alert_id": alert_id,
                        "event_id": ev["id"],
                        "citation_role": "trigger",
                    })

            elif ev_type == "service_stopped":
                unit = str(details.get("unit", "")).lower().strip()
                desc = str(details.get("unit_description", "")).lower()
                is_critical_unit = (
                    unit in self._CRITICAL_SERVICES
                    or any(tok in desc for tok in ("firewall", "ufw", "audit", "openssh", "fail2ban", "apparmor", "aegis"))
                )
                if is_critical_unit:
                    fp_raw = f"{h_id}:RULE-DEFENSE-EVASION:{ev['id']}"
                    alert_id = f"ALT-SVC-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                    if alert_id in generated_ids:
                        continue
                    generated_ids.add(alert_id)

                    now_iso = datetime.now(timezone.utc).isoformat()
                    target_unit = details.get("unit") or details.get("unit_description") or "security service"
                    alerts.append({
                        "id": alert_id,
                        "host_id": h_id,
                        "rule_id": "RULE-DEFENSE-EVASION",
                        "rule_version": "1.0",
                        "title": "Critical Security Service Stopped (Defense Evasion)",
                        "severity": "critical",
                        "detected_at": ev.get("event_timestamp") or now_iso,
                        "reason": f"Critical defensive or monitoring service '{target_unit}' was stopped or deactivated on host '{h_id}'.",
                        "created_at": now_iso,
                    })
                    evidence_links.append({
                        "alert_id": alert_id,
                        "event_id": ev["id"],
                        "citation_role": "trigger",
                    })

        return alerts, evidence_links

    def _evaluate_critical_file_tamper(
        self,
        events: List[Dict[str, Any]],
        generated_ids: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        RULE-SSH-KEY-BACKDOOR:
        - Modification or tampering of SSH authorized_keys, /etc/ssh/sshd_config, or /etc/sudoers: Critical.
        """
        alerts: List[Dict[str, Any]] = []
        evidence_links: List[Dict[str, Any]] = []

        for ev in events:
            if ev.get("event_type") != "critical_file_modified":
                continue
            h_id = ev.get("host_id", "")
            user = ev.get("user_name") or "unknown"
            details = ev.get("details", {}) or {}
            target_file = details.get("target_file", "critical file")
            cmd = details.get("command", "")

            fp_raw = f"{h_id}:RULE-SSH-KEY-BACKDOOR:{ev['id']}"
            alert_id = f"ALT-KEY-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
            if alert_id in generated_ids:
                continue
            generated_ids.add(alert_id)

            now_iso = datetime.now(timezone.utc).isoformat()
            alerts.append({
                "id": alert_id,
                "host_id": h_id,
                "rule_id": "RULE-SSH-KEY-BACKDOOR",
                "rule_version": "1.0",
                "title": "Critical Security File / SSH Authorized Keys Tampering",
                "severity": "critical",
                "detected_at": ev.get("event_timestamp") or now_iso,
                "reason": (
                    f"Detected modification of sensitive security file '{target_file}' "
                    f"by user '{user}'" + (f" via '{cmd}'." if cmd else ".")
                ),
                "created_at": now_iso,
            })
            evidence_links.append({
                "alert_id": alert_id,
                "event_id": ev["id"],
                "citation_role": "trigger",
            })

        return alerts, evidence_links

    def _evaluate_defense_apt_rules(
        self,
        events: List[Dict[str, Any]],
        generated_ids: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Defense-Grade APT Rules for Critical Infrastructure & Military Cyber Defense:
        - RULE-ANTI-FORENSICS (MITRE T1070): Audit log wiping, command history clearing, shred/truncate. Severity: Critical.
        - RULE-DATA-EXFIL (MITRE T1041 / T1560): Sensitive data archiving or network exfiltration (scp/rsync/curl). Severity: Critical.
        - RULE-ROOTKIT-SNIFF (MITRE T1547.006 / T1040): Kernel module insertion (insmod/modprobe) or promiscuous sniffing. Severity: Critical.
        """
        alerts: List[Dict[str, Any]] = []
        evidence_links: List[Dict[str, Any]] = []

        for ev in events:
            ev_type = ev.get("event_type")
            h_id = ev.get("host_id", "")
            user = ev.get("user_name") or "unknown"
            details = ev.get("details", {}) or {}
            cmd = details.get("command", "")
            now_iso = datetime.now(timezone.utc).isoformat()

            if ev_type == "anti_forensics_execution":
                fp_raw = f"{h_id}:RULE-ANTI-FORENSICS:{ev['id']}"
                alert_id = f"ALT-FORENSIC-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                if alert_id in generated_ids:
                    continue
                generated_ids.add(alert_id)
                ind = details.get("matched_indicator", "log/history tampering")
                alerts.append({
                    "id": alert_id,
                    "host_id": h_id,
                    "rule_id": "RULE-ANTI-FORENSICS",
                    "rule_version": "1.0",
                    "title": "Anti-Forensics Log Wiping & History Erasure (MITRE T1070)",
                    "severity": "critical",
                    "detected_at": ev.get("event_timestamp") or now_iso,
                    "reason": (
                        f"Detected anti-forensics indicator '{ind}' executed by '{user}' on host '{h_id}'"
                        + (f": {cmd}" if cmd else ".")
                    ),
                    "created_at": now_iso,
                })
                evidence_links.append({
                    "alert_id": alert_id,
                    "event_id": ev["id"],
                    "citation_role": "trigger",
                })

            elif ev_type == "data_exfiltration_attempt":
                fp_raw = f"{h_id}:RULE-DATA-EXFIL:{ev['id']}"
                alert_id = f"ALT-EXFIL-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                if alert_id in generated_ids:
                    continue
                generated_ids.add(alert_id)
                stage = details.get("exfil_stage", "data_exfiltration")
                dst = details.get("destination_ip") or ev.get("source_ip") or "external destination"
                alerts.append({
                    "id": alert_id,
                    "host_id": h_id,
                    "rule_id": "RULE-DATA-EXFIL",
                    "rule_version": "1.0",
                    "title": "Sensitive Data Staging & Outbound Exfiltration (MITRE T1041)",
                    "severity": "critical",
                    "detected_at": ev.get("event_timestamp") or now_iso,
                    "reason": (
                        f"Detected sensitive {stage.replace('_', ' ')} initiated by '{user}' targeting '{dst}' on host '{h_id}'"
                        + (f": {cmd}" if cmd else ".")
                    ),
                    "created_at": now_iso,
                })
                evidence_links.append({
                    "alert_id": alert_id,
                    "event_id": ev["id"],
                    "citation_role": "trigger",
                })

            elif ev_type == "rootkit_or_sniff_activity":
                fp_raw = f"{h_id}:RULE-ROOTKIT-SNIFF:{ev['id']}"
                alert_id = f"ALT-ROOTKIT-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
                if alert_id in generated_ids:
                    continue
                generated_ids.add(alert_id)
                act = details.get("activity_type", "kernel_or_sniff")
                iface = details.get("interface")
                mod_path = details.get("module_path")
                desc = (
                    f"network interface '{iface}' entered promiscuous packet sniffing mode"
                    if act == "promiscuous_sniffing" and iface
                    else f"unauthorized kernel module or packet capture operation ({mod_path or cmd})"
                )
                alerts.append({
                    "id": alert_id,
                    "host_id": h_id,
                    "rule_id": "RULE-ROOTKIT-SNIFF",
                    "rule_version": "1.0",
                    "title": "Kernel Rootkit Module Load / Promiscuous Network Sniffing (MITRE T1547.006)",
                    "severity": "critical",
                    "detected_at": ev.get("event_timestamp") or now_iso,
                    "reason": f"Detected {desc} on host '{h_id}' under user '{user}'.",
                    "created_at": now_iso,
                })
                evidence_links.append({
                    "alert_id": alert_id,
                    "event_id": ev["id"],
                    "citation_role": "trigger",
                })

        return alerts, evidence_links

    def _evaluate_container_and_k8s_rules(
        self,
        events: List[Dict[str, Any]],
        generated_ids: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Evaluates Docker/Container Runtime and Kubernetes Control Plane Audit events:
        - RULE-CONTAINER-EXEC (high)
        - RULE-CONTAINER-ESCAPE-RISK (critical)
        - RULE-CONTAINER-OOM-CRASH (medium)
        - RULE-K8S-POD-EXEC (high)
        - RULE-K8S-RBAC-ESCALATION (critical)
        - RULE-K8S-SECRET-ACCESS (high)
        - RULE-K8S-PRIVILEGED-POD (critical)
        """
        alerts: List[Dict[str, Any]] = []
        evidence_links: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        rule_map = {
            "container_exec_shell": (
                "RULE-CONTAINER-EXEC",
                "ALT-CTREXEC",
                "Interactive Shell Execution Inside Running Container (MITRE T1609)",
                "high",
            ),
            "privileged_container_started": (
                "RULE-CONTAINER-ESCAPE-RISK",
                "ALT-CTRESC",
                "Privileged Container or Docker Socket Mount Detected (MITRE T1611)",
                "critical",
            ),
            "container_oom_or_crash": (
                "RULE-CONTAINER-OOM-CRASH",
                "ALT-CTRDIE",
                "Abnormal Container Termination / OOMKilled Detected",
                "medium",
            ),
            "k8s_pod_exec": (
                "RULE-K8S-POD-EXEC",
                "ALT-K8SEXEC",
                "Kubernetes Pod Exec / Interactive Attach Detected (MITRE T1609)",
                "high",
            ),
            "k8s_rbac_escalation": (
                "RULE-K8S-RBAC-ESCALATION",
                "ALT-K8SRBAC",
                "Kubernetes RBAC RoleBinding / ClusterRoleBinding Escalation (MITRE T1098)",
                "critical",
            ),
            "k8s_secret_access": (
                "RULE-K8S-SECRET-ACCESS",
                "ALT-K8SSEC",
                "Kubernetes Secret Access Recorded in Audit Stream (MITRE T1552.007)",
                "high",
            ),
            "k8s_privileged_pod": (
                "RULE-K8S-PRIVILEGED-POD",
                "ALT-K8SPRIV",
                "Privileged / Host-Namespace Kubernetes Pod Created (MITRE T1611)",
                "critical",
            ),
        }

        for ev in events:
            ev_type = ev.get("event_type")
            if ev_type not in rule_map:
                continue
            rule_id, alt_prefix, title, severity = rule_map[ev_type]
            h_id = ev.get("host_id") or "unknown"
            fp_raw = f"{h_id}:{rule_id}:{ev['id']}"
            alert_id = f"{alt_prefix}-{hashlib.sha256(fp_raw.encode()).hexdigest()[:16]}"
            if alert_id in generated_ids:
                continue
            generated_ids.add(alert_id)

            details = ev.get("details") or {}
            reason = details.get("raw_summary") or ev.get("message") or f"{rule_id} triggered on host '{h_id}'."
            alerts.append({
                "id": alert_id,
                "host_id": h_id,
                "rule_id": rule_id,
                "rule_version": "1.0",
                "title": title,
                "severity": severity,
                "detected_at": ev.get("event_timestamp") or now_iso,
                "reason": reason,
                "created_at": now_iso,
            })
            evidence_links.append({
                "alert_id": alert_id,
                "event_id": ev["id"],
                "citation_role": "trigger",
            })

        return alerts, evidence_links


