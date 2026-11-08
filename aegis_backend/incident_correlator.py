"""
AEGIS Incident Correlation Engine.
Correlates discrete security alerts and telemetry evidence into unified security incidents.

Correlation Criteria:
1. Strict Host Isolation: Cross-host alert conflation is strictly forbidden.
2. Temporal Window: Alerts occurring within a configurable sliding window (default 30m / 1800s).
3. Pivot Continuity Requirement (Mandatory):
   Alerts must be linked by at least one verifiable pivot:
   - Shared Source IP address.
   - Shared Target Username.
   - Verified Causal Progression (e.g. Brute Force -> Account Compromise -> Root Escalation).
   Unrelated administrator actions or independent attacks from separate source IPs are segregated.
4. Explainable Correlation: Generates human-auditable correlation reasons for each group.
"""

import re
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple
from aegis_backend.risk_assessment import RiskAssessmentEngine, RiskAssessmentResult


class CorrelatedIncident:
    """Represents a grouped cluster of alerts forming an incident."""

    def __init__(
        self,
        incident_id: str,
        host_id: str,
        title: str,
        severity: str,
        primary_alert_id: str,
        alerts: List[Dict[str, Any]],
        source_ip: Optional[str] = None,
        target_user: Optional[str] = None,
        attack_scenario: Optional[str] = None,
        correlation_reason: Optional[str] = None,
        first_seen_at: Optional[str] = None,
        last_seen_at: Optional[str] = None,
        risk_result: Optional[RiskAssessmentResult] = None,
    ):
        self.incident_id = incident_id
        self.host_id = host_id
        self.title = title
        self.severity = severity
        self.primary_alert_id = primary_alert_id
        self.alerts = alerts
        self.source_ip = source_ip
        self.target_user = target_user
        self.attack_scenario = attack_scenario
        self.correlation_reason = correlation_reason or "Correlated via temporal and entity proximity."
        self.first_seen_at = first_seen_at or datetime.now(timezone.utc).isoformat()
        self.last_seen_at = last_seen_at or self.first_seen_at
        self.risk_result = risk_result or RiskAssessmentResult(risk_score=0, risk_level="low")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.incident_id,
            "host_id": self.host_id,
            "title": self.title,
            "severity": self.severity,
            "risk_level": self.risk_result.risk_level,
            "risk_score": self.risk_result.risk_score,
            "status": "new",
            "primary_alert_id": self.primary_alert_id,
            "alert_count": len(self.alerts),
            "source_ip": self.source_ip,
            "target_user": self.target_user,
            "attack_scenario": self.attack_scenario,
            "correlation_reason": self.correlation_reason,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "risk_factors": [f.__dict__ for f in self.risk_result.risk_factors],
            "storage_backend": "sqlite_local",
        }


class IncidentCorrelator:
    """Clusters alerts into cohesive incidents per host with pivot continuity validation."""

    def __init__(self, time_window_seconds: int = 1800):  # 30 minutes
        self.time_window_seconds = time_window_seconds

    @staticmethod
    def _parse_ts(ts_str: Optional[str]) -> datetime:
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    @classmethod
    def generate_incident_id(cls, host_id: str, alert_ids: List[str]) -> str:
        """Generates a stable, reproducible incident identifier."""
        sorted_ids = sorted(alert_ids)
        digest = hashlib.sha256(f"{host_id}:{':'.join(sorted_ids)}".encode()).hexdigest()[:12]
        return f"INC-{host_id}-{digest}"

    @classmethod
    def _extract_entities(cls, alert: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
        """Extracts source IPs and usernames from alert reason and details."""
        ips = set()
        users = set()

        reason = str(alert.get("reason", ""))
        # Match IPv4 addresses
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", reason):
            ips.add(ip)

        # Match user patterns
        for u in re.findall(r"user ['\"]([^'\"]+)['\"]", reason):
            users.add(u)
        for u in re.findall(r"for user ([a-zA-Z0-9_\-]+)", reason):
            users.add(u)

        return ips, users

    def _can_correlate(
        self,
        alert: Dict[str, Any],
        cluster: List[Dict[str, Any]],
    ) -> Tuple[bool, Optional[str]]:
        """
        Determines if an alert belongs to an existing cluster based on:
        1. Temporal proximity (<= time_window_seconds).
        2. Pivot continuity: shared IP, shared user, or causal attack progression.
        """
        alert_ts = self._parse_ts(alert.get("detected_at"))
        latest_in_cluster = max(self._parse_ts(a.get("detected_at")) for a in cluster)
        earliest_in_cluster = min(self._parse_ts(a.get("detected_at")) for a in cluster)

        # Check temporal window against latest activity
        delta = abs((alert_ts - latest_in_cluster).total_seconds())
        if delta > self.time_window_seconds:
            return False, None

        alert_ips, alert_users = self._extract_entities(alert)
        alert_rule = alert.get("rule_id", "")

        # Extract IP and User entities
        alert_ips, alert_users = self._extract_entities(alert)
        alert_rule = alert.get("rule_id", "")

        cluster_ips: Set[str] = set()
        cluster_users: Set[str] = set()
        cluster_rules: Set[str] = set()
        cluster_auth_users: Set[str] = set()
        has_auth_success = False

        for a in cluster:
            ips, users = self._extract_entities(a)
            cluster_ips.update(ips)
            cluster_users.update(users)
            r = a.get("rule_id", "")
            cluster_rules.add(r)
            if r == "RULE-AUTH-003":
                has_auth_success = True
                cluster_auth_users.update(users)

        shared_ips = alert_ips & cluster_ips
        shared_users = alert_users & cluster_users

        # 1. Independent Brute-Force Attacks Isolation
        # If incoming alert is brute-force and cluster already has brute-force, require shared Source IP.
        # Different IPs targeting common usernames (e.g. 'ubuntu', 'root') must remain distinct incidents.
        if alert_rule == "RULE-SSH-BRUTE" and "RULE-SSH-BRUTE" in cluster_rules:
            if shared_ips:
                ip_str = ", ".join(sorted(shared_ips))
                return True, f"Shared Source IP pivot ({ip_str}) in continuing brute-force campaign."
            return False, None

        # 2. Strict Causal Attack Progression: Failed Brute-Force -> Accepted Login
        if ("RULE-SSH-BRUTE" in cluster_rules) and (alert_rule == "RULE-AUTH-003"):
            if shared_ips:
                ip_str = ", ".join(sorted(shared_ips))
                return True, f"Causal attack chain progression: Repeated failed logins followed by successful authentication from {ip_str}."
            if shared_users:
                user_str = ", ".join(sorted(shared_users))
                return True, f"Causal attack chain progression: Repeated failed logins followed by successful authentication for user '{user_str}'."
            return False, None

        # 3. Strict Causal Attack Progression: Accepted Login -> Suspicious Sudo Execution
        if alert_rule == "RULE-SUSP-SUDO":
            if has_auth_success:
                # Require that sudo is executed by the user who just authenticated (or shared IP)
                matching_users = alert_users & cluster_auth_users
                if matching_users:
                    user_str = ", ".join(sorted(matching_users))
                    return True, f"Causal attack chain progression: Successful authentication followed by privileged sudo execution by user '{user_str}'."
                if shared_ips:
                    ip_str = ", ".join(sorted(shared_ips))
                    return True, f"Causal attack chain progression: Activity from authenticated session origin {ip_str} followed by privileged sudo execution."
            # If the cluster only has failed brute-force and NO accepted authentication,
            # an unlinked sudo (even by 'ubuntu') must NOT be conflated with the brute force attacker!
            return False, None

        # 4. Shared Source IP Pivot across other detections
        if shared_ips:
            ip_str = ", ".join(sorted(shared_ips))
            return True, f"Shared Source IP pivot ({ip_str}) with activity occurring within {int(delta)}s."

        # 5. Shared Target User Pivot (Only for authenticated sessions or explicit user pivots)
        if shared_users and (has_auth_success or alert_rule == "RULE-AUTH-003"):
            user_str = ", ".join(sorted(shared_users))
            return True, f"Shared Target User pivot ('{user_str}') across correlated detections."

        return False, None

    def correlate(
        self,
        alerts: List[Dict[str, Any]],
        posture_findings: Optional[List[Dict[str, Any]]] = None,
        evidence_counts: Optional[Dict[str, int]] = None,
    ) -> List[CorrelatedIncident]:
        """
        Groups alerts by host, sorts chronologically, and forms clusters
        connected by verified pivot continuity.
        """
        if not alerts:
            return []

        evidence_counts = evidence_counts or {}

        # 1. Partition strictly by host_id (Zero Cross-Host Contamination)
        by_host: Dict[str, List[Dict[str, Any]]] = {}
        for a in alerts:
            hid = a.get("host_id", "")
            if hid:
                by_host.setdefault(hid, []).append(a)

        incidents: List[CorrelatedIncident] = []

        for host_id, host_alerts in by_host.items():
            # Sort alerts chronologically
            sorted_alerts = sorted(
                host_alerts,
                key=lambda a: self._parse_ts(a.get("detected_at")),
            )

            # Cluster alerts by pivot continuity
            clusters: List[List[Dict[str, Any]]] = []
            cluster_reasons: List[List[str]] = []

            for alert in sorted_alerts:
                matched_idx = None
                matched_reason = None

                for idx, cluster in enumerate(clusters):
                    can_corr, reason = self._can_correlate(alert, cluster)
                    if can_corr:
                        matched_idx = idx
                        matched_reason = reason
                        break

                if matched_idx is not None:
                    clusters[matched_idx].append(alert)
                    if matched_reason:
                        cluster_reasons[matched_idx].append(matched_reason)
                else:
                    clusters.append([alert])
                    cluster_reasons.append([])

            # For each cluster, synthesize a CorrelatedIncident
            for idx, cluster in enumerate(clusters):
                reasons = cluster_reasons[idx]
                combined_reason = "; ".join(dict.fromkeys(reasons)) if reasons else "Single isolated security detection on host."
                incident = self._build_incident_from_cluster(
                    host_id=host_id,
                    cluster=cluster,
                    posture_findings=posture_findings,
                    evidence_counts=evidence_counts,
                    correlation_reason=combined_reason,
                )
                incidents.append(incident)

        return incidents

    def _build_incident_from_cluster(
        self,
        host_id: str,
        cluster: List[Dict[str, Any]],
        posture_findings: Optional[List[Dict[str, Any]]],
        evidence_counts: Dict[str, int],
        correlation_reason: str,
    ) -> CorrelatedIncident:
        alert_ids = [a.get("id") for a in cluster]
        incident_id = self.generate_incident_id(host_id, alert_ids)

        # Entity extraction
        source_ips: Set[str] = set()
        users: Set[str] = set()
        rule_ids: Set[str] = set()
        severities = []

        for a in cluster:
            rule_ids.add(a.get("rule_id", ""))
            severities.append(a.get("severity", "low").lower())
            ips, us = self._extract_entities(a)
            source_ips.update(ips)
            users.update(us)

        # Highest severity (Rule Engine immutability)
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        highest_sev = max(severities, key=lambda s: sev_rank.get(s, 0), default="medium")

        # Determine Primary Alert (highest severity or earliest trigger)
        primary_alert = min(
            cluster,
            key=lambda a: (-sev_rank.get(a.get("severity", "low").lower(), 0), a.get("detected_at")),
        )

        first_seen = min(a.get("detected_at") for a in cluster)
        last_seen = max(a.get("detected_at") for a in cluster)

        # Compute total evidence count across all alerts in cluster
        total_evidence = sum(evidence_counts.get(a.get("id", ""), 0) for a in cluster)

        # Evaluate risk score
        risk_result = RiskAssessmentEngine.evaluate(
            alerts=cluster,
            evidence_count=total_evidence,
            posture_findings=posture_findings,
        )

        # Synthesize Title and Attack Scenario
        has_brute = "RULE-SSH-BRUTE" in rule_ids
        has_auth = "RULE-AUTH-003" in rule_ids
        has_sudo = "RULE-SUSP-SUDO" in rule_ids

        primary_ip = sorted(list(source_ips))[0] if source_ips else None
        primary_user = sorted(list(users))[0] if users else None

        if has_brute and has_auth and has_sudo:
            title = f"Multi-Stage Brute-Force to Privileged Sudo Shell on {host_id}"
            scenario = (
                f"Adversary launched automated SSH authentication brute-force from {primary_ip or 'external IP'}, "
                f"succeeded in authenticating as user '{primary_user or 'account'}', and executed privileged root shell via sudo."
            )
        elif has_auth and has_sudo:
            title = f"Compromised Account Login Followed by Privileged Sudo on {host_id}"
            scenario = (
                f"Account '{primary_user or 'user'}' authenticated successfully after multiple failures, "
                f"followed immediately by suspicious privileged commands via sudo."
            )
        elif has_brute and has_auth:
            title = f"SSH Brute-Force with Successful Login on {host_id}"
            scenario = (
                f"Repeated SSH authentication failures from {primary_ip or 'remote IP'} culminated in a successful login."
            )
        elif has_sudo:
            title = f"Suspicious Sudo Privileged Execution on {host_id}"
            scenario = f"User '{primary_user or 'privileged user'}' executed potentially hazardous commands or root shells via sudo."
        elif has_brute:
            title = f"Repeated SSH Authentication Failures (Brute-Force) on {host_id}"
            scenario = f"External source IP {primary_ip or 'unknown'} generated repeated authentication failures against SSH."
        else:
            title = f"Security Event Cluster ({len(cluster)} alerts) on {host_id}"
            scenario = primary_alert.get("reason", "Multiple security alerts detected in close temporal proximity.")

        return CorrelatedIncident(
            incident_id=incident_id,
            host_id=host_id,
            title=title,
            severity=highest_sev,
            primary_alert_id=primary_alert.get("id", ""),
            alerts=cluster,
            source_ip=primary_ip,
            target_user=primary_user,
            attack_scenario=scenario,
            correlation_reason=correlation_reason,
            first_seen_at=first_seen,
            last_seen_at=last_seen,
            risk_result=risk_result,
        )
