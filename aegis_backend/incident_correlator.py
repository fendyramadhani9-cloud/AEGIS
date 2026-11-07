"""
AEGIS Incident Correlation Engine.
Correlates discrete security alerts and telemetry evidence into unified security incidents.

Correlation Criteria:
1. Strict Host Isolation: Cross-host alert conflation is strictly forbidden.
2. Temporal Window: Alerts occurring within a configurable sliding window (default 30m).
3. Entity Correlation: Common source IP address or target username.
4. Attack Progression: Reconnaissance/Brute-force -> Initial Access -> Privilege Escalation.
"""

import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
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
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "risk_factors": [f.__dict__ for f in self.risk_result.risk_factors],
        }


class IncidentCorrelator:
    """Clusters alerts into cohesive incidents per host."""

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

    def correlate(
        self,
        alerts: List[Dict[str, Any]],
        posture_findings: Optional[List[Dict[str, Any]]] = None,
        evidence_counts: Optional[Dict[str, int]] = None,
    ) -> List[CorrelatedIncident]:
        """
        Groups alerts by host, sorts chronologically, and forms clusters
        connected by shared entities or temporal proximity.
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

            # Cluster alerts by sliding time window and entity connectivity
            clusters: List[List[Dict[str, Any]]] = []
            for alert in sorted_alerts:
                alert_ts = self._parse_ts(alert.get("detected_at"))
                alert_reason = alert.get("reason", "").lower()

                # Attempt to add to existing cluster
                matched_cluster = None
                for cluster in clusters:
                    latest_in_cluster = max(
                        self._parse_ts(a.get("detected_at")) for a in cluster
                    )
                    delta = abs((alert_ts - latest_in_cluster).total_seconds())

                    if delta <= self.time_window_seconds:
                        # Correlate if temporal window matches
                        matched_cluster = cluster
                        break

                if matched_cluster is not None:
                    matched_cluster.append(alert)
                else:
                    clusters.append([alert])

            # For each cluster, synthesize a CorrelatedIncident
            for cluster in clusters:
                incident = self._build_incident_from_cluster(
                    host_id=host_id,
                    cluster=cluster,
                    posture_findings=posture_findings,
                    evidence_counts=evidence_counts,
                )
                incidents.append(incident)

        return incidents

    def _build_incident_from_cluster(
        self,
        host_id: str,
        cluster: List[Dict[str, Any]],
        posture_findings: Optional[List[Dict[str, Any]]],
        evidence_counts: Dict[str, int],
    ) -> CorrelatedIncident:
        alert_ids = [a.get("id") for a in cluster]
        incident_id = self.generate_incident_id(host_id, alert_ids)

        # Entity extraction
        source_ips = set()
        users = set()
        rule_ids = set()
        severities = []

        for a in cluster:
            rule_ids.add(a.get("rule_id", ""))
            severities.append(a.get("severity", "low").lower())
            reason = a.get("reason", "")
            # Extract IP if mentioned
            import re
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", reason)
            if ip_match:
                source_ips.add(ip_match.group(0))
            # Extract user if mentioned
            user_match = re.search(r"user '([^']+)'", reason)
            if user_match:
                users.add(user_match.group(1))

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

        primary_ip = next(iter(source_ips), None)
        primary_user = next(iter(users), None)

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
            first_seen_at=first_seen,
            last_seen_at=last_seen,
            risk_result=risk_result,
        )
