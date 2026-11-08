"""
AEGIS Incident Context Builder.
Constructs comprehensive, sanitized, grounded forensic contexts for AI analysis.

Guarantees:
1. Ground Truth Only: Never fabricates events or evidence IDs.
2. Sanitization Boundary: Masks secrets, tokens, and credentials via TelemetrySanitizer.
3. Prompt Injection Defense: Treats raw telemetry logs as untrusted forensic artifacts.
4. Security Checker Posture Integration: Enriches context with host configuration findings.
"""

from typing import List, Dict, Any, Set, Optional
from aegis_backend.sanitizer import TelemetrySanitizer


class IncidentContext:
    """Encapsulates all verified forensic context for an incident."""

    def __init__(
        self,
        incident_id: str,
        host_id: str,
        title: str,
        severity: str,
        alerts: List[Dict[str, Any]],
        evidence_items: List[Dict[str, Any]],
        posture_findings: Optional[List[Dict[str, Any]]] = None,
        source_ip: Optional[str] = None,
        target_user: Optional[str] = None,
        attack_scenario: Optional[str] = None,
    ):
        self.incident_id = incident_id
        self.host_id = host_id
        self.title = title
        self.severity = severity
        self.alerts = alerts
        self.evidence_items = evidence_items
        self.posture_findings = posture_findings or []
        self.source_ip = source_ip
        self.target_user = target_user
        self.attack_scenario = attack_scenario
        self.allowed_evidence_ids: Set[str] = {
            ev.get("event_id") or ev.get("id") for ev in evidence_items if (ev.get("event_id") or ev.get("id"))
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "host_id": self.host_id,
            "title": self.title,
            "severity": self.severity,
            "alerts": self.alerts,
            "evidence": self.evidence_items,
            "posture": self.posture_findings,
            "entities": {
                "source_ip": self.source_ip,
                "target_user": self.target_user,
            },
            "attack_scenario": self.attack_scenario,
            "allowed_evidence_ids": sorted(list(self.allowed_evidence_ids)),
        }


class IncidentContextBuilder:
    """Builds and sanitizes forensic investigation context from repository data."""

    @classmethod
    def build(
        cls,
        incident: Dict[str, Any],
        alerts: List[Dict[str, Any]],
        evidence_items: List[Dict[str, Any]],
        posture_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> IncidentContext:
        sanitizer = TelemetrySanitizer()

        # Sanitize alerts
        sanitized_alerts: List[Dict[str, Any]] = []
        for a in alerts:
            clean_a = dict(a)
            if "reason" in clean_a:
                clean_a["reason"] = sanitizer.mask_text(str(clean_a["reason"]))
            sanitized_alerts.append(clean_a)

        # Sanitize evidence items
        sanitized_evidence: List[Dict[str, Any]] = []
        for ev in evidence_items:
            clean_ev = dict(ev)
            if "message" in clean_ev:
                clean_ev["message"] = sanitizer.mask_text(str(clean_ev["message"]))
            if "details" in clean_ev and isinstance(clean_ev["details"], dict):
                clean_ev["details"] = sanitizer.mask_dict(clean_ev["details"])
            # Normalize event_id key
            ev_id = clean_ev.get("event_id") or clean_ev.get("id")
            clean_ev["event_id"] = ev_id
            sanitized_evidence.append(clean_ev)

        # Filter relevant posture findings for this host
        host_id = incident.get("host_id", "")
        relevant_posture: List[Dict[str, Any]] = []
        if posture_findings:
            for pf in posture_findings:
                if pf.get("host_id") == host_id and pf.get("status") in ("fail", "warning"):
                    relevant_posture.append({
                        "check_id": pf.get("check_id"),
                        "category": pf.get("category"),
                        "status": pf.get("status"),
                        "title": pf.get("title") or pf.get("check_name"),
                        "actual_value": sanitizer.mask_text(str(pf.get("actual_value", ""))),
                        "expected_value": str(pf.get("expected_value", "")),
                    })

        return IncidentContext(
            incident_id=incident.get("id", ""),
            host_id=host_id,
            title=incident.get("title", ""),
            severity=incident.get("severity", "medium"),
            alerts=sanitized_alerts,
            evidence_items=sanitized_evidence,
            posture_findings=relevant_posture,
            source_ip=incident.get("source_ip"),
            target_user=incident.get("target_user"),
            attack_scenario=incident.get("attack_scenario"),
        )

