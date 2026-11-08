"""
AEGIS Incident Context Builder.
Constructs comprehensive, sanitized, grounded forensic contexts for AI analysis.

Guarantees:
1. Ground Truth Only: Never fabricates events or evidence IDs.
2. Sanitization Boundary: Masks secrets, tokens, and credentials via TelemetrySanitizer.
3. Prompt Injection Defense: Treats raw telemetry logs as untrusted forensic artifacts.
4. Security Checker Posture Integration: Enriches context with host configuration findings.
5. Source Attribution & Provenance: Explicitly binds network classification and data provenance.
"""

from typing import List, Dict, Any, Set, Optional
from aegis_backend.sanitizer import TelemetrySanitizer
from aegis_backend.source_attribution import classify_ip_source


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
        risk_score: int = 0,
        risk_level: str = "low",
        provenance: str = "genuine_host_telemetry",
        risk_factors: Optional[List[Dict[str, Any]]] = None,
        allowed_evidence_ids: Optional[Set[str]] = None,
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
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.provenance = provenance
        self.risk_factors = risk_factors or []
        self.source_attribution = classify_ip_source(self.source_ip)
        self.allowed_evidence_ids: Set[str] = allowed_evidence_ids or {
            ev.get("event_id") or ev.get("id") for ev in evidence_items if (ev.get("event_id") or ev.get("id"))
        }

    def to_dict(self) -> Dict[str, Any]:
        risk_factor_summary = [
            f"[{rf.get('category', 'general').upper()}] {rf.get('factor_name', rf.get('name', 'Risk Factor'))} (+{rf.get('points', 0)} pts): {rf.get('description', '')}"
            for rf in self.risk_factors
        ]
        return {
            "incident_id": self.incident_id,
            "host_id": self.host_id,
            "title": self.title,
            "severity": self.severity,
            "official_risk_score": self.risk_score,
            "official_risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
            "risk_factor_summary": risk_factor_summary,
            "provenance": self.provenance,
            "source_attribution": classify_ip_source(self.source_ip),
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
        risk_factors: Optional[List[Dict[str, Any]]] = None,
    ) -> IncidentContext:
        sanitizer = TelemetrySanitizer()

        # Sanitize alerts
        sanitized_alerts: List[Dict[str, Any]] = []
        alert_referenced_evidence_ids: Set[str] = set()
        for a in alerts:
            clean_a = dict(a)
            if "reason" in clean_a:
                clean_a["reason"] = sanitizer.mask_text(str(clean_a["reason"]))
            sanitized_alerts.append(clean_a)
            for eid in clean_a.get("evidence_ids", []) or []:
                if eid:
                    alert_referenced_evidence_ids.add(str(eid))

        # Build complete set of allowed evidence IDs before any budgeting
        all_allowed_ids: Set[str] = set()
        for ev in evidence_items:
            eid = ev.get("event_id") or ev.get("id")
            if eid:
                all_allowed_ids.add(str(eid))

        # Sanitize and prioritize evidence items (token budgeting: max 15 prioritized items)
        sanitized_evidence: List[Dict[str, Any]] = []
        for ev in evidence_items:
            clean_ev = dict(ev)
            if "message" in clean_ev:
                clean_ev["message"] = sanitizer.mask_text(str(clean_ev["message"]))
            if "details" in clean_ev and isinstance(clean_ev["details"], dict):
                clean_ev["details"] = sanitizer.mask_dict(clean_ev["details"])
            # Normalize event_id key
            ev_id = clean_ev.get("event_id") or clean_ev.get("id")
            clean_ev["event_id"] = str(ev_id) if ev_id else None
            sanitized_evidence.append(clean_ev)

        # Prioritization: trigger / alert-referenced > failure/escalation > others
        def _evidence_priority(item: Dict[str, Any]) -> int:
            eid = item.get("event_id")
            score = 0
            if eid and eid in alert_referenced_evidence_ids:
                score += 10
            msg = str(item.get("message", "")).lower()
            if any(k in msg for k in ("fail", "invalid", "root", "sudo", "error", "denied")):
                score += 5
            return score

        sanitized_evidence.sort(key=_evidence_priority, reverse=True)
        budgeted_evidence = sanitized_evidence[:15]

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

        resolved_risk_factors = risk_factors or incident.get("risk_factors") or []

        return IncidentContext(
            incident_id=incident.get("id", ""),
            host_id=host_id,
            title=incident.get("title", ""),
            severity=incident.get("severity", "medium"),
            alerts=sanitized_alerts,
            evidence_items=budgeted_evidence,
            posture_findings=relevant_posture,
            source_ip=incident.get("source_ip"),
            target_user=incident.get("target_user"),
            attack_scenario=incident.get("attack_scenario"),
            risk_score=incident.get("risk_score", 0),
            risk_level=incident.get("risk_level", incident.get("severity", "medium")),
            provenance=incident.get("provenance", "genuine_host_telemetry"),
            risk_factors=resolved_risk_factors,
            allowed_evidence_ids=all_allowed_ids,
        )
