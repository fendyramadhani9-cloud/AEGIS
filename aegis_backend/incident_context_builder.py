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

        # Stratified Forensic Sampling (Token budgeting: max 15 prioritized items)
        # Guarantees that in high-volume attacks (1,000+ events), critical milestone events
        # (auth success, sudo execution, persistence/config changes) and temporal boundaries are not crowded out
        # by repetitive brute-force failure logs.
        budget_limit = 15

        if len(evidence_items) <= budget_limit:
            selected_raw_items = list(evidence_items)
        else:
            bucket_triggers: List[Dict[str, Any]] = []
            bucket_milestones: List[Dict[str, Any]] = []
            bucket_anomalies: List[Dict[str, Any]] = []
            bucket_others: List[Dict[str, Any]] = []

            for ev in evidence_items:
                eid = str(ev.get("event_id") or ev.get("id") or "")
                msg = str(ev.get("message", "")).lower()
                etype = str(ev.get("event_type", "")).lower()

                if eid and eid in alert_referenced_evidence_ids:
                    bucket_triggers.append(ev)
                elif (
                    any(k in msg for k in ("accepted", "session opened for user", "auth_success", "login success", "success"))
                    or etype in ("auth_success", "login_success")
                    or any(k in msg for k in ("sudo:", "command=", "uid=0", "pkexec", "privilege", "escalat"))
                    or etype in ("sudo_exec", "privilege_escalation")
                    or any(k in msg for k in ("authorized_keys", "/etc/cron", "crontab", "/etc/sudoers", "/etc/shadow"))
                ):
                    bucket_milestones.append(ev)
                elif any(k in msg for k in ("fail", "invalid", "denied", "error", "refused")) or "fail" in etype:
                    bucket_anomalies.append(ev)
                else:
                    bucket_others.append(ev)

            selected_dict: Dict[str, Dict[str, Any]] = {}

            def _add_item(item: Dict[str, Any]):
                item_id = str(item.get("event_id") or item.get("id") or id(item))
                if item_id not in selected_dict and len(selected_dict) < budget_limit:
                    selected_dict[item_id] = item

            # 1. Always preserve alert triggers (up to 4)
            for item in bucket_triggers[:4]:
                _add_item(item)

            # 2. Always preserve critical milestones (up to 6)
            for item in bucket_milestones[:6]:
                _add_item(item)

            # 3. Preserve temporal boundary anchors (earliest and latest events)
            if evidence_items:
                _add_item(evidence_items[0])
                _add_item(evidence_items[-1])

            # 4. Fill remaining budget with anomalies / failure events
            for item in bucket_anomalies:
                if len(selected_dict) >= budget_limit:
                    break
                _add_item(item)

            # 5. Fill any remaining slots from other events
            for item in bucket_others:
                if len(selected_dict) >= budget_limit:
                    break
                _add_item(item)

            selected_raw_items = list(selected_dict.values())

        # Sort selected budgeted items chronologically for coherent narrative
        def _get_ts(it: Dict[str, Any]) -> str:
            return str(it.get("event_timestamp") or it.get("timestamp") or it.get("created_at") or "")

        selected_raw_items.sort(key=_get_ts)

        # Sanitize selected budgeted evidence items
        sanitized_evidence: List[Dict[str, Any]] = []
        for ev in selected_raw_items:
            clean_ev = dict(ev)
            if "message" in clean_ev:
                clean_ev["message"] = sanitizer.mask_text(str(clean_ev["message"]))
            if "details" in clean_ev and isinstance(clean_ev["details"], dict):
                clean_ev["details"] = sanitizer.mask_dict(clean_ev["details"])
            # Normalize event_id key
            ev_id = clean_ev.get("event_id") or clean_ev.get("id")
            clean_ev["event_id"] = str(ev_id) if ev_id else None
            sanitized_evidence.append(clean_ev)

        budgeted_evidence = sanitized_evidence[:budget_limit]

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
