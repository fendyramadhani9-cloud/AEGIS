"""
AEGIS Incident Service.
Orchestrates incident lifecycle, alert correlation, timeline reconstruction,
risk evaluation, and AI-powered security investigations.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import logging

from aegis_backend.incident_correlator import IncidentCorrelator, CorrelatedIncident
from aegis_backend.incident_context_builder import IncidentContextBuilder, IncidentContext
from aegis_backend.risk_assessment import RiskAssessmentEngine
from aegis_backend.ai_provider import BaseAIProvider, get_ai_provider
from aegis_backend.schemas import (
    IncidentItem,
    IncidentDetailResponse,
    IncidentTimelineItem,
    AIAnalysisItem,
    IncidentSummaryResponse,
    AlertItem,
)

logger = logging.getLogger("aegis_backend.incident_service")


class IncidentService:
    """Service layer managing incidents and security investigations."""

    def __init__(self, repository, ai_provider: Optional[BaseAIProvider] = None):
        self.repo = repository
        self.ai_provider = ai_provider or get_ai_provider()
        self.correlator = IncidentCorrelator(time_window_seconds=1800)

    def correlate_alerts(self, host_id: Optional[str] = None) -> List[IncidentItem]:
        """
        Scans alerts for a host (or all hosts) and groups unassigned alerts
        into correlated security incidents.
        """
        # 1. Fetch alerts
        alerts_data, _ = self.repo.list_alerts(limit=100, host_id=host_id)
        if not alerts_data:
            return []

        # 2. Fetch posture context
        posture_findings = []
        try:
            findings_data, _ = self.repo.list_security_findings(host_id=host_id, limit=50)
            posture_findings = findings_data
        except Exception:
            pass

        # 3. Gather evidence counts for all alerts
        evidence_counts: Dict[str, int] = {}
        for a in alerts_data:
            aid = a.get("id")
            if aid:
                try:
                    evs = self.repo.get_alert_evidence(aid)
                    evidence_counts[aid] = len(evs) if evs else 0
                except Exception:
                    evidence_counts[aid] = 0

        # 4. Run correlation engine
        correlated_groups = self.correlator.correlate(
            alerts=alerts_data,
            posture_findings=posture_findings,
            evidence_counts=evidence_counts,
        )

        persisted_incidents: List[IncidentItem] = []
        for grp in correlated_groups:
            inc_dict = grp.to_dict()
            persisted = self.repo.upsert_incident(inc_dict, alert_ids=[a.get("id") for a in grp.alerts])
            persisted_incidents.append(IncidentItem.model_validate(persisted))

        return persisted_incidents

    def get_incident_detail(self, incident_id: str) -> Optional[IncidentDetailResponse]:
        """Fetches full incident view including correlated alerts, evidence, and latest analysis."""
        incident_data = self.repo.get_incident_by_id(incident_id)
        if not incident_data:
            return None

        # Correlated alerts
        alerts_data = self.repo.get_incident_alerts(incident_id)
        alert_items = [AlertItem.model_validate(a) for a in alerts_data]

        # Evidence count
        total_ev_count = 0
        all_evidence = []
        for a in alerts_data:
            aid = a.get("id")
            if aid:
                try:
                    evs = self.repo.get_alert_evidence(aid) or []
                    all_evidence.extend(evs)
                    total_ev_count += len(evs)
                except Exception:
                    pass

        # Host posture context
        posture_context: Dict[str, Any] = {}
        try:
            findings, _ = self.repo.list_security_findings(host_id=incident_data.get("host_id"), limit=20)
            failed = [f for f in findings if f.get("status") in ("fail", "warning")]
            posture_context = {
                "total_issues": len(failed),
                "issues": [
                    {"check_id": f.get("check_id"), "title": f.get("check_name") or f.get("title"), "status": f.get("status")}
                    for f in failed[:5]
                ],
            }
        except Exception:
            pass

        # Risk breakdown
        risk_result = RiskAssessmentEngine.evaluate(
            alerts=alerts_data,
            evidence_count=total_ev_count,
            posture_findings=findings if "findings" in locals() else None,
        )

        # Latest AI Analysis
        latest_analysis = self.repo.get_latest_ai_analysis(incident_id)
        analysis_item = AIAnalysisItem.model_validate(latest_analysis) if latest_analysis else None

        return IncidentDetailResponse(
            incident=IncidentItem.model_validate(incident_data),
            alerts=alert_items,
            evidence_count=total_ev_count,
            posture_context=posture_context,
            risk_factors=[f.__dict__ for f in risk_result.risk_factors],
            latest_analysis=analysis_item,
        )

    def update_incident_status(
        self, incident_id: str, new_status: str, note: Optional[str] = None, operator: str = "admin"
    ) -> Optional[IncidentItem]:
        """Updates the lifecycle status of an incident and records audit history."""
        updated = self.repo.update_incident_status(
            incident_id=incident_id,
            status=new_status,
            note=note,
            operator=operator,
        )
        if not updated:
            return None
        return IncidentItem.model_validate(updated)

    def analyze_incident(self, incident_id: str, force: bool = False) -> Optional[AIAnalysisItem]:
        """Executes AI security analysis on the incident and persists the findings."""
        incident_data = self.repo.get_incident_by_id(incident_id)
        if not incident_data:
            return None

        # Check existing analysis unless forced
        if not force:
            existing = self.repo.get_latest_ai_analysis(incident_id)
            if existing and existing.get("analysis_status") == "completed":
                return AIAnalysisItem.model_validate(existing)

        # Build context
        alerts_data = self.repo.get_incident_alerts(incident_id)
        evidence_items = []
        for a in alerts_data:
            aid = a.get("id")
            if aid:
                try:
                    evs = self.repo.get_alert_evidence(aid)
                    if evs:
                        evidence_items.extend(evs)
                except Exception:
                    pass

        posture_findings = []
        try:
            p_data, _ = self.repo.list_security_findings(host_id=incident_data.get("host_id"), limit=30)
            posture_findings = p_data
        except Exception:
            pass

        risk_factors = incident_data.get("risk_factors") or []
        if not risk_factors:
            try:
                risk_factors = self.repo.get_incident_risk_factors(incident_id)
            except Exception:
                risk_factors = []

        context = IncidentContextBuilder.build(
            incident=incident_data,
            alerts=alerts_data,
            evidence_items=evidence_items,
            posture_findings=posture_findings,
            risk_factors=risk_factors,
        )

        # Call AI Provider
        analysis_result = self.ai_provider.analyze_incident(context)

        # Enforce Risk Engine Single Source of Truth
        # AI providers must NEVER overwrite the deterministic risk score
        analysis_dict = analysis_result.model_dump()
        analysis_dict["risk_score"] = incident_data.get("risk_score", analysis_dict.get("risk_score", 0))
        analysis_dict["risk_level"] = incident_data.get("risk_level", analysis_dict.get("risk_level", "medium"))

        # Persist Analysis Result
        saved = self.repo.save_ai_analysis(analysis_dict)
        return AIAnalysisItem.model_validate(saved)

    def get_incident_timeline(self, incident_id: str) -> List[IncidentTimelineItem]:
        """
        Reconstructs an end-to-end chronological timeline merging telemetry events,
        alerts, status changes, and AI analysis milestones.
        """
        timeline_items = self.repo.get_incident_timeline(incident_id)
        return [IncidentTimelineItem.model_validate(t) for t in timeline_items]

    def get_incidents_summary(self, host_id: Optional[str] = None) -> IncidentSummaryResponse:
        """Retrieves aggregated metrics for incidents."""
        summary_data = self.repo.get_incidents_summary(host_id=host_id)
        return IncidentSummaryResponse.model_validate(summary_data)

