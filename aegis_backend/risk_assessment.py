"""
AEGIS Multi-Dimensional Risk Assessment Engine.
Calculates objective, contextual incident risk scores (0-100) and levels based on
alert severities, attack sequence progression, evidence quality, and host posture.

Guarantees:
1. Mathematical transparency: Every point contributing to the score is listed as a factor.
2. Single source of truth formula: Harmonized across code, documentation, and tests.
3. Preserves deterministic alert severity: The original alert severity is never mutated.
4. Incorporates Security Checker posture context without conflating posture with active threat.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class RiskFactor:
    factor_id: str
    factor_name: str
    points: int
    category: str  # 'severity', 'multi_alert', 'progression', 'evidence', 'posture'
    description: str
    supporting_evidence_ids: List[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        """Alias for backward compatibility with existing tests and UI."""
        return self.factor_name


@dataclass
class RiskAssessmentResult:
    risk_score: int
    risk_level: str  # 'critical', 'high', 'medium', 'low'
    risk_factors: List[RiskFactor] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": [
                {
                    "factor_id": f.factor_id,
                    "factor_name": f.factor_name,
                    "name": f.factor_name,
                    "points": f.points,
                    "category": f.category,
                    "description": f.description,
                    "supporting_evidence_ids": f.supporting_evidence_ids,
                }
                for f in self.risk_factors
            ],
            "summary": self.summary,
        }


class RiskAssessmentEngine:
    """
    Evaluates contextual risk for a correlated incident using an explicit, bounded formula:
    Risk = min(100, Base + MultiAlert + Progression + Evidence + Posture)
    """

    SEVERITY_WEIGHTS = {
        "critical": 40,
        "high": 30,
        "medium": 20,
        "low": 10,
        "info": 5,
    }

    @classmethod
    def evaluate(
        cls,
        alerts: List[Dict[str, Any]],
        evidence_count: int = 0,
        posture_findings: Optional[List[Dict[str, Any]]] = None,
        entities: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessmentResult:
        factors: List[RiskFactor] = []
        score = 0

        if not alerts:
            return RiskAssessmentResult(
                risk_score=0,
                risk_level="low",
                risk_factors=[],
                summary="No active alerts in incident.",
            )

        # ---------------------------------------------------------------------
        # 1. Base Severity Contribution (Highest alert severity in cluster)
        # ---------------------------------------------------------------------
        severities = [a.get("severity", "low").lower() for a in alerts]
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        highest_sev = max(severities, key=lambda s: sev_rank.get(s, 0), default="low")
        base_points = cls.SEVERITY_WEIGHTS.get(highest_sev, 10)
        score += base_points
        factors.append(
            RiskFactor(
                factor_id=f"SEV-{highest_sev.upper()}",
                factor_name="Base Alert Severity",
                points=base_points,
                category="severity",
                description=f"Incident encompasses at least one '{highest_sev.upper()}' severity detection.",
            )
        )

        # ---------------------------------------------------------------------
        # 2. Multi-Alert Correlation Escalation (Cluster depth)
        # +6 points per additional alert beyond the primary, capped at +24
        # ---------------------------------------------------------------------
        if len(alerts) > 1:
            multi_alert_points = min((len(alerts) - 1) * 6, 24)
            score += multi_alert_points
            factors.append(
                RiskFactor(
                    factor_id="MULTI-ALERT",
                    factor_name="Correlated Multi-Alert Cluster",
                    points=multi_alert_points,
                    category="multi_alert",
                    description=f"Cluster aggregates {len(alerts)} related detections on the same host.",
                )
            )

        # ---------------------------------------------------------------------
        # 3. Attack Sequence Progression Analysis (Kill-chain stages)
        # ---------------------------------------------------------------------
        rule_ids = {a.get("rule_id", "") for a in alerts}
        has_brute = "RULE-SSH-BRUTE" in rule_ids
        has_auth_success = "RULE-AUTH-003" in rule_ids
        has_susp_sudo = "RULE-SUSP-SUDO" in rule_ids

        if has_brute and has_auth_success and has_susp_sudo:
            prog_points = 25
            score += prog_points
            factors.append(
                RiskFactor(
                    factor_id="PROG-KILLCHAIN",
                    factor_name="Full Kill Chain Sequence",
                    points=prog_points,
                    category="progression",
                    description="Complete progression observed: SSH Brute Force -> Successful Access -> Privileged Sudo Execution.",
                )
            )
        elif has_auth_success and has_susp_sudo:
            prog_points = 20
            score += prog_points
            factors.append(
                RiskFactor(
                    factor_id="PROG-AUTH-SUDO",
                    factor_name="Access to Privilege Escalation",
                    points=prog_points,
                    category="progression",
                    description="Authentication success immediately followed by privileged root/sudo commands.",
                )
            )
        elif has_brute and has_auth_success:
            prog_points = 15
            score += prog_points
            factors.append(
                RiskFactor(
                    factor_id="PROG-BRUTE-AUTH",
                    factor_name="Brute Force to Compromise",
                    points=prog_points,
                    category="progression",
                    description="Repeated failed authentications culminated in successful account login.",
                )
            )

        # Interactive Root Shell / High-risk command execution
        for a in alerts:
            reason = (a.get("reason") or "").lower()
            title = (a.get("title") or "").lower()
            if a.get("rule_id") == "RULE-SUSP-SUDO" and ("root shell" in title or "/bin/bash" in reason or "chmod 777" in reason):
                score += 10
                factors.append(
                    RiskFactor(
                        factor_id="PROG-ROOTSHELL",
                        factor_name="Interactive Root Shell Spawn",
                        points=10,
                        category="progression",
                        description="Privileged interactive shell or hazardous permission modification (/bin/bash or chmod 777) executed via sudo.",
                    )
                )
                break

        # ---------------------------------------------------------------------
        # 4. Forensic Telemetry Corroboration Strength
        # ---------------------------------------------------------------------
        if evidence_count >= 10:
            score += 8
            factors.append(
                RiskFactor(
                    factor_id="EVID-SUBSTANTIAL",
                    factor_name="Substantial Forensic Telemetry",
                    points=8,
                    category="evidence",
                    description=f"Strong corroborating evidence ({evidence_count} logged events) substantiating detection.",
                )
            )
        elif evidence_count >= 4:
            score += 5
            factors.append(
                RiskFactor(
                    factor_id="EVID-MODERATE",
                    factor_name="Corroborating Telemetry Evidence",
                    points=5,
                    category="evidence",
                    description=f"{evidence_count} telemetry events ground the detected activity.",
                )
            )
        elif evidence_count >= 1:
            score += 2
            factors.append(
                RiskFactor(
                    factor_id="EVID-MINIMAL",
                    factor_name="Minimal Telemetry Evidence",
                    points=2,
                    category="evidence",
                    description=f"{evidence_count} telemetry event(s) recorded.",
                )
            )

        # ---------------------------------------------------------------------
        # 5. Host Posture Vulnerability Context (from Security Checker)
        # Capped at +20
        # ---------------------------------------------------------------------
        if posture_findings:
            failed_check_ids = {
                f.get("check_id")
                for f in posture_findings
                if f.get("status", "").lower() == "fail"
            }
            if "FW-001" in failed_check_ids:
                score += 10
                factors.append(
                    RiskFactor(
                        factor_id="POSTURE-FW-FAIL",
                        factor_name="Vulnerable Host Perimeter (Firewall Inactive)",
                        points=10,
                        category="posture",
                        description="Host firewall (UFW/nftables) is inactive, facilitating unrestricted network ingress.",
                    )
                )
            if "SYS-002" in failed_check_ids:
                score += 5
                factors.append(
                    RiskFactor(
                        factor_id="POSTURE-APPARMOR-FAIL",
                        factor_name="Vulnerable Host Containment (AppArmor Inactive)",
                        points=5,
                        category="posture",
                        description="AppArmor mandatory access control is not enforcing profiles on the host.",
                    )
                )
            if "ACC-004" in failed_check_ids:
                score += 5
                factors.append(
                    RiskFactor(
                        factor_id="POSTURE-PERM-FAIL",
                        factor_name="Insecure System File Permissions",
                        points=5,
                        category="posture",
                        description="Key security configuration files (/etc/sudoers or /etc/shadow) have permissive access permissions.",
                    )
                )

        # ---------------------------------------------------------------------
        # 6. Bounding & Level Classification
        # ---------------------------------------------------------------------
        bounded_score = min(max(score, 0), 100)

        if bounded_score >= 85:
            risk_level = "critical"
        elif bounded_score >= 65:
            risk_level = "high"
        elif bounded_score >= 35:
            risk_level = "medium"
        else:
            risk_level = "low"

        return RiskAssessmentResult(
            risk_score=bounded_score,
            risk_level=risk_level,
            risk_factors=factors,
            summary=f"Incident assessed at {risk_level.upper()} risk (Score: {bounded_score}/100) with {len(factors)} corroborating risk factors.",
        )
