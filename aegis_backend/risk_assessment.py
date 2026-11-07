"""
AEGIS Multi-Dimensional Risk Assessment Engine.
Calculates objective, contextual incident risk scores and levels based on
alert severities, attack sequence progression, evidence quality, and host posture.
Guarantees:
1. Mathematical transparency: Every point contributing to the score is listed as a factor.
2. Preserves deterministic alert severity: The original alert severity is never mutated.
3. Incorporates Security Checker posture context without conflating posture with active threat.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class RiskFactor:
    name: str
    points: int
    category: str  # 'severity', 'progression', 'evidence', 'posture'
    description: str


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
                    "name": f.name,
                    "points": f.points,
                    "category": f.category,
                    "description": f.description,
                }
                for f in self.risk_factors
            ],
            "summary": self.summary,
        }


class RiskAssessmentEngine:
    """Evaluates contextual risk for a correlated incident."""

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

        # 1. Base Severity Contribution (Highest alert severity)
        severities = [a.get("severity", "low").lower() for a in alerts]
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        highest_sev = max(severities, key=lambda s: sev_rank.get(s, 0), default="low")
        base_points = cls.SEVERITY_WEIGHTS.get(highest_sev, 10)
        score += base_points
        factors.append(
            RiskFactor(
                name="Base Alert Severity",
                points=base_points,
                category="severity",
                description=f"Incident encompasses at least one '{highest_sev.upper()}' severity detection.",
            )
        )

        # 2. Multi-Alert Correlation Escalation
        if len(alerts) > 1:
            multi_alert_points = min((len(alerts) - 1) * 8, 24)
            score += multi_alert_points
            factors.append(
                RiskFactor(
                    name="Correlated Multi-Alert Cluster",
                    points=multi_alert_points,
                    category="correlation",
                    description=f"Cluster aggregates {len(alerts)} related detections on the same host.",
                )
            )

        # 3. Attack Sequence Progression Analysis
        rule_ids = {a.get("rule_id", "") for a in alerts}
        has_brute = "RULE-SSH-BRUTE" in rule_ids
        has_auth_success = "RULE-AUTH-003" in rule_ids
        has_susp_sudo = "RULE-SUSP-SUDO" in rule_ids

        if has_brute and has_auth_success and has_susp_sudo:
            prog_points = 25
            score += prog_points
            factors.append(
                RiskFactor(
                    name="Full Kill Chain Sequence",
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
                    name="Access to Privilege Escalation",
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
                    name="Brute Force to Compromise",
                    points=prog_points,
                    category="progression",
                    description="Repeated failed authentications culminated in successful account login.",
                )
            )

        # Sudo root shell specific escalation
        for a in alerts:
            if a.get("rule_id") == "RULE-SUSP-SUDO" and "Root Shell" in a.get("title", ""):
                score += 10
                factors.append(
                    RiskFactor(
                        name="Interactive Root Shell Spawn",
                        points=10,
                        category="progression",
                        description="Privileged interactive shell execution (/bin/bash) executed via sudo.",
                    )
                )
                break

        # 4. Evidence Volume & Forensic Confidence
        if evidence_count >= 10:
            score += 8
            factors.append(
                RiskFactor(
                    name="Substantial Forensic Telemetry",
                    points=8,
                    category="evidence",
                    description=f"Strong corroborating evidence ({evidence_count} logged events) substantiating detection.",
                )
            )
        elif evidence_count >= 4:
            score += 5
            factors.append(
                RiskFactor(
                    name="Corroborating Telemetry Evidence",
                    points=5,
                    category="evidence",
                    description=f"{evidence_count} telemetry events ground the detected activity.",
                )
            )

        # 5. Host Posture Vulnerability Context (from Security Checker)
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
                        name="Vulnerable Host Perimeter (Firewall Inactive)",
                        points=10,
                        category="posture",
                        description="Host firewall (UFW/nftables) is inactive, facilitating unrestricted network ingress.",
                    )
                )
            if "SYS-002" in failed_check_ids:
                score += 5
                factors.append(
                    RiskFactor(
                        name="Vulnerable Host Containment (AppArmor Inactive)",
                        points=5,
                        category="posture",
                        description="AppArmor mandatory access control is not enforcing profiles on the host.",
                    )
                )
            if "ACC-004" in failed_check_ids:
                score += 5
                factors.append(
                    RiskFactor(
                        name="Insecure System File Permissions",
                        points=5,
                        category="posture",
                        description="Key security configuration files (/etc/sudoers or /etc/shadow) have permissive access permissions.",
                    )
                )

        # Bound score between 0 and 100
        bounded_score = min(max(score, 0), 100)

        # Map to Risk Level
        if bounded_score >= 80:
            level = "critical"
        elif bounded_score >= 60:
            level = "high"
        elif bounded_score >= 35:
            level = "medium"
        else:
            level = "low"

        summary = (
            f"Risk score {bounded_score}/100 ({level.upper()}) derived from "
            f"{highest_sev.upper()} base alert severity with {len(factors)} contextual risk factors."
        )

        return RiskAssessmentResult(
            risk_score=bounded_score,
            risk_level=level,
            risk_factors=factors,
            summary=summary,
        )
