"""
Evaluation Metrics Engine for AEGIS.
Calculates:
1. Schema Compliance Rate (0.0 to 1.0)
2. Evidence Citation Validity (0.0 to 1.0)
3. Severity Preservation Rate (0.0 to 1.0)
4. Unsupported Claim Rate (0.0 to 1.0)
5. Status Recognition Accuracy (0.0 to 1.0)
"""

from typing import List, Dict, Any
from pydantic import BaseModel, Field


class EvaluationMetrics(BaseModel):
    total_scenarios_evaluated: int = 0
    passed_scenarios: int = 0
    failed_scenarios: int = 0
    schema_compliance_rate: float = 1.0
    evidence_citation_validity: float = 1.0
    severity_preservation_rate: float = 1.0
    unsupported_claim_rate: float = 0.0
    status_recognition_accuracy: float = 1.0


class ScenarioEvaluationResult(BaseModel):
    scenario_id: str
    passed: bool
    agent_type: str
    errors: List[str] = Field(default_factory=list)
    metrics_snapshot: Dict[str, Any] = Field(default_factory=dict)

