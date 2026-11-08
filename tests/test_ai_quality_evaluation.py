"""
AEGIS AI Quality Evaluation Test Suite (Prioritas 10).
Validates:
1. Contextual Buzzword Quarantine: Demotes unevidenced exfiltration/C2/lateral/persistence claims
   from factual inferences into unverified hypotheses without blind erasure.
2. Quantitative Claim Fidelity: Detects claims of multiple/repeated failures when telemetry records <= 1.
3. Loopback Identity Discontinuity Guard: Flags distinct users (e.g. guest and ubuntu) on loopback.
4. SSoT Immutability: Guarantees risk score, risk level, and factors remain strictly authoritative.
5. 4-Tier Forensic Taxonomy: Facts, Inferences, Hypotheses, Unknowns separation and strict ID whitelisting.
"""

import pytest
from datetime import datetime, timezone
from aegis_backend.incident_context_builder import IncidentContext, IncidentContextBuilder
from aegis_backend.schemas import AIAnalysisItem
from aegis_backend.ai_provider import verify_forensic_grounding, MockAIProvider


def test_grounding_quarantines_unsupported_exfiltration_buzzwords():
    """
    KOREKSI 1 & 2:
    Buktikan bahwa klaim eksfiltrasi tanpa bukti telemetri:
    - DIHAPUS dari kesimpulan faktual (inferences/facts).
    - DIPERTAHANKAN sebagai hipotesis berstatus 'unverified'.
    - MENYERTAKAN langkah verifikasi (investigation_step) dan data gap (unknown_items).
    - TIDAK DIHAPUS secara membabi buta.
    """
    context = IncidentContext(
        incident_id="INC-SSH-001",
        host_id="host-fenn",
        title="SSH Failed Authentication Attempt",
        severity="medium",
        alerts=[
            {"id": "ALT-1", "rule_id": "RULE-SSH-BRUTE", "title": "SSH Authentication Anomaly"}
        ],
        evidence_items=[
            {"event_id": "EVT-101", "message": "Failed password for root from 192.168.1.50 port 44221 ssh2", "event_type": "auth_failure"},
            {"event_id": "EVT-102", "message": "Failed password for root from 192.168.1.50 port 44222 ssh2", "event_type": "auth_failure"},
        ],
        source_ip="192.168.1.50",
        target_user="root",
        attack_scenario="SSH password guessing attempts.",
        risk_score=35,
        risk_level="medium",
    )

    # Simulasikan hasil mentah AI yang berhalusinasi menyatakan eksfiltrasi data faktual
    raw_analysis = AIAnalysisItem(
        analysis_id="ANL-TEST-01",
        incident_id="INC-SSH-001",
        host_id="host-fenn",
        analysis_status="completed",
        threat_classification="SSH Brute Force and Data Exfiltration",
        executive_summary="Adversary conducted brute force and successfully completed sensitive data exfiltration outside the network.",
        attack_scenario="Attacker guessed password and performed data exfiltration.",
        facts=[
            {"evidence_id": "EVT-101", "fact": "Failed login observed.", "timestamp": "2026-11-08T10:00:00Z"},
            {"evidence_id": "EVT-102", "fact": "Eksfiltrasi data berhasil dilakukan.", "timestamp": "2026-11-08T10:00:05Z"},
        ],
        inferences=[
            {
                "statement": "Adversary initiated data exfiltration to a remote server.",
                "supporting_evidence_ids": ["EVT-101"],
                "rationale": "High volume outbound transfer suspected.",
            },
            {
                "statement": "Multiple authentication failures indicate automated dictionary attack.",
                "supporting_evidence_ids": ["EVT-101", "EVT-102"],
                "rationale": "Consecutive failed login events.",
            }
        ],
        hypotheses=[],
        unknown_items=[],
        observed_behaviors=[],
        timeline=[],
        risk_level="critical",  # AI mencoba menaikkan severity secara semena-mena
        risk_score=99,         # AI mencoba menaikkan risk score secara semena-mena
        confidence_level="high",
        confidence_reason="Model inference.",
        supporting_evidence=["EVT-101", "EVT-102"],
        contradicting_evidence=[],
        unknowns=[],
        impact_assessment="Severe compromise.",
        recommended_actions=[{"priority": "immediate", "action": "Review logs."}],
        containment_recommendations=[],
        investigation_notes="",
        provider="mock-evaluator",
        model="mock",
        storage_backend="sqlite_local",
        created_at="2026-11-08T10:00:00Z",
        completed_at="2026-11-08T10:00:01Z",
    )

    # BEFORE VALIDATION: Klaim eksfiltrasi berada di inferences sebagai fakta
    assert any("exfiltration" in inf["statement"].lower() for inf in raw_analysis.inferences)
    assert len(raw_analysis.hypotheses) == 0

    # EXECUTE GROUNDING VALIDATION
    validated = verify_forensic_grounding(raw_analysis, context)

    # AFTER VALIDATION:
    # 1. Klaim eksfiltrasi DIHAPUS dari inferences
    assert not any("exfiltration" in inf["statement"].lower() for inf in validated.inferences)
    assert len(validated.inferences) == 1
    assert "dictionary attack" in validated.inferences[0]["statement"]

    # 2. Klaim eksfiltrasi DIPERTAHANKAN di hypotheses sebagai unverified
    assert len(validated.hypotheses) >= 1
    exfil_hypotheses = [h for h in validated.hypotheses if "exfiltration" in h["statement"].lower() or "eksfiltrasi" in h["statement"].lower()]
    assert len(exfil_hypotheses) >= 1
    for eh in exfil_hypotheses:
        assert eh["status"] == "unverified"
        assert len(eh.get("investigation_step", "")) > 10
        assert "firewall" in eh["investigation_step"].lower() or "netflow" in eh["investigation_step"].lower() or "scp" in eh["investigation_step"].lower()

    # 3. Data gap dicatat di unknown_items
    assert any("eksfiltrasi" in u["data_gap"].lower() or "exfiltration" in u["data_gap"].lower() for u in validated.unknown_items)

    # 4. Executive summary menyertakan catatan forensik
    assert "Catatan Forensik" in validated.executive_summary
    assert "unverified" in validated.executive_summary.lower()


def test_quantitative_fidelity_single_failure_not_multiple():
    """
    KOREKSI 2 & 4:
    Buktikan bahwa klaim kejadian jamak ('multiple failed logins') TIDAK LOLOS
    jika telemetri fakta hanya memuat satu kegagalan login (failure_count <= 1).
    """
    context = IncidentContext(
        incident_id="INC-SINGLE-001",
        host_id="host-fenn",
        title="Isolated SSH Login Failure",
        severity="low",
        alerts=[{"id": "ALT-SINGLE", "rule_id": "RULE-AUTH-001", "title": "Single Auth Failure"}],
        evidence_items=[
            # HANYA SATU EVENT KEGAGALAN
            {"event_id": "EVT-SOLO-1", "message": "Failed password for user admin from 10.0.0.5 port 55123 ssh2", "event_type": "auth_failure"}
        ],
        source_ip="10.0.0.5",
        target_user="admin",
        attack_scenario="Isolated failed attempt.",
        risk_score=15,
        risk_level="low",
    )

    # AI berhalusinasi menyatakan 'multiple failed logins' dan 'berulang kali'
    raw_analysis = AIAnalysisItem(
        analysis_id="ANL-QUANT-01",
        incident_id="INC-SINGLE-001",
        host_id="host-fenn",
        analysis_status="completed",
        threat_classification="Automated Brute Force Attack",
        executive_summary="Adversary executed multiple failed logins in a repeated brute force attack against admin.",
        attack_scenario="Multiple failed attempts recorded.",
        facts=[{"evidence_id": "EVT-SOLO-1", "fact": "Failed login for admin.", "timestamp": "2026-11-08T10:00:00Z"}],
        inferences=[
            {
                "statement": "Multiple failed attempts indicate an automated dictionary scan.",
                "supporting_evidence_ids": ["EVT-SOLO-1"],
                "rationale": "High frequency logins.",
            }
        ],
        hypotheses=[],
        unknown_items=[],
        observed_behaviors=[],
        timeline=[],
        risk_level="low",
        risk_score=15,
        confidence_level="high",
        confidence_reason="Observation.",
        supporting_evidence=["EVT-SOLO-1"],
        contradicting_evidence=[],
        unknowns=[],
        impact_assessment="Minimal.",
        recommended_actions=[],
        containment_recommendations=[],
        investigation_notes="",
        provider="mock-evaluator",
        model="mock",
        storage_backend="sqlite_local",
        created_at="2026-11-08T10:00:00Z",
        completed_at="2026-11-08T10:00:01Z",
    )

    # BEFORE VALIDATION: Tidak ada catatan ketidaksesuaian kuantitatif
    assert not any("ketidaksesuaian kuantitatif" in u.get("data_gap", "").lower() for u in raw_analysis.unknown_items)

    # EXECUTE VALIDATION
    validated = verify_forensic_grounding(raw_analysis, context)

    # AFTER VALIDATION:
    # 1. Ketidaksesuaian kuantitatif terdeteksi dan dicatat di unknown_items
    quant_gaps = [u for u in validated.unknown_items if "ketidaksesuaian kuantitatif" in u.get("data_gap", "").lower()]
    assert len(quant_gaps) == 1
    assert "1 event kegagalan" in quant_gaps[0]["data_gap"]

    # 2. Catatan kuantitatif ditambahkan ke investigation_notes
    assert "Catatan Kuantitatif" in validated.investigation_notes
    assert "1 event kegagalan" in validated.investigation_notes


def test_identity_discontinuity_on_loopback():
    """
    KOREKSI 4:
    Buktikan bahwa pada antarmuka loopback (127.0.0.1), kemunculan dua identitas berbeda
    ('guest' dan 'ubuntu') TIDAK digabung menjadi satu penyerang tanpa bukti korelasi proses.
    """
    context = IncidentContext(
        incident_id="INC-LOOPBACK-001",
        host_id="host-fenn",
        title="Local Authentication Sequence",
        severity="medium",
        alerts=[
            {"id": "ALT-L1", "rule_id": "RULE-AUTH-FAIL", "title": "Auth failure on loopback"},
            {"id": "ALT-L2", "rule_id": "RULE-AUTH-003", "title": "Auth success on loopback"},
        ],
        evidence_items=[
            {"event_id": "EVT-LB-1", "user": "guest", "message": "Failed password for guest from 127.0.0.1 port 33120 ssh2", "event_type": "auth_failure"},
            {"event_id": "EVT-LB-2", "user": "ubuntu", "message": "Accepted publickey for ubuntu from 127.0.0.1 port 33122 ssh2", "event_type": "auth_success"},
        ],
        source_ip="127.0.0.1",
        target_user="ubuntu",
        attack_scenario="Local process activities.",
        risk_score=30,
        risk_level="medium",
    )

    raw_analysis = AIAnalysisItem(
        analysis_id="ANL-LB-01",
        incident_id="INC-LOOPBACK-001",
        host_id="host-fenn",
        analysis_status="completed",
        threat_classification="Privilege Escalation on Localhost",
        executive_summary="Attacker targeted guest account then switched to ubuntu account locally.",
        attack_scenario="Attacker transitioned between accounts.",
        facts=[
            {"evidence_id": "EVT-LB-1", "fact": "Failed password for guest on 127.0.0.1", "timestamp": "2026-11-08T10:00:00Z"},
            {"evidence_id": "EVT-LB-2", "fact": "Accepted publickey for ubuntu on 127.0.0.1", "timestamp": "2026-11-08T10:01:00Z"},
        ],
        inferences=[
            {
                "statement": "Attacker compromised guest and subsequently logged in as ubuntu.",
                "supporting_evidence_ids": ["EVT-LB-1", "EVT-LB-2"],
                "rationale": "Sequential activity on loopback.",
            }
        ],
        hypotheses=[],
        unknown_items=[],
        observed_behaviors=[],
        timeline=[],
        risk_level="medium",
        risk_score=30,
        confidence_level="high",
        confidence_reason="Local telemetry.",
        supporting_evidence=["EVT-LB-1", "EVT-LB-2"],
        contradicting_evidence=[],
        unknowns=[],
        impact_assessment="Local activity.",
        recommended_actions=[],
        containment_recommendations=[],
        investigation_notes="",
        provider="mock-evaluator",
        model="mock",
        storage_backend="sqlite_local",
        created_at="2026-11-08T10:00:00Z",
        completed_at="2026-11-08T10:01:05Z",
    )

    # EXECUTE VALIDATION
    validated = verify_forensic_grounding(raw_analysis, context)

    # AFTER VALIDATION:
    # 1. Data gap ketiadaan pohon proses (parent PID tree) antara guest dan ubuntu dicatat
    pid_gaps = [u for u in validated.unknown_items if "pohon proses" in u.get("data_gap", "").lower()]
    assert len(pid_gaps) == 1
    assert "guest" in pid_gaps[0]["data_gap"]
    assert "ubuntu" in pid_gaps[0]["data_gap"]

    # 2. Rationale inferensi disisipi peringatan proses independen
    inf_rationales = [inf["rationale"] for inf in validated.inferences]
    assert any("loopback lokal dengan identitas terpisah" in r for r in inf_rationales)


def test_risk_score_and_factors_immutability():
    """
    KOREKSI 3:
    Buktikan bahwa risk score dan risk level SSoT TIDAK BISA DIUBAH oleh AI,
    dan rincian risk_factors dari engine deterministik tersalurkan utuh.
    """
    # Context dengan risk score resmi 40 (SEV-CRITICAL)
    context = IncidentContext(
        incident_id="INC-RISK-001",
        host_id="host-fenn",
        title="Root Compromise Alert",
        severity="critical",
        alerts=[{"id": "ALT-CRIT", "rule_id": "RULE-SUSP-SUDO", "title": "Unauthorized Sudo Root"}],
        evidence_items=[{"event_id": "EVT-SUDO-1", "message": "sudo: COMMAND=/bin/bash", "event_type": "sudo_exec"}],
        source_ip="192.168.1.100",
        target_user="root",
        risk_score=40,
        risk_level="critical",
        risk_factors=[
            {"factor_id": "SEV-CRITICAL", "factor_name": "Base Alert Severity", "points": 40, "category": "severity", "description": "Critical alert"},
            {"factor_id": "POSTURE-FAIL", "factor_name": "PermitRootLogin Active", "points": 15, "category": "posture", "description": "SSH misconfiguration"},
        ]
    )

    # AI berhalusinasi menghasilkan skor berbeda (misal meremehkan jadi 10 atau melebih-lebihkan jadi 100)
    raw_analysis = AIAnalysisItem(
        analysis_id="ANL-RISK-01",
        incident_id="INC-RISK-001",
        host_id="host-fenn",
        analysis_status="completed",
        threat_classification="Privileged Shell Invocation",
        executive_summary="Sudo bash executed.",
        attack_scenario="Sudo root shell.",
        facts=[{"evidence_id": "EVT-SUDO-1", "fact": "sudo bash run.", "timestamp": "2026-11-08T10:00:00Z"}],
        inferences=[{"statement": "Root access acquired.", "supporting_evidence_ids": ["EVT-SUDO-1"], "rationale": "sudo command."}],
        hypotheses=[],
        unknown_items=[],
        observed_behaviors=[],
        timeline=[],
        risk_level="low",   # AI mencoba meremehkan severity
        risk_score=10,      # AI mencoba menurunkan skor menjadi 10
        confidence_level="high",
        confidence_reason="Confirmed.",
        supporting_evidence=["EVT-SUDO-1"],
        contradicting_evidence=[],
        unknowns=[],
        impact_assessment="High.",
        recommended_actions=[],
        containment_recommendations=[],
        investigation_notes="",
        provider="mock-evaluator",
        model="mock",
        storage_backend="sqlite_local",
        created_at="2026-11-08T10:00:00Z",
        completed_at="2026-11-08T10:00:01Z",
    )

    # EXECUTE VALIDATION
    validated = verify_forensic_grounding(raw_analysis, context)

    # AFTER VALIDATION:
    # 1. Skor dan level dipulihkan 100% ke nilai SSoT otoritatif
    assert validated.risk_score == 40
    assert validated.risk_level == "critical"

    # 2. Konteks builder menyertakan risk_factors dan risk_factor_summary
    ctx_dict = context.to_dict()
    assert "risk_factors" in ctx_dict
    assert len(ctx_dict["risk_factors"]) == 2
    assert "risk_factor_summary" in ctx_dict
    assert any("SEV-CRITICAL" in s or "Base Alert Severity" in s for s in ctx_dict["risk_factor_summary"])


def test_four_tier_taxonomy_separation_and_evidence_validity():
    """
    KOREKSI 4:
    Buktikan bahwa seluruh ID referensi bukti divalidasi ketat (halusinasi ID dibuang),
    dan keempat tier taksonomi (facts, inferences, hypotheses, unknowns) terpisah dengan disiplin.
    """
    context = IncidentContext(
        incident_id="INC-TAX-001",
        host_id="host-fenn",
        title="Forensic Taxonomy Test",
        severity="medium",
        alerts=[{"id": "ALT-1", "rule_id": "RULE-TEST", "title": "Test Alert"}],
        evidence_items=[
            {"event_id": "EVT-REAL-01", "message": "Real telemetry event 1", "event_type": "auth"},
            {"event_id": "EVT-REAL-02", "message": "Real telemetry event 2", "event_type": "auth"},
        ],
        source_ip="192.168.1.10",
        risk_score=25,
        risk_level="medium",
    )

    # Injeksi ID halusinasi fiktif (EVT-FAKE-999 dan EVT-PHANTOM-888)
    raw_analysis = AIAnalysisItem(
        analysis_id="ANL-TAX-01",
        incident_id="INC-TAX-001",
        host_id="host-fenn",
        analysis_status="completed",
        threat_classification="Test Sequence",
        executive_summary="Testing taxonomy.",
        attack_scenario="Taxonomy test.",
        facts=[
            {"evidence_id": "EVT-REAL-01", "fact": "Valid real observation.", "timestamp": "2026-11-08T10:00:00Z"},
            {"evidence_id": "EVT-FAKE-999", "fact": "Hallucinated ghost observation.", "timestamp": "2026-11-08T10:00:01Z"},
        ],
        inferences=[
            {
                "statement": "Inference based on real and hallucinated evidence.",
                "supporting_evidence_ids": ["EVT-REAL-01", "EVT-PHANTOM-888"],
                "rationale": "Logical derivation.",
            }
        ],
        hypotheses=[
            {"statement": "Potential secondary attack route.", "status": "unverified", "investigation_step": "Check network flow."}
        ],
        unknown_items=[
            {"data_gap": "Absence of full kernel process accounting.", "impact": "Process ancestry not verifiable."}
        ],
        observed_behaviors=[],
        timeline=[],
        risk_level="medium",
        risk_score=25,
        confidence_level="medium",
        confidence_reason="Test.",
        supporting_evidence=["EVT-REAL-01", "EVT-FAKE-999", "EVT-PHANTOM-888"],
        contradicting_evidence=[],
        unknowns=[],
        impact_assessment="Test assessment.",
        recommended_actions=[],
        containment_recommendations=[],
        investigation_notes="",
        provider="mock-evaluator",
        model="mock",
        storage_backend="sqlite_local",
        created_at="2026-11-08T10:00:00Z",
        completed_at="2026-11-08T10:00:01Z",
    )

    # EXECUTE VALIDATION
    validated = verify_forensic_grounding(raw_analysis, context)

    # AFTER VALIDATION:
    # 1. Fakta halusinasi EVT-FAKE-999 dibuang
    fact_eids = [f["evidence_id"] for f in validated.facts]
    assert "EVT-FAKE-999" not in fact_eids
    assert "EVT-REAL-01" in fact_eids

    # 2. Inferensi membersihkan ID fiktif EVT-PHANTOM-888
    inf_eids = validated.inferences[0]["supporting_evidence_ids"]
    assert "EVT-PHANTOM-888" not in inf_eids
    assert "EVT-REAL-01" in inf_eids

    # 3. supporting_evidence bersih dari ID fiktif
    for eid in validated.supporting_evidence:
        assert eid in context.allowed_evidence_ids

    # 4. Keempat tier terisi dan terpisah secara disiplin
    assert len(validated.facts) >= 1
    assert len(validated.inferences) >= 1
    assert len(validated.hypotheses) >= 1
    assert len(validated.unknown_items) >= 1
    for h in validated.hypotheses:
        assert h["status"] == "unverified"
        assert len(h["investigation_step"]) > 0

