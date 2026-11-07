"""
Unit tests for AEGIS Security Checker Catalog & Registry.
Verifies catalog integrity, check ID stability, categories, severities, and remediation guidance.
"""

import pytest
from aegis_backend.security_checker_catalog import (
    SECURITY_CHECKS_CATALOG,
    CheckCategory,
    CheckSeverity,
    CheckStatus,
    SecurityCheckDefinition,
)


def test_catalog_contains_expected_core_checks():
    assert len(SECURITY_CHECKS_CATALOG) >= 20, "Catalog should contain at least 20 comprehensive checks."
    
    # Required Check IDs
    required_ids = [
        "SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005", "SSH-006", "SSH-007", "SSH-008",
        "ACC-001", "ACC-002", "ACC-003", "ACC-004", "ACC-005",
        "FW-001", "FW-002", "FW-003",
        "SYS-001", "SYS-002", "SYS-003", "SYS-004",
        "LOG-001", "LOG-002", "LOG-003",
        "NET-001", "NET-002",
        "FS-001", "FS-002", "FS-003",
    ]
    for cid in required_ids:
        assert cid in SECURITY_CHECKS_CATALOG, f"Missing required check {cid} in catalog!"


def test_all_catalog_definitions_have_required_fields():
    for cid, defn in SECURITY_CHECKS_CATALOG.items():
        assert defn.check_id == cid
        assert len(defn.check_name) > 3
        assert isinstance(defn.category, CheckCategory)
        assert isinstance(defn.severity, CheckSeverity)
        assert len(defn.expected_value) > 3
        assert len(defn.description) > 10
        assert len(defn.security_impact) > 10
        assert len(defn.recommendation) > 10
        assert len(defn.remediation_reference) > 3


def test_categories_coverage():
    categories_present = {defn.category for defn in SECURITY_CHECKS_CATALOG.values()}
    expected_categories = {
        CheckCategory.SSH,
        CheckCategory.ACCOUNT,
        CheckCategory.FIREWALL,
        CheckCategory.SYSTEM,
        CheckCategory.LOGGING,
        CheckCategory.NETWORK,
        CheckCategory.FILESYSTEM,
    }
    assert categories_present == expected_categories
