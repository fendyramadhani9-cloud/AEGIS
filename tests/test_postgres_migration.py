"""
Pytest integration wrapper for PostgreSQL Database Engine Migration tests.
Runs verify_postgres_migration.cjs against a clean local PostgreSQL engine,
verifying that all 7 critical database constraints, triggers, and RLS policies pass.
"""

import subprocess
import sys
from pathlib import Path


def test_postgresql_migration_and_constraints_engine():
    script_path = Path(__file__).parent / "verify_postgres_migration.cjs"
    assert script_path.exists(), "verify_postgres_migration.cjs not found!"

    # Execute Node test runner
    result = subprocess.run(
        ["node", str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )

    print(result.stdout)
    if result.returncode != 0:
        print("STDERR:", result.stderr, file=sys.stderr)

    assert result.returncode == 0, f"PostgreSQL migration integration tests failed:\n{result.stderr or result.stdout}"
    assert "ALL 7 DATABASE INTEGRATION TESTS PASSED (100%)" in result.stdout


def test_postgresql_atomic_alert_evidence_rpc():
    script_path = Path(__file__).parent / "verify_atomic_rpc.cjs"
    assert script_path.exists(), "verify_atomic_rpc.cjs not found!"

    result = subprocess.run(
        ["node", str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )

    print(result.stdout)
    if result.returncode != 0:
        print("STDERR:", result.stderr, file=sys.stderr)

    assert result.returncode == 0, f"Atomic RPC verification failed:\n{result.stderr or result.stdout}"
    assert "ALL 10 FINAL PRODUCTION HARDENED ATOMIC RPC TESTS PASSED (100%)" in result.stdout


def test_postgresql_security_checker_migration():
    script_path = Path(__file__).parent / "verify_security_checker_migration.cjs"
    assert script_path.exists(), "verify_security_checker_migration.cjs not found!"

    result = subprocess.run(
        ["node", str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )

    print(result.stdout)
    if result.returncode != 0:
        print("STDERR:", result.stderr, file=sys.stderr)

    assert result.returncode == 0, f"Security Checker migration tests failed:\n{result.stderr or result.stdout}"
    assert "ALL 7 SECURITY CHECKER DATABASE ENGINE TESTS PASSED (100%)" in result.stdout


