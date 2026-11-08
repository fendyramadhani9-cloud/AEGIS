"""
Tests for AEGIS SQLite Hot Backup and Recovery Tooling.
Verifies:
1. Online backup creation in WAL mode.
2. Cryptographic checksum generation and integrity verification.
3. Successful restore into target database.
4. Tamper detection on modified checksum.
5. Post-restore data fidelity and table count checks.
"""

import os
import sqlite3
import tempfile
import pytest
from scripts.backup_sqlite import perform_backup, check_sqlite_integrity
from scripts.restore_sqlite import perform_restore


@pytest.fixture
def populated_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "source.db")
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("CREATE TABLE test_data (id INTEGER PRIMARY KEY, note TEXT);")
        conn.execute("INSERT INTO test_data (note) VALUES ('entry 1'), ('entry 2'), ('entry 3');")
        conn.commit()
        conn.close()
        yield db_path, tmpdir


def test_backup_and_restore_cycle(populated_db):
    source_db, tmpdir = populated_db
    backup_dir = os.path.join(tmpdir, "backups")

    # 1. Perform backup
    backup_res = perform_backup(source_db, backup_dir, retention_count=5)
    assert backup_res["status"] == "SUCCESS"
    assert os.path.exists(backup_res["backup_file"])
    assert os.path.exists(backup_res["checksum_file"])

    # 2. Restore into fresh location
    restored_db = os.path.join(tmpdir, "restored.db")
    restore_res = perform_restore(backup_res["backup_file"], restored_db)
    assert restore_res["status"] == "SUCCESS"
    assert restore_res["integrity_check"] == "ok"
    assert restore_res["tables_restored"].get("test_data") == 3

    # Verify query on restored db
    conn = sqlite3.connect(restored_db)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM test_data;")
    count = cur.fetchone()[0]
    conn.close()
    assert count == 3


def test_restore_tamper_detection(populated_db):
    source_db, tmpdir = populated_db
    backup_dir = os.path.join(tmpdir, "backups")

    backup_res = perform_backup(source_db, backup_dir)
    backup_file = backup_res["backup_file"]

    # Tamper with the backup file by appending corrupt byte
    with open(backup_file, "ab") as f:
        f.write(b"\x00corrupt")

    # Attempting restore must raise Checksum mismatch ValueError
    restored_db = os.path.join(tmpdir, "tampered_restored.db")
    with pytest.raises(ValueError) as excinfo:
        perform_restore(backup_file, restored_db, verify_checksum=True)

    assert "Checksum mismatch" in str(excinfo.value)

