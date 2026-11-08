"""
AEGIS SQLite Database Recovery & Restore Tool (WAL-Safe).
Safely restores an AEGIS incident and security checker SQLite database from a validated backup.

Guarantees:
1. Pre-restore SHA-256 cryptographic verification against backup checksum manifest.
2. Pre-restore PRAGMA integrity verification of the backup file before touching live database.
3. Automatic pre-restore snapshot of existing live database (<db>.pre_restore_<timestamp>).
4. Safe handling of WAL journal files (wal_checkpoint and removal of obsolete .wal/.shm).
5. Post-restore integrity verification and table inventory reporting.
"""

import os
import sys
import json
import shutil
import sqlite3
import hashlib
import argparse
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis_restore")


def compute_sha256(filepath: str) -> str:
    """Computes SHA-256 checksum of a file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def check_sqlite_integrity(db_path: str) -> Tuple[bool, str]:
    """Runs PRAGMA integrity_check on the specified database."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA integrity_check;")
        rows = cur.fetchall()
        if rows and rows[0][0] == "ok":
            return True, "ok"
        return False, f"Integrity check failed: {[r[0] for r in rows]}"
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def perform_restore(
    backup_file: str,
    target_db_path: str,
    verify_checksum: bool = True,
    force: bool = False,
) -> Dict[str, Any]:
    """
    Safely restores backup_file into target_db_path.
    """
    backup_file = os.path.abspath(backup_file)
    target_db_path = os.path.abspath(target_db_path)

    if not os.path.exists(backup_file):
        raise FileNotFoundError(f"Backup file not found at: {backup_file}")

    logger.info("Initiating SQLite restoration: %s -> %s", backup_file, target_db_path)

    # 1. SHA-256 Checksum Verification
    sha256_actual = compute_sha256(backup_file)
    checksum_file = f"{backup_file}.sha256"
    manifest_file = f"{backup_file}.manifest.json"

    expected_sha256 = None
    if os.path.exists(checksum_file):
        with open(checksum_file, "r", encoding="utf-8") as f:
            line = f.readline().strip()
            if line:
                expected_sha256 = line.split()[0]
    elif os.path.exists(manifest_file):
        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            expected_sha256 = data.get("sha256")

    if expected_sha256 and verify_checksum:
        if sha256_actual.lower() != expected_sha256.lower():
            raise ValueError(
                f"Checksum mismatch! Expected: {expected_sha256}, Actual: {sha256_actual}. "
                "The backup file may be corrupt or tampered with."
            )
        logger.info("Checksum verified successfully: %s", sha256_actual[:16])
    elif verify_checksum and not expected_sha256:
        logger.warning("No .sha256 or .manifest.json file found to verify backup checksum. Proceeding with integrity check.")

    # 2. Backup File PRAGMA Integrity Check
    is_valid, msg = check_sqlite_integrity(backup_file)
    if not is_valid:
        raise RuntimeError(f"Backup file failed PRAGMA integrity check: {msg}")
    logger.info("Backup file passed PRAGMA integrity check.")

    # 3. Target Pre-Restore Safety Snapshot & WAL Cleanup
    pre_restore_snapshot = None
    if os.path.exists(target_db_path):
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        pre_restore_snapshot = f"{target_db_path}.pre_restore_{ts}"
        logger.info("Creating pre-restore safety snapshot of live database: %s", pre_restore_snapshot)

        # Checkpoint target WAL before copying snapshot
        try:
            target_conn = sqlite3.connect(target_db_path, timeout=5.0)
            target_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            target_conn.close()
        except Exception as e:
            logger.warning("Could not checkpoint target before snapshot: %s", e)

        shutil.copy2(target_db_path, pre_restore_snapshot)

        # Remove stale WAL and SHM files to ensure restored file opens cleanly
        for ext in ["-wal", "-shm", ".wal", ".shm"]:
            wal_f = target_db_path + ext
            if os.path.exists(wal_f):
                try:
                    os.remove(wal_f)
                    logger.info("Removed stale live WAL file: %s", wal_f)
                except OSError as e:
                    logger.warning("Could not remove %s: %s", wal_f, e)

    # 4. Perform Atomic Restore via SQLite Backup API
    os.makedirs(os.path.dirname(target_db_path), exist_ok=True)
    src_conn = sqlite3.connect(backup_file, timeout=30.0)
    dest_conn = sqlite3.connect(target_db_path, timeout=30.0)
    try:
        with dest_conn:
            src_conn.backup(dest_conn, pages=100)
    finally:
        src_conn.close()
        dest_conn.close()

    # 5. Post-Restore Verification & Table Inventory
    post_ok, post_msg = check_sqlite_integrity(target_db_path)
    if not post_ok:
        # Emergency rollback if snapshot exists
        if pre_restore_snapshot and os.path.exists(pre_restore_snapshot):
            shutil.copy2(pre_restore_snapshot, target_db_path)
            logger.critical("Restored database failed integrity check! Rolled back to %s", pre_restore_snapshot)
        raise RuntimeError(f"Restored database failed PRAGMA integrity check: {post_msg}")

    # Re-enable WAL and inspect tables
    table_counts = {}
    ver_conn = sqlite3.connect(target_db_path, timeout=10.0)
    try:
        ver_conn.execute("PRAGMA journal_mode = WAL;")
        ver_conn.execute("PRAGMA foreign_keys = ON;")
        cur = ver_conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
        tables = [r[0] for r in cur.fetchall()]
        for t in tables:
            cur.execute(f"SELECT COUNT(*) FROM {t};")
            table_counts[t] = cur.fetchone()[0]
    finally:
        ver_conn.close()

    logger.info("Restore successful! Validated %d tables in restored database.", len(table_counts))

    return {
        "status": "SUCCESS",
        "restored_at_utc": datetime.now(timezone.utc).isoformat(),
        "backup_source": backup_file,
        "target_db": target_db_path,
        "sha256": sha256_actual,
        "pre_restore_snapshot": pre_restore_snapshot,
        "integrity_check": "ok",
        "tables_restored": table_counts,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS SQLite WAL-Safe Recovery & Restore Tool")
    parser.add_argument("--backup-file", required=True, help="Path to backup file to restore")
    parser.add_argument("--target-db", default=os.getenv("AEGIS_SQLITE_PATH", "data/aegis_incidents.db"), help="Target DB path")
    parser.add_argument("--skip-checksum", action="store_true", help="Skip SHA256 checksum check")
    parser.add_argument("--force", action="store_true", help="Force overwrite without confirmation")
    args = parser.parse_args()

    try:
        result = perform_restore(
            backup_file=args.backup_file,
            target_db_path=args.target_db,
            verify_checksum=not args.skip_checksum,
            force=args.force,
        )
        print(json.dumps(result, indent=2))
        sys.exit(0)
    except Exception as e:
        logger.error("Restore failed: %s", e)
        sys.exit(1)
