"""
AEGIS SQLite Hot Online Backup Tool (WAL-Safe).
Safely captures an ACID-consistent snapshot of an active SQLite database in WAL mode
using SQLite's Online Backup API.

Guarantees:
1. Online, lock-free backup without interrupting backend operations.
2. Complete transaction capture including uncheckpointed WAL frames.
3. Pre- and post-backup PRAGMA integrity verification.
4. Cryptographic SHA-256 manifest generation for tamper detection.
5. Automated retention rotation (retaining last N backups).
"""

import os
import sys
import json
import sqlite3
import hashlib
import argparse
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis_backup")


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


def perform_backup(
    source_db_path: str,
    output_dir: str,
    retention_count: int = 10,
) -> Dict[str, Any]:
    """
    Performs hot online backup of source SQLite database into output directory.
    """
    source_db_path = os.path.abspath(source_db_path)
    if not os.path.exists(source_db_path):
        raise FileNotFoundError(f"Source database not found at {source_db_path}")

    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = os.path.basename(source_db_path)
    backup_filename = f"{base_name}.backup_{timestamp}"
    backup_filepath = os.path.abspath(os.path.join(output_dir, backup_filename))

    logger.info("Starting hot online backup: %s -> %s", source_db_path, backup_filepath)

    # 1. Pre-backup source integrity check
    pre_ok, pre_msg = check_sqlite_integrity(source_db_path)
    if not pre_ok:
        logger.warning("Pre-backup source integrity check warning: %s", pre_msg)

    # 2. Hot Online Backup using sqlite3 backup API
    src_conn = sqlite3.connect(source_db_path, timeout=30.0)
    dest_conn = sqlite3.connect(backup_filepath, timeout=30.0)
    try:
        with dest_conn:
            src_conn.backup(dest_conn, pages=100)
    finally:
        src_conn.close()
        dest_conn.close()

    # 3. Post-backup integrity verification
    post_ok, post_msg = check_sqlite_integrity(backup_filepath)
    if not post_ok:
        raise RuntimeError(f"Backup file corrupted! Integrity check failed: {post_msg}")

    # 4. Checksum computation
    sha256_hash = compute_sha256(backup_filepath)
    checksum_filepath = f"{backup_filepath}.sha256"
    with open(checksum_filepath, "w", encoding="utf-8") as f:
        f.write(f"{sha256_hash}  {os.path.basename(backup_filepath)}\n")

    file_size = os.path.getsize(backup_filepath)
    logger.info("Backup successfully completed. Size: %d bytes, SHA256: %s", file_size, sha256_hash[:16])

    # 5. Backup Retention Rotation
    backups = []
    for fname in os.listdir(output_dir):
        if fname.startswith(f"{base_name}.backup_") and not fname.endswith(".sha256"):
            fpath = os.path.join(output_dir, fname)
            backups.append((os.path.getmtime(fpath), fpath))
    backups.sort(key=lambda x: x[0], reverse=True)

    pruned = []
    if len(backups) > retention_count:
        for _, old_backup in backups[retention_count:]:
            try:
                os.remove(old_backup)
                pruned.append(old_backup)
                old_sha = f"{old_backup}.sha256"
                if os.path.exists(old_sha):
                    os.remove(old_sha)
                logger.info("Pruned old backup: %s", old_backup)
            except OSError as e:
                logger.warning("Failed to prune %s: %s", old_backup, e)

    metadata = {
        "status": "SUCCESS",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_db": source_db_path,
        "backup_file": backup_filepath,
        "checksum_file": checksum_filepath,
        "sha256": sha256_hash,
        "size_bytes": file_size,
        "integrity_check": "ok",
        "retention_count": retention_count,
        "pruned_backups": pruned,
    }

    manifest_path = f"{backup_filepath}.manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS SQLite WAL-Safe Hot Online Backup Tool")
    parser.add_argument("--db-path", default=os.getenv("AEGIS_SQLITE_PATH", "data/aegis_incidents.db"), help="Source DB path")
    parser.add_argument("--output-dir", default="data/backups", help="Destination backup directory")
    parser.add_argument("--retention", type=int, default=10, help="Number of backups to retain")
    args = parser.parse_args()

    try:
        result = perform_backup(args.db_path, args.output_dir, args.retention)
        print(json.dumps(result, indent=2))
        sys.exit(0)
    except Exception as e:
        logger.error("Backup failed: %s", e)
        sys.exit(1)
