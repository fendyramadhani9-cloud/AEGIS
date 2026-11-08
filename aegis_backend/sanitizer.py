"""
Telemetry Sanitizer & Redaction Module for AEGIS.
Enforces PRD §8 (Data Protection and Security Constraints).

Executes PRE-PARSING and PRE-STORAGE inspection to guarantee that sensitive credentials,
private keys, password hashes, and tokens never enter the database or AI pipeline.
Strictly rejects or quarantines any record containing sensitive secrets.
"""

import re
from typing import Tuple, Optional, Dict, Any, List


class TelemetrySanitizer:
    """
    Validates log lines and event payloads against strict secret & credential patterns.
    If any secret is detected, the line is flagged as unsafe and must be quarantined.
    """

    # 1. Private Cryptographic Keys (OpenSSH, RSA, EC, DSA, PGP, and base64 openssh-key-v1 signature)
    _RE_PRIVATE_KEY = re.compile(
        r"(?:-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----|b3BlbnNzaC1rZXk)",
        re.IGNORECASE,
    )

    # 2. Unix Password Hashes & Shadow Entries
    # Standard crypt hashes: $1$ (MD5), $5$ (SHA-256), $6$ (SHA-512), $y$ (yescrypt), $argon2
    _RE_SHADOW_HASH = re.compile(
        r"(?:^|[\s:])\$(?:[156y]|argon2[a-z0-9]*)\$[a-zA-Z0-9./$+=_-]{16,}",
        re.IGNORECASE,
    )

    # 3. HTTP Authorization Headers & Bearer Tokens
    _RE_AUTH_HEADER = re.compile(
        r"(?i)(?:authorization:\s*(?:bearer|basic)\s+[^\s]+|bearer\s+[a-zA-Z0-9_\-\.]{20,})",
    )

    # 4. Explicit Password / Credential Key-Value Pairs
    # E.g., password=secret123, passwd: mypass, api_key = "xyz..."
    # Note: 'pwd' is deliberately excluded to prevent false positives with Unix 'PWD=/...' in sudoers logs.
    _RE_CREDENTIAL_KV = re.compile(
        r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"]?[^\s'\",;&]+['\"]?",
    )

    # 5. Sensitive Command Line Arguments (Auditd EXECVE or process args)
    # E.g., -p Password123, --password=xxx, --token=xxx, -u user:password
    _RE_CLI_CREDENTIAL = re.compile(
        r"(?i)(?:--password[=\s]+[^\s]+|(?:\s|^)-p\s+[^\s\-]+|--token[=\s]+[^\s]+|(?:\s|^)-u\s+[a-zA-Z0-9_-]+:[^\s]+)",
    )

    # 6. Common Cloud / Platform Secret Tokens
    _RE_PLATFORM_SECRETS = re.compile(
        r"(?:\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z-_]{35}\b|\bghp_[0-9a-zA-Z]{36}\b|\bsb_secret_[a-zA-Z0-9_-]+\b)",
    )

    # 7. Database & Service URIs with embedded credentials (user:password@host)
    _RE_URI_CREDENTIAL = re.compile(
        r"[a-z0-9+.-]+:\/\/[a-zA-Z0-9._%+-]+:[^\s@]+@[a-zA-Z0-9.-]+",
        re.IGNORECASE,
    )

    @classmethod
    def inspect_line(cls, line: str) -> Tuple[bool, Optional[str]]:
        """
        Inspects a single raw log line for sensitive credentials or keys.
        
        Returns:
            (is_safe, violation_reason)
            If is_safe is False, the line MUST NOT be parsed or stored in the database.
        """
        if not line:
            return True, None

        if cls._RE_PRIVATE_KEY.search(line):
            return False, "private_key_detected"

        if cls._RE_SHADOW_HASH.search(line):
            return False, "password_hash_detected"

        if cls._RE_AUTH_HEADER.search(line):
            return False, "auth_token_detected"

        if cls._RE_CREDENTIAL_KV.search(line):
            return False, "credential_kv_detected"

        if cls._RE_CLI_CREDENTIAL.search(line):
            return False, "cli_credential_detected"

        if cls._RE_PLATFORM_SECRETS.search(line):
            return False, "platform_token_detected"

        if cls._RE_URI_CREDENTIAL.search(line):
            return False, "uri_credential_detected"

        return True, None

    @classmethod
    def inspect_dict(cls, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Recursively checks a dictionary of event details for sensitive secrets."""
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(secret_term in k_lower for secret_term in ["password", "passwd", "secret", "private_key", "token"]):
                return False, f"sensitive_key_detected_{k}"
            if isinstance(v, str):
                is_safe, reason = cls.inspect_line(v)
                if not is_safe:
                    return False, reason
            elif isinstance(v, dict):
                is_safe, reason = cls.inspect_dict(v)
                if not is_safe:
                    return False, reason
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        is_safe, reason = cls.inspect_line(item)
                        if not is_safe:
                            return False, reason
                    elif isinstance(item, dict):
                        is_safe, reason = cls.inspect_dict(item)
                        if not is_safe:
                            return False, reason
        return True, None

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """
        Redacts sensitive tokens, private keys, passwords, and authorization headers from text
        so it can safely be sent to AI providers or logged.
        """
        if not text:
            return ""
        redacted = cls._RE_PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)
        redacted = cls._RE_SHADOW_HASH.sub(" [REDACTED_HASH]", redacted)
        redacted = cls._RE_AUTH_HEADER.sub("Authorization: [REDACTED_AUTH_TOKEN]", redacted)
        redacted = cls._RE_CREDENTIAL_KV.sub("[REDACTED_SECRET]", redacted)
        redacted = cls._RE_CLI_CREDENTIAL.sub("[REDACTED_CLI_ARG]", redacted)
        redacted = cls._RE_PLATFORM_SECRETS.sub("[REDACTED_PLATFORM_KEY]", redacted)
        redacted = cls._RE_URI_CREDENTIAL.sub("[REDACTED_URI]", redacted)
        return redacted

    mask_text = sanitize_text

    @classmethod
    def mask_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitizes dictionary values recursively."""
        if not data or not isinstance(data, dict):
            return {}
        cleaned = {}
        sensitive_keys = {"password", "passwd", "token", "secret", "private_key", "api_key", "authorization"}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in sensitive_keys):
                cleaned[k] = "[REDACTED_SECRET]"
            elif isinstance(v, str):
                cleaned[k] = cls.sanitize_text(v)
            elif isinstance(v, dict):
                cleaned[k] = cls.mask_dict(v)
            elif isinstance(v, list):
                cleaned[k] = [
                    cls.mask_dict(i) if isinstance(i, dict) else cls.sanitize_text(str(i)) if isinstance(i, str) else i
                    for i in v
                ]
            else:
                cleaned[k] = v
        return cleaned
