# AEGIS AI Security, Privacy Boundaries & Anti-Hallucination Guardrails

## 1. Zero-Trust Telemetry Sanitization
AEGIS enforces strict pre-storage and pre-transmission sanitization via `TelemetrySanitizer` in compliance with PRD §8.

### Sanitized Categories
- **Cryptographic Private Keys:** RSA, OpenSSH, EC, DSA (`-----BEGIN ... PRIVATE KEY-----` and `b3BlbnNzaC1rZXk`).
- **Unix Shadow Passwords:** `$1$`, `$5$`, `$6$`, `$y$`, and `$argon2` crypt strings.
- **Authorization Headers:** `Authorization: Bearer <token>` and `Basic <base64>`.
- **Credential Key-Value Pairs:** `password=`, `passwd=`, `api_key=`, `access_token=`, `client_secret=`.
- **CLI Password Arguments:** `--password <val>`, `-p <val>`, `-u user:pass`.
- **Platform Secret Tokens:** AWS Access Keys (`AKIA...`), Google API Keys (`AIza...`), GitHub Personal Access Tokens (`ghp_...`).
- **URI Connection Credentials:** `postgres://user:password@host:port/db`.

## 2. Anti-Hallucination Guardrails
To prevent generative AI from fabricating forensic facts, AEGIS imposes four non-negotiable boundaries:

### A. Strict Evidence Whitelist (`allowed_evidence_ids`)
Every forensic prompt contains an explicit whitelist of verified telemetry event IDs (`allowed_evidence_ids`). Upon receiving the LLM response, the engine executes strict validation:
```python
valid_citations = [cid for cid in cited if cid in context.allowed_evidence_ids]
```
Any event ID not present in the whitelist is dropped. The AI is prevented from citing fictitious logs.

### B. Quantitative Event Count Fidelity
The investigation prompt instructs the model to preserve exact numerical fidelity (e.g. "3 failed attempts" rather than "hundreds of attempts").

### C. Immutable Severity Binding
Incident risk levels and alert severities are established by the deterministic engine. The LLM cannot downgrade or inflate threat severity.

### D. Prompt Injection Defense
Raw log messages are wrapped inside JSON forensic structures with explicit instructions treating them as untrusted raw telemetry. Injected commands like `IGNORE ALL PREVIOUS INSTRUCTIONS` are rendered harmless and treated as inert strings.
