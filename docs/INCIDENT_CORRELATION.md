# AEGIS Incident Correlation & Multi-Factor Risk Model

## 1. Correlation Methodology
The AEGIS Incident Correlator groups discrete alerts into cohesive multi-stage attack scenarios.

### A. Strict Host Partitioning
Alerts are partitioned strictly by `host_id`. Cross-host alert correlation is categorically prohibited to maintain sovereign telemetry isolation per monitored host.

### B. Sliding Temporal Window
Alerts occurring within a configurable sliding window (default `1800` seconds / 30 minutes) are candidates for clustering. When an alert arrives within 30 minutes of the latest event in an active cluster on the same host, the cluster window extends.

### C. Entity Overlap
Alerts sharing common entities are given high correlation affinity:
- **Source IP Address:** E.g., multiple SSH brute-force attempts from `192.168.1.100`.
- **Target User Account:** E.g., failed login for user `ubuntu` followed by sudo privilege execution by `ubuntu`.

### D. Attack Progression Pattern Matching
The engine identifies multi-stage kill chains:
1. `RULE-SSH-BRUTE` (Initial Access Attempt / Credential Stuffing)
2. `RULE-AUTH-003` (Successful Initial Access)
3. `RULE-SUSP-SUDO` (Privilege Escalation / Root Execution)

## 2. Multi-Factor Mathematical Risk Scoring
The risk score (0–100) is calculated objectively through additive, transparent factors:

$$\text{RiskScore} = \min(100, \text{BasePoints} + \text{MultiAlertPoints} + \text{KillChainPoints} + \text{EvidencePoints} + \text{PosturePoints})$$

| Factor Name | Condition / Logic | Max Points |
| :--- | :--- | :--- |
| **Base Alert Severity** | Highest severity in cluster: Critical (+40), High (+30), Medium (+20), Low (+10). | 40 |
| **Multi-Alert Cluster** | Additional alerts in cluster: $+8$ points per additional alert. | 24 |
| **Full Kill Chain** | Simultaneous occurrence of Brute-force + Auth Success + Sudo Root. | 25 |
| **Access Escalation** | Auth Success followed immediately by Suspicious Sudo command. | 18 |
| **Supporting Evidence** | Verified evidence count: $\ge 5$ items (+10), $\ge 2$ items (+6). | 10 |
| **Posture Penalty** | Inactive firewall (`FW-001`) or root SSH permitted (`SSH-001`). | 15 |

### Risk Level Categorization
- **Critical (80–100):** Immediate containment required. Active breach progression.
- **High (60–79):** High-confidence attack or privilege escalation attempt.
- **Medium (40–59):** Repeated suspicious attempts without confirmed access.
- **Low (0–39):** Isolated informational or single failed attempt.

## 3. Stable Incident ID Generation
Incident identifiers are generated using a deterministic SHA-256 digest:
$$\text{Digest} = \text{SHA256}(\text{host\_id} + ":" + \text{join}(\text{sorted}(\text{alert\_ids})))[0:12]$$
$$\text{IncidentID} = \text{"INC-"} + \text{host\_id} + \text{"-"} + \text{Digest}$$
This guarantees that re-running correlation produces stable, idempotent identifiers.
