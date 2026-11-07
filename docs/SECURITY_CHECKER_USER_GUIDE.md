# AEGIS Security Checker: Administrator User Guide

## 1. Accessing the Dashboard

1. Navigate to the AEGIS Web Dashboard:
   - **Production URL**: `https://aegis.diazz.web.id`
   - **Local URL**: `http://localhost:80` (or host IP)
2. In the navigation sidebar, click on **Detections** (`/detections`).
3. In the subheader toggle, switch to **SC checks** (Security Checker).

---

## 2. Interpreting the Security Overview

At the top of the **SC checks** tab, summary metrics display the posture of your infrastructure:
- **Total Checks**: Total number of evaluated configuration rules.
- **Passed**: Green count indicating checks meeting security compliance.
- **Failed**: Red count indicating active security vulnerabilities requiring remediation.
- **Warning**: Amber count indicating deviations from best practices or non-ideal configurations.
- **Not Applicable**: Grey count for checks not relevant to the host's current configuration (e.g. firewall policy when firewall is disabled).

---

## 3. Filtering & Searching Findings

- **Host Filter**: Select a specific host from the dropdown to focus on its posture, or select **All hosts**.
- **Search Bar**: Type any keyword, title fragment, or Check ID (e.g. `SSH-001`, `firewall`, `sudo`) to filter results instantly.
- **Status Chips**: Filter by `All Status`, `Failed`, `Warning`, `Passed`, `N/A`, `Error`, or `Not Checked`.
- **Category Chips**: Filter by security domains: `SSH`, `Account`, `Firewall`, `System`, `Logging`, `Network`, `Filesystem`.
- **Severity Chips**: Filter by impact: `Critical`, `High`, `Medium`, `Low`.

---

## 4. Triggering an On-Demand Security Scan

1. From the **Detections** screen (or a specific **Host Detail** screen):
2. Click the **Run Security Check** button.
3. The button will display `Scanning…` while the agent performs the read-only audit.
4. Upon completion, a confirmation notice displays the Run ID and the table refreshes automatically with fresh findings.

---

## 5. Reviewing Finding Details & Executing Remediation

1. In the checks list, click **Details** on any row.
2. In the **Security Checker Result** screen:
   - **Observed Configuration vs. Standard**: Compares the host's actual observed state with the compliant baseline.
   - **Security Impact**: Explains what attack vector is enabled if this finding is left unaddressed.
   - **Remediation Guidance**: Contains actionable bash commands formatted in copyable code blocks.
   - **Evidence & Command Output**: Expandable drawer revealing raw inspection output and diagnostic evidence.
   - **References**: Lists standard citations (e.g. CIS Ubuntu Linux Benchmark 24.04).
3. Apply the recommended fix on the host and re-run the check to confirm remediation.
