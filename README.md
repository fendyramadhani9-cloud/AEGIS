# AEGIS

> Linux Security Monitoring & Incident Investigation System for Ubuntu Server.

AEGIS (formerly SentinelTrace) is a security monitoring and incident investigation platform designed specifically for system administrators and DevOps teams managing fleet-scale Ubuntu servers. It couples deterministic host security telemetry with AI-powered incident triage, explanation, and report generation.

---

## Key Features

- **Security Checker (SC):** Baseline configuration auditing, permissions scanning, and CIS-aligned vulnerability checks.
- **Runtime Monitor (RM):** Real-time observation of process executions, authentication events, systemd units, network sockets, and file integrity.
- **Deterministic Rules Engine:** Transparent and explainable threat detection that never relies on probabilistic black-box decisions for primary alerts.
- **Telemetry Gaps Visibility:** Explicitly highlights periods or sources where data collection was interrupted or unavailable, preventing false assumptions of security.
- **Emergency Evidence Mode:** Controlled, time-bounded on-demand forensic evidence gathering during active incident investigations.
- **AI Analysis Agents:** Localized AI explanation, uncertainty flagging, triage assistance, and automated PDF report compilation. (No automatic blocking or system modification).
- **Executive & Incident Reports:** Automated generation of daily health digests and incident post-mortem PDF documents.

---

## UI / UX Architecture

- **Mobile-First & Desktop Dashboard:** Responsive custom CSS design system optimized for mobile (< 768px), tablet (768px–1023px), and desktop (>= 1024px).
- **Dual Visual Themes:**
  - **Light Mode:** Warm Ivory (`#F7F6F1`) background with Forest Green (`#14432A`) brand accents and Amber highlights.
  - **Dark Mode:** Deep Charcoal (`#121415`) background with Liquid Amber accents and restrained luminescent indicators.
- **Accessible & Honest:** Clear typography (Inter & JetBrains Mono), WCAG AAA contrast, semantic color badges paired with distinct icons, and full body scroll locks for modal dialogs.

---

## Tech Stack

- **Frontend:** React 18, TypeScript, Vite, Lucide Icons, React Router v6.
- **Styling:** Custom Vanilla CSS Design System with CSS variables and responsive media queries.
- **Target OS Monitored:** Ubuntu Server 22.04 LTS / 24.04 LTS.

---

## Getting Started

```bash
cd dashboard
npm install
npm run dev
```

To build for production:

```bash
cd dashboard
npm run build
npm run preview
```
