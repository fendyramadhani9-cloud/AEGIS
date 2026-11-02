# AEGIS — Responsive Security Dashboard (Mobile + Desktop)

Production-ready responsive UI/UX for AEGIS, a Linux security monitoring and incident investigation application built with React 18, TypeScript, Vite, and Lucide icons.

## Responsive Capabilities

- **Mobile (< 768px):** Thumb-friendly bottom navigation bar, single-column touch cards, and bottom sheet drawers for fast incident triage on mobile screens.
- **Desktop (>= 1024px) & Tablet (>= 768px):** Persistent left sidebar with real-time evidence mode indicator and pipeline status, multi-column investigation grids (1.4fr / 1fr), structured data tables with log source matrices, and center modal dialogs.
- **Both Themes Available Everywhere:** Warm Ivory / Forest Green light theme and Deep Charcoal / Liquid Amber dark theme, with a one-click switcher in the desktop sidebar and Settings.

## Quick Start

```bash
cd dashboard
npm install
npm run dev
```

Visit `http://localhost:5173` in a mobile viewport or mobile device emulator.

## Build & Typecheck

```bash
cd dashboard
npm run build
```

## Features & PRD Compliance

- **Brand & Themes:** Warm Ivory / Forest Green light theme & Deep Charcoal / Liquid Amber dark theme, integrated with the official AEGIS owl logo.
- **Deterministic Detection First:** Clearly separates deterministic Rules Engine alerts from Security Checker configuration findings.
- **AI Contextualization:** Dedicated AI analysis panels for the 3 backend AI roles (`SC Analysis Agent`, `RM Analysis Agent`, `Reporting Agent`).
- **Honest Telemetry:** Visualizes telemetry gaps with diagonal hatched blocks. Never implies that missing events were recovered.
- **Emergency Evidence Mode:** Live countdown bar, authorized reasons, automatic expiration, and private storage safeguards.
- **Interactive State Simulator:** Toggle between Sample, Loading, Empty, and Error states in Settings.

