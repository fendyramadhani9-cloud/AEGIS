-- ==============================================================================
-- AEGIS Security Monitoring & Incident Investigation System
-- Rollback Migration: 004_incident_investigation.sql
--
-- Safety Guarantees:
-- 1. Drops newly created incident and analysis tables in reverse dependency order.
-- 2. Preserves alerts, alert_evidence, telemetry_events, and hosts.
-- 3. Fully non-destructive to historical threat telemetry.
-- ==============================================================================

DROP TABLE IF EXISTS public.incident_status_history CASCADE;
DROP TABLE IF EXISTS public.ai_analyses CASCADE;
DROP TABLE IF EXISTS public.incident_timeline CASCADE;
DROP TABLE IF EXISTS public.incident_alerts CASCADE;
DROP TABLE IF EXISTS public.incidents CASCADE;

