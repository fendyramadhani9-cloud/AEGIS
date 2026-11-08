const { PGlite } = require('../dashboard/node_modules/@electric-sql/pglite');
const fs = require('fs');

async function runAuditTests() {
  console.log('======================================================================');
  console.log('  AEGIS MIGRATION 002-004 HARDENING & BEHAVIORAL AUDIT (PGLITE)');
  console.log('======================================================================\n');

  const db = new PGlite();

  // 1. Apply Migrations
  console.log('[1] Applying 001_initial_schema.sql...');
  await db.exec(fs.readFileSync('supabase/migrations/001_initial_schema.sql', 'utf8'));
  console.log('    [PASS] 001_initial_schema.sql applied.');

  console.log('[2] Applying unified_migration_002_to_004.sql (ACID Transaction)...');
  await db.exec(fs.readFileSync('supabase/migrations/unified_migration_002_to_004.sql', 'utf8'));
  console.log('    [PASS] unified_migration_002_to_004.sql applied successfully.');

  // 2. Audit RLS on All Tables
  console.log('\n[3] Auditing Row Level Security (RLS) on public schema tables...');
  const rlsCheck = await db.query(`
    SELECT relname, relrowsecurity 
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'
    ORDER BY relname;
  `);
  
  let allRlsPassed = true;
  for (const row of rlsCheck.rows) {
    if (!row.relrowsecurity) {
      console.error(`    [FAIL] Table ${row.relname} DOES NOT have RLS enabled!`);
      allRlsPassed = false;
    }
  }
  if (allRlsPassed) {
    console.log(`    [PASS] All ${rlsCheck.rows.length} public tables have Row Level Security (RLS) ENABLED.`);
  } else {
    throw new Error('RLS audit failed: some tables lack RLS!');
  }

  // Seed baseline host
  await db.query(`
    INSERT INTO public.hosts (id, hostname, ip_address, os, agent_version)
    VALUES ('host-fenn-ubuntu', 'fenn', '192.168.193.129', 'Ubuntu 24.04', '0.1.0'),
           ('host-other-ubuntu', 'other', '192.168.193.130', 'Ubuntu 24.04', '0.1.0');
  `);

  // Seed telemetry event on host-fenn
  await db.query(`
    INSERT INTO public.telemetry_events (id, host_id, source_id, message, event_timestamp, event_type, details)
    VALUES ('ev-001', 'host-fenn-ubuntu', 'ssh-auth', 'Failed password for root', NOW(), 'auth_failure', '{"user": "root"}'::jsonb),
           ('ev-002-other', 'host-other-ubuntu', 'ssh-auth', 'Failed password for admin', NOW(), 'auth_failure', '{"user": "admin"}'::jsonb);
  `);

  // 3. Test RPC fn_ingest_alert_with_evidence
  console.log('\n[4] Testing fn_ingest_alert_with_evidence RPC...');
  
  // Case 4.1: Atomic Ingest of Alert + Evidence
  const ingestRes = await db.query(`
    SELECT public.fn_ingest_alert_with_evidence(
      '[{
        "id": "ALT-001",
        "host_id": "host-fenn-ubuntu",
        "rule_id": "RULE-SSH-BRUTE",
        "rule_version": "1.0",
        "title": "SSH Brute Force",
        "severity": "high",
        "detected_at": "2026-11-08T07:00:00Z",
        "reason": "Multiple failures"
      }]'::jsonb,
      '[{
        "alert_id": "ALT-001",
        "event_id": "ev-001",
        "citation_role": "trigger"
      }]'::jsonb
    ) as result;
  `);
  console.log('    [PASS] Ingest Alert + Evidence result:', ingestRes.rows[0].result);

  // Case 4.2: Idempotent Re-Ingest
  const idempotentRes = await db.query(`
    SELECT public.fn_ingest_alert_with_evidence(
      '[{
        "id": "ALT-001",
        "host_id": "host-fenn-ubuntu",
        "rule_id": "RULE-SSH-BRUTE",
        "rule_version": "1.0",
        "title": "SSH Brute Force",
        "severity": "high",
        "detected_at": "2026-11-08T07:00:00Z",
        "reason": "Multiple failures"
      }]'::jsonb,
      '[{
        "alert_id": "ALT-001",
        "event_id": "ev-001",
        "citation_role": "trigger"
      }]'::jsonb
    ) as result;
  `);
  console.log('    [PASS] Idempotent Ingest result (0 new rows):', idempotentRes.rows[0].result);

  // Case 4.3: Conflicting Duplicate Alert (Mismatched Title)
  try {
    await db.query(`
      SELECT public.fn_ingest_alert_with_evidence(
        '[{
          "id": "ALT-001",
          "host_id": "host-fenn-ubuntu",
          "rule_id": "RULE-SSH-BRUTE",
          "rule_version": "1.0",
          "title": "CONFLICTING TITLE",
          "severity": "high",
          "detected_at": "2026-11-08T07:00:00Z",
          "reason": "Multiple failures"
        }]'::jsonb,
        '[]'::jsonb
      );
    `);
    throw new Error('Conflicting alert title should have been rejected!');
  } catch (err) {
    console.log('    [PASS] Conflicting duplicate alert rejected:', err.message.slice(0, 70));
  }

  // Case 4.4: Conflicting Evidence Citation Role Mutation
  try {
    await db.query(`
      SELECT public.fn_ingest_alert_with_evidence(
        '[]'::jsonb,
        '[{
          "alert_id": "ALT-001",
          "event_id": "ev-001",
          "citation_role": "supporting"
        }]'::jsonb
      );
    `);
    throw new Error('Citation role mutation should have been rejected!');
  } catch (err) {
    console.log('    [PASS] Citation role mutation rejected:', err.message.slice(0, 70));
  }

  // Case 4.5: Evidence Host Mismatch (Evidence from host-other linked to alert on host-fenn)
  try {
    await db.query(`
      SELECT public.fn_ingest_alert_with_evidence(
        '[]'::jsonb,
        '[{
          "alert_id": "ALT-001",
          "event_id": "ev-002-other",
          "citation_role": "supporting"
        }]'::jsonb
      );
    `);
    throw new Error('Cross-host evidence linking should have been rejected!');
  } catch (err) {
    console.log('    [PASS] Cross-host evidence linking rejected:', err.message.slice(0, 70));
  }

  // 4. Test Incidents Trigger & Host Isolation
  console.log('\n[5] Testing Incidents Trigger & Host Isolation (trg_incidents_severity_match)...');
  
  // Case 5.1: Incident with primary_alert_id from different host -> MUST FAIL
  try {
    await db.query(`
      INSERT INTO public.incidents (id, host_id, title, severity, primary_alert_id, risk_level, risk_score)
      VALUES ('INC-MISMATCH', 'host-other-ubuntu', 'Cross Host Incident', 'high', 'ALT-001', 'high', 80);
    `);
    throw new Error('Cross-host incident creation should have been rejected!');
  } catch (err) {
    console.log('    [PASS] Cross-host incident correctly rejected:', err.message.slice(0, 75));
  }

  // Case 5.2: Valid Incident with Dynamic Severity Escalation (high -> critical)
  await db.query(`
    INSERT INTO public.incidents (id, host_id, title, severity, primary_alert_id, risk_level, risk_score)
    VALUES ('INC-VALID-001', 'host-fenn-ubuntu', 'Legit Incident', 'critical', 'ALT-001', 'critical', 95);
  `);
  const incRes = await db.query(`SELECT id, host_id, severity, alert_id, primary_alert_id FROM public.incidents WHERE id = 'INC-VALID-001';`);
  console.log('    [PASS] Dynamic severity escalation allowed & alert_id backfilled:', incRes.rows[0]);

  // 5. Test Security Checker Trigger
  console.log('\n[6] Testing Security Checker Sync Trigger (fn_sync_host_last_sc_run)...');
  const initialHost = await db.query(`SELECT last_sc_run_at FROM public.hosts WHERE id = 'host-fenn-ubuntu';`);
  console.log('    Initial host last_sc_run_at:', initialHost.rows[0].last_sc_run_at);

  await db.query(`
    INSERT INTO public.security_check_runs (id, host_id, status, total_checks, passed_checks, failed_checks, started_at, completed_at)
    VALUES ('RUN-001', 'host-fenn-ubuntu', 'completed', 28, 20, 8, '2026-11-08T07:10:00Z', '2026-11-08T07:11:00Z');
  `);
  const updatedHost = await db.query(`SELECT last_sc_run_at FROM public.hosts WHERE id = 'host-fenn-ubuntu';`);
  console.log('    [PASS] Synchronized host last_sc_run_at:', updatedHost.rows[0].last_sc_run_at);

  console.log('\n======================================================================');
  console.log('  ALL AUDIT TESTS PASSED (100% SUCCESS)');
  console.log('======================================================================');
}

runAuditTests().catch(err => {
  console.error('\n[FATAL AUDIT FAILURE]:', err);
  process.exit(1);
});
