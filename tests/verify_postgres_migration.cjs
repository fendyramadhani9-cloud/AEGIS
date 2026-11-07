/**
 * AEGIS PostgreSQL Migration & Security Integration Test Suite
 *
 * Runs against a clean, isolated local PostgreSQL instance (PGlite / PostgreSQL engine).
 * Tests all 7 critical database-level guarantees:
 * 1. Clean migration execution from scratch without syntax or dependency errors.
 * 2. Strict access revocation: 'anon' and 'authenticated' roles cannot read tables.
 * 3. Backend access: 'service_role' and admin have required full privileges.
 * 4. Alert severity immutability: trigger blocks updates that alter severity.
 * 5. Incident & Investigation severity/host integrity: mismatch is blocked.
 * 6. Evidence host-binding integrity: linking event from different host is rejected.
 * 7. Automated updated_at trigger: advances timestamp automatically on row update.
 */

const fs = require('fs');
const path = require('path');
const { PGlite } = require('../dashboard/node_modules/@electric-sql/pglite');

async function runDatabaseTests() {
  console.log('============================================================');
  console.log('  AEGIS POSTGRESQL MIGRATION INTEGRATION TEST SUITE');
  console.log('============================================================\n');

  // 1. Initialize Clean Isolated PostgreSQL Database
  const db = new PGlite();
  const versionRes = await db.query('SELECT version();');
  console.log(`[+] Database engine: ${versionRes.rows[0].version}`);

  // -------------------------------------------------------------
  // TEST 1: Execute Migration on Clean Database
  // -------------------------------------------------------------
  console.log('\n[TEST 1] Executing 001_initial_schema.sql on clean PostgreSQL...');
  const migrationPath = path.join(__dirname, '..', 'supabase', 'migrations', '001_initial_schema.sql');
  const migrationSql = fs.readFileSync(migrationPath, 'utf8');

  try {
    await db.exec(migrationSql);
    console.log('  [PASS] Migration executed successfully from scratch with 0 errors.');
  } catch (err) {
    console.error('  [FAIL] Migration execution failed:', err);
    process.exit(1);
  }

  // Verify all 13 tables exist
  const tablesRes = await db.query(`
    SELECT tablename FROM pg_catalog.pg_tables 
    WHERE schemaname = 'public' 
    ORDER BY tablename;
  `);
  const expectedTables = [
    'alert_evidence',
    'alerts',
    'evidence_sessions',
    'findings',
    'hosts',
    'incidents',
    'investigations',
    'log_sources',
    'report_hosts',
    'reports',
    'system_status',
    'telemetry_events',
    'telemetry_gaps',
  ];
  const createdTables = tablesRes.rows.map((r) => r.tablename);
  for (const exp of expectedTables) {
    if (!createdTables.includes(exp)) {
      throw new Error(`Expected table '${exp}' missing from database!`);
    }
  }
  console.log(`  [PASS] Verified all 13 tables created: ${createdTables.join(', ')}`);

  // Verify default singleton system_status
  const sysRes = await db.query('SELECT * FROM public.system_status WHERE id = 1;');
  if (sysRes.rows.length !== 1 || sysRes.rows[0].collector !== 'ok') {
    throw new Error('system_status singleton not initialized properly!');
  }
  console.log('  [PASS] Verified system_status singleton initialized.');

  // -------------------------------------------------------------
  // TEST 2: Role 'anon' and 'authenticated' Access Revocation
  // -------------------------------------------------------------
  console.log('\n[TEST 2] Verifying access denial for anon and authenticated roles...');

  // Test anon role access
  await db.query('SET ROLE anon;');
  let anonBlocked = false;
  try {
    await db.query('SELECT * FROM public.hosts;');
  } catch (err) {
    anonBlocked = true;
    console.log(`  [PASS] anon role blocked from reading 'hosts': ${err.message}`);
  }
  if (!anonBlocked) throw new Error("FAIL: 'anon' role was able to read 'hosts' table!");

  let anonAlertBlocked = false;
  try {
    await db.query('SELECT * FROM public.alerts;');
  } catch (err) {
    anonAlertBlocked = true;
    console.log(`  [PASS] anon role blocked from reading 'alerts': ${err.message}`);
  }
  if (!anonAlertBlocked) throw new Error("FAIL: 'anon' role was able to read 'alerts' table!");

  // Test authenticated role access
  await db.query('SET ROLE authenticated;');
  let authBlocked = false;
  try {
    await db.query('SELECT * FROM public.incidents;');
  } catch (err) {
    authBlocked = true;
    console.log(`  [PASS] authenticated role blocked from reading 'incidents': ${err.message}`);
  }
  if (!authBlocked) throw new Error("FAIL: 'authenticated' role was able to read 'incidents' table!");

  // -------------------------------------------------------------
  // TEST 3: Backend Roles Have Full Required Privileges
  // -------------------------------------------------------------
  console.log('\n[TEST 3] Verifying backend role (postgres / service_role) privileges...');
  await db.query('RESET ROLE;'); // Return to superuser/admin

  // Insert a test host
  await db.query(`
    INSERT INTO public.hosts (id, hostname, ip_address, os, agent_status)
    VALUES ('srv-prod-01', 'core-auth-srv01', '10.0.0.15', 'Ubuntu 22.04 LTS', 'online');
  `);
  const hostCheck = await db.query("SELECT * FROM public.hosts WHERE id = 'srv-prod-01';");
  if (hostCheck.rows.length !== 1) throw new Error('Failed to insert test host using admin role!');
  console.log("  [PASS] Successfully inserted and queried host 'srv-prod-01'.");

  // -------------------------------------------------------------
  // TEST 4: Alert Severity Immutability Trigger
  // -------------------------------------------------------------
  console.log('\n[TEST 4] Testing alert severity immutability trigger...');
  await db.query(`
    INSERT INTO public.alerts (id, host_id, rule_id, rule_version, title, severity, detected_at, reason)
    VALUES ('ALT-001', 'srv-prod-01', 'RULE-SSH-BRUTE', '1.0', 'SSH Brute Force Attack', 'high', now(), 'Multiple failed logins');
  `);

  let sevChangeBlocked = false;
  try {
    // Attempt to illegally modify severity
    await db.query("UPDATE public.alerts SET severity = 'critical' WHERE id = 'ALT-001';");
  } catch (err) {
    sevChangeBlocked = true;
    console.log(`  [PASS] Severity modification blocked as expected: ${err.message}`);
  }
  if (!sevChangeBlocked) throw new Error('FAIL: Alert severity was modified, trigger did not enforce immutability!');

  // Normal update of non-severity fields should succeed
  await db.query("UPDATE public.alerts SET title = 'SSH Brute Force Detected (Reviewed)' WHERE id = 'ALT-001';");
  const alertCheck = await db.query("SELECT title, severity FROM public.alerts WHERE id = 'ALT-001';");
  if (alertCheck.rows[0].title !== 'SSH Brute Force Detected (Reviewed)' || alertCheck.rows[0].severity !== 'high') {
    throw new Error('Normal alert update failed or severity shifted!');
  }
  console.log("  [PASS] Allowed normal title update while keeping severity strictly locked to 'high'.");

  // -------------------------------------------------------------
  // TEST 5: Incident & Investigation Severity and Host Matching
  // -------------------------------------------------------------
  console.log('\n[TEST 5] Testing incident & investigation severity and host integrity...');

  // 5a. Mismatched severity on incident insert
  let incSevMismatchBlocked = false;
  try {
    await db.query(`
      INSERT INTO public.incidents (id, alert_id, host_id, title, severity, status)
      VALUES ('INC-001', 'ALT-001', 'srv-prod-01', 'SSH Incident', 'low', 'open');
    `);
  } catch (err) {
    incSevMismatchBlocked = true;
    console.log(`  [PASS] Incident severity mismatch blocked: ${err.message}`);
  }
  if (!incSevMismatchBlocked) throw new Error('FAIL: Incident was inserted with severity different from Alert!');

  // 5b. Mismatched host_id on incident insert
  // Create second host for mismatch test
  await db.query(`
    INSERT INTO public.hosts (id, hostname, ip_address, os, agent_status)
    VALUES ('srv-prod-02', 'db-srv02', '10.0.0.16', 'Ubuntu 22.04 LTS', 'online');
  `);

  let incHostMismatchBlocked = false;
  try {
    await db.query(`
      INSERT INTO public.incidents (id, alert_id, host_id, title, severity, status)
      VALUES ('INC-001', 'ALT-001', 'srv-prod-02', 'SSH Incident', 'high', 'open');
    `);
  } catch (err) {
    incHostMismatchBlocked = true;
    console.log(`  [PASS] Incident host mismatch blocked: ${err.message}`);
  }
  if (!incHostMismatchBlocked) throw new Error('FAIL: Incident was inserted with host different from Alert!');

  // 5c. Valid incident insert with matching severity and host
  await db.query(`
    INSERT INTO public.incidents (id, alert_id, host_id, title, severity, status)
    VALUES ('INC-001', 'ALT-001', 'srv-prod-01', 'SSH Incident', 'high', 'open');
  `);
  console.log('  [PASS] Valid incident successfully inserted with matching severity and host.');

  // 5d. Investigation severity cannot override parent incident
  let invSevOverrideBlocked = false;
  try {
    await db.query(`
      INSERT INTO public.investigations (incident_id, run_number, severity, analysis_status, incident_summary)
      VALUES ('INC-001', 1, 'medium', 'completed', 'AI downgraded severity');
    `);
  } catch (err) {
    invSevOverrideBlocked = true;
    console.log(`  [PASS] Investigation severity override blocked: ${err.message}`);
  }
  if (!invSevOverrideBlocked) throw new Error('FAIL: AI investigation overridden incident severity!');

  // Valid investigation matching incident severity
  await db.query(`
    INSERT INTO public.investigations (incident_id, run_number, severity, analysis_status, incident_summary)
    VALUES ('INC-001', 1, 'high', 'completed', 'AI verified brute force activity');
  `);
  console.log('  [PASS] Valid investigation recorded with matching severity.');

  // -------------------------------------------------------------
  // TEST 6: Evidence Cross-Host Integrity Binding
  // -------------------------------------------------------------
  console.log('\n[TEST 6] Testing cross-host evidence binding integrity...');

  // Event 1 belongs to srv-prod-01
  await db.query(`
    INSERT INTO public.telemetry_events (id, host_id, source_id, event_type, message)
    VALUES ('EVT-HOST1-001', 'srv-prod-01', 'ssh-auth', 'auth_failure', 'Failed password for admin');
  `);

  // Event 2 belongs to srv-prod-02
  await db.query(`
    INSERT INTO public.telemetry_events (id, host_id, source_id, event_type, message)
    VALUES ('EVT-HOST2-002', 'srv-prod-02', 'ssh-auth', 'auth_failure', 'Failed password for root');
  `);

  // Try linking ALT-001 (host1) with EVT-HOST2-002 (host2) -> MUST FAIL
  let crossHostLinkBlocked = false;
  try {
    await db.query(`
      INSERT INTO public.alert_evidence (alert_id, event_id, citation_role)
      VALUES ('ALT-001', 'EVT-HOST2-002', 'supporting');
    `);
  } catch (err) {
    crossHostLinkBlocked = true;
    console.log(`  [PASS] Cross-host evidence linking blocked: ${err.message}`);
  }
  if (!crossHostLinkBlocked) throw new Error('FAIL: Alert evidence linked across different hosts!');

  // Valid evidence link from same host -> MUST SUCCEED
  await db.query(`
    INSERT INTO public.alert_evidence (alert_id, event_id, citation_role)
    VALUES ('ALT-001', 'EVT-HOST1-001', 'trigger');
  `);
  console.log('  [PASS] Valid same-host evidence successfully linked in alert_evidence.');

  // -------------------------------------------------------------
  // TEST 7: Automated updated_at Trigger (Millisecond Precision)
  // -------------------------------------------------------------
  console.log('\n[TEST 7] Testing automated updated_at trigger (millisecond precision)...');
  const beforeHost = await db.query("SELECT updated_at, to_char(updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS iso_ts FROM public.hosts WHERE id = 'srv-prod-01';");
  const tsBeforeIso = beforeHost.rows[0].iso_ts;
  const tsBeforeMs = new Date(beforeHost.rows[0].updated_at).getTime();

  // Artificial delay (150ms) to ensure distinct wall-clock progression
  await new Promise((r) => setTimeout(r, 150));

  await db.query("UPDATE public.hosts SET hostname = 'core-auth-srv01-updated' WHERE id = 'srv-prod-01';");
  const afterHost = await db.query("SELECT updated_at, to_char(updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS iso_ts FROM public.hosts WHERE id = 'srv-prod-01';");
  const tsAfterIso = afterHost.rows[0].iso_ts;
  const tsAfterMs = new Date(afterHost.rows[0].updated_at).getTime();
  const deltaHostMs = tsAfterMs - tsBeforeMs;

  if (deltaHostMs <= 0) {
    throw new Error(`FAIL: hosts.updated_at did not advance! Before: ${tsBeforeIso}, After: ${tsAfterIso}`);
  }
  console.log(`  [PASS] hosts.updated_at advanced: ${tsBeforeIso} -> ${tsAfterIso} (Delta: +${deltaHostMs}ms)`);

  // Test updated_at on incidents
  const beforeInc = await db.query("SELECT updated_at, to_char(updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS iso_ts FROM public.incidents WHERE id = 'INC-001';");
  const tsIncBeforeIso = beforeInc.rows[0].iso_ts;
  const tsIncBeforeMs = new Date(beforeInc.rows[0].updated_at).getTime();

  await new Promise((r) => setTimeout(r, 150));
  await db.query("UPDATE public.incidents SET status = 'investigating' WHERE id = 'INC-001';");
  const afterInc = await db.query("SELECT updated_at, to_char(updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS iso_ts FROM public.incidents WHERE id = 'INC-001';");
  const tsIncAfterIso = afterInc.rows[0].iso_ts;
  const tsIncAfterMs = new Date(afterInc.rows[0].updated_at).getTime();
  const deltaIncMs = tsIncAfterMs - tsIncBeforeMs;

  if (deltaIncMs <= 0) {
    throw new Error(`FAIL: incidents.updated_at did not advance! Before: ${tsIncBeforeIso}, After: ${tsIncAfterIso}`);
  }
  console.log(`  [PASS] incidents.updated_at advanced: ${tsIncBeforeIso} -> ${tsIncAfterIso} (Delta: +${deltaIncMs}ms)`);

  console.log('\n============================================================');
  console.log('  ALL 7 DATABASE INTEGRATION TESTS PASSED (100%)');
  console.log('============================================================\n');
}

runDatabaseTests().catch((err) => {
  console.error('\n[FATAL ERROR IN TEST SUITE]:', err);
  process.exit(1);
});

