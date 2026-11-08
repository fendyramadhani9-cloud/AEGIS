const fs = require('fs');
const path = require('path');
const { PGlite } = require('../dashboard/node_modules/@electric-sql/pglite');

async function testIncidentMigration() {
  console.log('======================================================================');
  console.log('  AEGIS MIGRATION 004: INCIDENT & AI INVESTIGATION POSTGRES SUITE');
  console.log('======================================================================\n');

  const db = new PGlite();

  // 1. Run migration 001
  const m1 = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'migrations', '001_initial_schema.sql'), 'utf8');
  await db.exec(m1);
  console.log('[+] Migration 001 executed successfully.');

  // 2. Run migration 004
  const m4 = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'migrations', '004_incident_investigation.sql'), 'utf8');
  await db.exec(m4);
  console.log('[+] Migration 004 executed successfully.');

  // 3. Setup test host and alerts
  await db.query(`
    INSERT INTO public.hosts (id, hostname, ip_address, os)
    VALUES ('host-alpha', 'server-alpha', '192.168.1.10', 'Ubuntu 24.04 LTS');
  `);
  await db.query(`
    INSERT INTO public.alerts (id, host_id, rule_id, rule_version, title, severity, detected_at, reason)
    VALUES 
      ('ALT-001', 'host-alpha', 'RULE-SSH-BRUTE', '1.0', 'Brute Force', 'high', now(), 'Repeated failures'),
      ('ALT-002', 'host-alpha', 'RULE-AUTH-003', '1.0', 'Login Success', 'high', now(), 'Success after fail');
  `);
  console.log('[+] Baseline host and 2 alerts initialized.\n');

  // [TEST 1] Happy path: Create incident, link alerts, timeline, AI analysis
  console.log('[TEST 1] Testing Happy Path insertion of incident, junction alerts, and analysis...');
  await db.query(`
    INSERT INTO public.incidents (
      id, host_id, alert_id, title, severity, risk_level, risk_score, status, primary_alert_id, alert_count, source_ip, target_user, attack_scenario
    ) VALUES (
      'INC-01', 'host-alpha', 'ALT-001', 'Multi-Stage SSH Attack', 'high', 'critical', 85, 'new', 'ALT-001', 2, '192.168.1.50', 'admin', 'Brute-force to login'
    );
  `);
  await db.query(`
    INSERT INTO public.incident_alerts (incident_id, alert_id)
    VALUES ('INC-01', 'ALT-001'), ('INC-01', 'ALT-002');
  `);
  await db.query(`
    INSERT INTO public.incident_timeline (
      incident_id, timestamp, kind, title, description, severity
    ) VALUES (
      'INC-01', now(), 'alert', 'Brute Force Alert', 'Triggered by SSH-BRUTE rule', 'high'
    );
  `);
  await db.query(`
    INSERT INTO public.ai_analyses (
      id, incident_id, host_id, analysis_status, threat_classification, executive_summary, attack_scenario,
      risk_level, risk_score, confidence_level, confidence_reason, supporting_evidence, impact_assessment, provider, model
    ) VALUES (
      'ANL-01', 'INC-01', 'host-alpha', 'completed', 'Credential Stuffing', 'Executive summary text', 'Attack narrative',
      'high', 85, 'high', 'Grounded in logs', ARRAY['EVT-01'], 'Impact text', 'gemini', 'gemini-3.5-flash-lite'
    );
  `);
  await db.query(`
    INSERT INTO public.incident_status_history (
      incident_id, old_status, new_status, note, operator
    ) VALUES (
      'INC-01', 'new', 'investigating', 'Initial triage started', 'sec-ops'
    );
  `);

  const inc = await db.query(`SELECT * FROM public.incidents WHERE id = 'INC-01';`);
  if (inc.rows.length !== 1) throw new Error('Incident not found');
  if (inc.rows[0].risk_score !== 85) throw new Error('Incorrect risk score');
  console.log('  [PASS] Incident, alerts, timeline, AI analysis, and status history stored.\n');

  // [TEST 2] Constraint test: Invalid status rejected
  console.log('[TEST 2] Testing check constraint on invalid status...');
  let constraintCaught = false;
  try {
    await db.query(`
      INSERT INTO public.incidents (id, host_id, alert_id, title, severity, status)
      VALUES ('INC-BAD-01', 'host-alpha', 'ALT-001', 'Title', 'high', 'invalid_status_xyz');
    `);
  } catch (e) {
    constraintCaught = true;
  }
  if (!constraintCaught) throw new Error('Expected constraint failure on invalid status');
  console.log('  [PASS] Invalid status rejected by check constraint.\n');

  // [TEST 3] Constraint test: Foreign key rejection on non-existent host
  console.log('[TEST 3] Testing foreign key rejection on unknown host...');
  let fkCaught = false;
  try {
    await db.query(`
      INSERT INTO public.incidents (id, host_id, alert_id, title, severity, status)
      VALUES ('INC-BAD-02', 'host-ghost', 'ALT-001', 'Title', 'high', 'new');
    `);
  } catch (e) {
    fkCaught = true;
  }
  if (!fkCaught) throw new Error('Expected foreign key violation on unknown host');
  console.log('  [PASS] Unknown host correctly rejected.\n');

  // [TEST 4] Verification script execution
  console.log('[TEST 4] Testing verify_migration_004.sql...');
  const v4 = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'verify_migration_004.sql'), 'utf8');
  await db.exec(v4);
  console.log('  [PASS] verify_migration_004.sql passed without exception.\n');

  // [TEST 5] Safe Rollback verification
  console.log('[TEST 5] Testing rollback_migration_004.sql...');
  const rb4 = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'rollback_migration_004.sql'), 'utf8');
  await db.exec(rb4);

  // Verify baseline tables remain intact
  const hosts = await db.query(`SELECT count(*) as c FROM public.hosts;`);
  const alerts = await db.query(`SELECT count(*) as c FROM public.alerts;`);
  if (parseInt(hosts.rows[0].c, 10) !== 1) throw new Error('Host lost during rollback');
  if (parseInt(alerts.rows[0].c, 10) !== 2) throw new Error('Alerts lost during rollback');

  // Verify 004 tables are dropped
  const checkTables = (await db.query(`
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name IN ('incident_risk_factors', 'incident_alerts', 'incident_timeline', 'ai_analyses', 'incident_status_history');
  `)).rows;
  if (checkTables.length !== 0) throw new Error(`Rollback failed to drop 004 tables: ${JSON.stringify(checkTables)}`);

  // Verify columns on incidents were reverted (primary_alert_id should be gone)
  const checkCols = (await db.query(`
    SELECT column_name FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'incidents' AND column_name IN ('primary_alert_id', 'risk_score');
  `)).rows;
  if (checkCols.length !== 0) throw new Error(`Rollback failed to revert columns on incidents: ${JSON.stringify(checkCols)}`);

  console.log('  [PASS] Rollback cleanly dropped new tables while preserving hosts and alerts.\n');

  console.log('======================================================================');
  console.log('  ALL 5 MIGRATION 004 TESTS PASSED (100% SUCCESS)');
  console.log('======================================================================');
}

testIncidentMigration().catch((err) => {
  console.error('\n[FATAL ERROR]:', err);
  process.exit(1);
});
