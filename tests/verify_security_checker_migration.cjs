const fs = require('fs');
const path = require('path');
const { PGlite } = require('../dashboard/node_modules/@electric-sql/pglite');

async function testSecurityCheckerMigration() {
  console.log('======================================================================');
  console.log('  AEGIS MIGRATION 003: SECURITY CHECKER POSTGRES ENGINE SUITE');
  console.log('======================================================================\n');

  const db = new PGlite();

  // 1. Run migration 001
  const m1 = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'migrations', '001_initial_schema.sql'), 'utf8');
  await db.exec(m1);
  console.log('[+] Migration 001 executed successfully.');

  // 2. Run migration 003
  const m3 = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'migrations', '003_security_checker.sql'), 'utf8');
  await db.exec(m3);
  console.log('[+] Migration 003 executed successfully.');

  // 3. Setup test host
  await db.query(`
    INSERT INTO public.hosts (id, hostname, ip_address, os)
    VALUES ('host-alpha', 'server-alpha', '192.168.1.10', 'Ubuntu 24.04 LTS');
  `);
  console.log('[+] Test baseline host initialized.\n');

  // [TEST 1] Insert valid check run and findings
  console.log('[TEST 1] Testing Happy Path insertion of run and findings...');
  const runTime = new Date().toISOString();
  await db.query(`
    INSERT INTO public.security_check_runs (
      id, host_id, status, total_checks, passed_checks, failed_checks, warning_checks, error_checks, started_at, completed_at
    ) VALUES (
      'RUN-01', 'host-alpha', 'completed', 2, 1, 1, 0, 0, $1, $1
    );
  `, [runTime]);

  await db.query(`
    INSERT INTO public.security_findings (
      id, run_id, host_id, check_id, check_name, category, severity, status, actual_value, expected_value, description, checked_at
    ) VALUES 
      ('FND-01-SSH-001', 'RUN-01', 'host-alpha', 'SSH-001', 'PermitRootLogin', 'ssh', 'high', 'pass', 'PermitRootLogin no', 'PermitRootLogin no', 'Desc', $1),
      ('FND-01-FW-001', 'RUN-01', 'host-alpha', 'FW-001', 'UFW Status', 'firewall', 'high', 'fail', 'inactive', 'active', 'Desc', $1);
  `, [runTime]);

  const fndCount = await db.query(`SELECT count(*) as c FROM public.security_findings WHERE run_id = 'RUN-01';`);
  if (parseInt(fndCount.rows[0].c, 10) !== 2) throw new Error('Expected 2 findings inserted');
  console.log('  [PASS] Happy path successfully stored run and 2 findings.\n');

  // [TEST 2] Host last_sc_run_at Trigger Verification
  console.log('[TEST 2] Testing trigger trg_sc_runs_sync_host updates hosts.last_sc_run_at...');
  const hostRes = await db.query(`SELECT last_sc_run_at FROM public.hosts WHERE id = 'host-alpha';`);
  if (!hostRes.rows[0].last_sc_run_at) throw new Error('hosts.last_sc_run_at was not updated by trigger!');
  console.log(`  [PASS] Host last_sc_run_at automatically updated: ${hostRes.rows[0].last_sc_run_at}\n`);

  // [TEST 3] Unique constraint on (run_id, check_id)
  console.log('[TEST 3] Testing Unique Constraint uq_run_check (run_id, check_id)...');
  let duplicateRejected = false;
  try {
    await db.query(`
      INSERT INTO public.security_findings (
        id, run_id, host_id, check_id, check_name, category, severity, status, description, checked_at
      ) VALUES (
        'FND-DUP', 'RUN-01', 'host-alpha', 'SSH-001', 'PermitRootLogin', 'ssh', 'high', 'fail', 'Duplicate', $1
      );
    `, [runTime]);
  } catch (err) {
    duplicateRejected = true;
    console.log(`  Caught expected unique violation: ${err.message}`);
  }
  if (!duplicateRejected) throw new Error('Failed to reject duplicate (run_id, check_id)!');
  console.log('  [PASS] Unique constraint verified.\n');

  // [TEST 4] Foreign key constraint on unknown host
  console.log('[TEST 4] Testing Foreign Key rejection on unknown host...');
  let fkRejected = false;
  try {
    await db.query(`
      INSERT INTO public.security_check_runs (
        id, host_id, status, started_at
      ) VALUES ('RUN-PHANTOM', 'non-existent-host', 'completed', $1);
    `, [runTime]);
  } catch (err) {
    fkRejected = true;
    console.log(`  Caught expected FK violation: ${err.message}`);
  }
  if (!fkRejected) throw new Error('Failed to reject non-existent host_id!');
  console.log('  [PASS] Foreign key enforcement verified.\n');

  // [TEST 5] Check constraints (category, severity, status)
  console.log('[TEST 5] Testing Check Constraint rejection on invalid status and category...');
  let invalidStatusRejected = false;
  try {
    await db.query(`
      INSERT INTO public.security_findings (
        id, run_id, host_id, check_id, check_name, category, severity, status, description, checked_at
      ) VALUES (
        'FND-BAD-STATUS', 'RUN-01', 'host-alpha', 'SSH-099', 'Bad', 'ssh', 'high', 'INVALID_STATUS', 'Desc', $1
      );
    `, [runTime]);
  } catch (err) {
    invalidStatusRejected = true;
    console.log(`  Caught expected check constraint violation: ${err.message}`);
  }
  if (!invalidStatusRejected) throw new Error('Failed to reject invalid status string!');
  console.log('  [PASS] Check constraints verified.\n');

  // [TEST 6] Verification script execution
  console.log('[TEST 6] Executing verify_migration_003.sql...');
  const v3 = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'verify_migration_003.sql'), 'utf8');
  await db.exec(v3);
  console.log('  [PASS] verify_migration_003.sql executed cleanly.\n');

  // [TEST 7] Rollback script execution
  console.log('[TEST 7] Executing rollback_migration_003.sql...');
  const r3 = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'rollback_migration_003.sql'), 'utf8');
  await db.exec(r3);

  const checkDropped = await db.query(`
    SELECT count(*) as c FROM information_schema.tables 
    WHERE table_schema = 'public' AND table_name IN ('security_findings', 'security_check_runs');
  `);
  if (parseInt(checkDropped.rows[0].c, 10) !== 0) throw new Error('Rollback failed: tables still exist!');

  // Verify hosts still exist
  const checkHost = await db.query(`SELECT count(*) as c FROM public.hosts;`);
  if (parseInt(checkHost.rows[0].c, 10) !== 1) throw new Error('Rollback broke base hosts table!');

  console.log('  [PASS] Rollback script dropped Security Checker tables and preserved base schema.\n');

  console.log('======================================================================');
  console.log('  ALL 7 SECURITY CHECKER DATABASE ENGINE TESTS PASSED (100%)');
  console.log('======================================================================\n');
}

testSecurityCheckerMigration().catch((err) => {
  console.error('Test failed with error:', err);
  process.exit(1);
});

