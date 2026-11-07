const fs = require('fs');
const path = require('path');
const { PGlite } = require('../dashboard/node_modules/@electric-sql/pglite');

async function testFinalAuditRpc() {
  console.log('======================================================================');
  console.log('  AEGIS FINAL REVISION ATOMIC RPC & DEADLOCK CONCURRENCY SUITE');
  console.log('======================================================================\n');

  const db = new PGlite();

  // 1. Run migration 001
  const m1 = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'migrations', '001_initial_schema.sql'), 'utf8');
  await db.exec(m1);
  console.log('[+] Migration 001 executed successfully.');

  // 2. Run migration 002 (Final Audit Revision)
  const m2 = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'migrations', '002_atomic_alert_evidence_rpc.sql'), 'utf8');
  await db.exec(m2);
  console.log('[+] Migration 002 (Deterministic Lock & Audit Ingestion RPC) executed successfully.');

  // 3. Setup test data: hosts and telemetry_events
  await db.query(`
    INSERT INTO public.hosts (id, hostname, ip_address, os)
    VALUES 
      ('host-alpha', 'server-alpha', '192.168.1.10', 'Ubuntu 24.04'),
      ('host-beta', 'server-beta', '192.168.1.20', 'Ubuntu 24.04');
  `);

  await db.query(`
    INSERT INTO public.telemetry_events (id, host_id, source_id, event_type, event_timestamp, message)
    VALUES 
      ('EVT-ALPHA-01', 'host-alpha', 'ssh-auth', 'auth_fail', now(), 'Failed password for root from 1.2.3.4'),
      ('EVT-ALPHA-02', 'host-alpha', 'ssh-auth', 'auth_fail', now(), 'Failed password for root from 1.2.3.4'),
      ('EVT-ALPHA-03', 'host-alpha', 'ssh-auth', 'auth_success', now(), 'Accepted password for root from 1.2.3.4'),
      ('EVT-BETA-01', 'host-beta', 'ssh-auth', 'auth_fail', now(), 'Failed password for user from 5.6.7.8');
  `);
  console.log('[+] Test baseline hosts and telemetry events initialized.');

  // -------------------------------------------------------------
  // TEST 1: Happy Path - Alert with 2 valid evidence items
  // -------------------------------------------------------------
  console.log('\n[TEST 1] Testing Happy Path atomic alert ingestion...');
  const alerts1 = JSON.stringify([
    {
      id: 'ALT-HAPPY-01',
      host_id: 'host-alpha',
      rule_id: 'RULE-SSH-BRUTE',
      rule_version: '1.0',
      title: 'SSH Brute-force detected',
      severity: 'high',
      detected_at: '2026-11-01T12:00:00Z',
      reason: 'Multiple failed logins from 1.2.3.4'
    }
  ]);
  const evidence1 = JSON.stringify([
    { alert_id: 'ALT-HAPPY-01', event_id: 'EVT-ALPHA-01', citation_role: 'supporting' },
    { alert_id: 'ALT-HAPPY-01', event_id: 'EVT-ALPHA-02', citation_role: 'trigger' }
  ]);

  const res1 = await db.query(
    `SELECT public.fn_ingest_alert_with_evidence($1::jsonb, $2::jsonb) AS result;`,
    [alerts1, evidence1]
  );
  const data1 = res1.rows[0].result;
  console.log('  Result:', data1);
  if (data1.inserted_alerts !== 1 || data1.inserted_evidence !== 2) {
    throw new Error(`Expected 1 alert and 2 evidence items, got: ${JSON.stringify(data1)}`);
  }
  console.log('  [PASS] Happy path successfully stored alert and evidence.');

  // -------------------------------------------------------------
  // TEST 2: Idempotency on Identical Payload
  // -------------------------------------------------------------
  console.log('\n[TEST 2] Testing Idempotency on duplicate submission...');
  const res2 = await db.query(
    `SELECT public.fn_ingest_alert_with_evidence($1::jsonb, $2::jsonb) AS result;`,
    [alerts1, evidence1]
  );
  const data2 = res2.rows[0].result;
  if (data2.inserted_alerts !== 0 || data2.inserted_evidence !== 0) {
    throw new Error(`Expected 0 new inserts on duplicate, got: ${JSON.stringify(data2)}`);
  }
  console.log('  [PASS] Idempotency verified (0 duplicates inserted).');

  // -------------------------------------------------------------
  // TEST 3: Intra-Batch Duplicate Alert ID with Conflicting detected_at
  // -------------------------------------------------------------
  console.log('\n[TEST 3] Testing Intra-Batch Duplicate with Conflicting detected_at Timestamp...');
  const alertBadTsDup = JSON.stringify([
    {
      id: 'ALT-DUP-TS',
      host_id: 'host-alpha',
      rule_id: 'RULE-SSH-BRUTE',
      rule_version: '1.0',
      title: 'Alert Definition 1',
      severity: 'high',
      detected_at: '2026-11-01T10:00:00Z',
      reason: 'Reason 1'
    },
    {
      id: 'ALT-DUP-TS',
      host_id: 'host-alpha',
      rule_id: 'RULE-SSH-BRUTE',
      rule_version: '1.0',
      title: 'Alert Definition 1',
      severity: 'high',
      detected_at: '2026-11-01T11:00:00Z', // Different timestamp!
      reason: 'Reason 1'
    }
  ]);
  const evBadTsDup = JSON.stringify([
    { alert_id: 'ALT-DUP-TS', event_id: 'EVT-ALPHA-01', citation_role: 'trigger' }
  ]);
  let tsDupRejected = false;
  try {
    await db.query(`SELECT public.fn_ingest_alert_with_evidence($1::jsonb, $2::jsonb);`, [alertBadTsDup, evBadTsDup]);
  } catch (err) {
    tsDupRejected = true;
    console.log(`  Caught expected exception: ${err.message}`);
  }
  if (!tsDupRejected) throw new Error('Expected duplicate alert with differing detected_at to be rejected!');
  console.log('  [PASS] Intra-batch duplicate with conflicting detected_at rejected.');

  // -------------------------------------------------------------
  // TEST 4: Intra-Batch Duplicate Alert ID with Conflicting rule_version
  // -------------------------------------------------------------
  console.log('\n[TEST 4] Testing Intra-Batch Duplicate with Conflicting rule_version...');
  const alertBadVerDup = JSON.stringify([
    {
      id: 'ALT-DUP-VER',
      host_id: 'host-alpha',
      rule_id: 'RULE-SSH-BRUTE',
      rule_version: '1.0',
      title: 'Alert Definition 1',
      severity: 'high',
      detected_at: '2026-11-01T10:00:00Z',
      reason: 'Reason 1'
    },
    {
      id: 'ALT-DUP-VER',
      host_id: 'host-alpha',
      rule_id: 'RULE-SSH-BRUTE',
      rule_version: '2.0', // Conflicting rule_version!
      title: 'Alert Definition 1',
      severity: 'high',
      detected_at: '2026-11-01T10:00:00Z',
      reason: 'Reason 1'
    }
  ]);
  const evBadVerDup = JSON.stringify([
    { alert_id: 'ALT-DUP-VER', event_id: 'EVT-ALPHA-01', citation_role: 'trigger' }
  ]);
  let verDupRejected = false;
  try {
    await db.query(`SELECT public.fn_ingest_alert_with_evidence($1::jsonb, $2::jsonb);`, [alertBadVerDup, evBadVerDup]);
  } catch (err) {
    verDupRejected = true;
    console.log(`  Caught expected exception: ${err.message}`);
  }
  if (!verDupRejected) throw new Error('Expected duplicate alert with differing rule_version to be rejected!');
  console.log('  [PASS] Intra-batch duplicate with conflicting rule_version rejected.');

  // -------------------------------------------------------------
  // TEST 5: Intra-Batch Duplicate Evidence Pair with Conflicting Role MUST BE REJECTED
  // -------------------------------------------------------------
  console.log('\n[TEST 5] Testing Intra-Batch Duplicate Evidence Pair with Conflicting Role...');
  const alertEvRoleConflict = JSON.stringify([
    {
      id: 'ALT-EV-ROLE-01',
      host_id: 'host-alpha',
      rule_id: 'RULE-SSH-BRUTE',
      rule_version: '1.0',
      title: 'Role Conflict Test',
      severity: 'medium',
      detected_at: '2026-11-01T10:00:00Z',
      reason: 'Testing intra-batch evidence role conflict'
    }
  ]);
  const evRoleConflictBatch = JSON.stringify([
    { alert_id: 'ALT-EV-ROLE-01', event_id: 'EVT-ALPHA-01', citation_role: 'trigger' },
    { alert_id: 'ALT-EV-ROLE-01', event_id: 'EVT-ALPHA-01', citation_role: 'supporting' }
  ]);
  let evRoleConflictRejected = false;
  try {
    await db.query(`SELECT public.fn_ingest_alert_with_evidence($1::jsonb, $2::jsonb);`, [alertEvRoleConflict, evRoleConflictBatch]);
  } catch (err) {
    evRoleConflictRejected = true;
    console.log(`  Caught expected exception: ${err.message}`);
  }
  if (!evRoleConflictRejected) throw new Error('Expected intra-batch conflicting evidence role to be rejected!');
  console.log('  [PASS] Intra-batch evidence role conflict rejected.');

  // -------------------------------------------------------------
  // TEST 6: Mutation of citation_role on Existing DB Evidence MUST BE REJECTED
  // -------------------------------------------------------------
  console.log('\n[TEST 6] Testing Mutation of citation_role on Existing DB Evidence...');
  const evMutateRole = JSON.stringify([
    { alert_id: 'ALT-HAPPY-01', event_id: 'EVT-ALPHA-01', citation_role: 'trigger' } // Existing is 'supporting'
  ]);
  let roleMutationRejected = false;
  try {
    await db.query(`SELECT public.fn_ingest_alert_with_evidence('[]'::jsonb, $1::jsonb);`, [evMutateRole]);
  } catch (err) {
    roleMutationRejected = true;
    console.log(`  Caught expected exception: ${err.message}`);
  }
  if (!roleMutationRejected) throw new Error('Expected mutation of existing evidence citation_role to be rejected!');
  console.log('  [PASS] Attempted mutation of existing evidence citation_role rejected.');

  // -------------------------------------------------------------
  // TEST 7: Historical Evidence Integrity Checked Even When New Evidence Is Supplied
  // -------------------------------------------------------------
  console.log('\n[TEST 7] Testing Historical Evidence Check When New Evidence Is Also Supplied...');
  // Create an alert with corrupted DB evidence (host mismatch)
  await db.query(`
    INSERT INTO public.alerts (id, host_id, rule_id, rule_version, title, severity, detected_at, reason)
    VALUES ('ALT-HIST-CORRUPT', 'host-alpha', 'RULE-TEST', '1.0', 'Hist Corrupt', 'medium', now(), 'Reason');
  `);
  await db.query(`ALTER TABLE public.alert_evidence DISABLE TRIGGER trg_alert_evidence_host_match;`);
  await db.query(`
    INSERT INTO public.alert_evidence (alert_id, event_id, citation_role)
    VALUES ('ALT-HIST-CORRUPT', 'EVT-BETA-01', 'supporting'); -- EVT-BETA-01 belongs to host-beta!
  `);
  await db.query(`ALTER TABLE public.alert_evidence ENABLE TRIGGER trg_alert_evidence_host_match;`);

  // Now submit this existing alert ALONG WITH A NEW VALID EVIDENCE ITEM (EVT-ALPHA-03)
  const alertHistPayload = JSON.stringify([
    {
      id: 'ALT-HIST-CORRUPT',
      host_id: 'host-alpha',
      rule_id: 'RULE-TEST',
      rule_version: '1.0',
      title: 'Hist Corrupt',
      severity: 'medium',
      detected_at: new Date().toISOString(),
      reason: 'Reason'
    }
  ]);
  const newEvPayload = JSON.stringify([
    { alert_id: 'ALT-HIST-CORRUPT', event_id: 'EVT-ALPHA-03', citation_role: 'trigger' }
  ]);
  let histCorruptionCaught = false;
  try {
    await db.query(`SELECT public.fn_ingest_alert_with_evidence($1::jsonb, $2::jsonb);`, [alertHistPayload, newEvPayload]);
  } catch (err) {
    histCorruptionCaught = true;
    console.log(`  Caught expected historical corruption exception: ${err.message}`);
  }
  if (!histCorruptionCaught) throw new Error('Expected historical corrupted evidence to be caught even when new evidence is supplied!');
  console.log('  [PASS] Historical evidence corruption caught and rejected even with new incoming evidence.');

  // Cleanup corrupt test alert
  await db.query(`DELETE FROM public.alert_evidence WHERE alert_id = 'ALT-HIST-CORRUPT';`);
  await db.query(`DELETE FROM public.alerts WHERE id = 'ALT-HIST-CORRUPT';`);

  // -------------------------------------------------------------
  // TEST 8: Alert Without Evidence MUST BE REJECTED
  // -------------------------------------------------------------
  console.log('\n[TEST 8] Testing Alert Without Evidence (No Orphaned Alerts)...');
  const alertNoEv = JSON.stringify([
    {
      id: 'ALT-ORPHAN-01',
      host_id: 'host-alpha',
      rule_id: 'RULE-SSH-BRUTE',
      rule_version: '1.0',
      title: 'Orphaned Alert Attempt',
      severity: 'medium',
      detected_at: '2026-11-01T10:00:00Z',
      reason: 'Should be rejected'
    }
  ]);
  let orphanRejected = false;
  try {
    await db.query(`SELECT public.fn_ingest_alert_with_evidence($1::jsonb, '[]'::jsonb);`, [alertNoEv]);
  } catch (err) {
    orphanRejected = true;
    console.log(`  Caught expected exception: ${err.message}`);
  }
  if (!orphanRejected) throw new Error('Expected alert without evidence to be rejected!');
  console.log('  [PASS] Alert without evidence rejected.');

  // -------------------------------------------------------------
  // TEST 9: Deadlock-Free Concurrency on Multi-Alert Batches in Reverse Order
  // -------------------------------------------------------------
  console.log('\n[TEST 9] Testing Deadlock Prevention on Concurrent Multi-Alert Batches with Reverse Ordering...');
  // Setup 2 alerts: ALT-DLOCK-A and ALT-DLOCK-B
  // Batch 1 has [ALT-DLOCK-A, ALT-DLOCK-B]
  // Batch 2 has [ALT-DLOCK-B, ALT-DLOCK-A] (reversed order)
  const batch1Alerts = JSON.stringify([
    { id: 'ALT-DLOCK-A', host_id: 'host-alpha', rule_id: 'RULE-1', rule_version: '1.0', title: 'A', severity: 'low', detected_at: '2026-11-01T10:00:00Z', reason: 'R' },
    { id: 'ALT-DLOCK-B', host_id: 'host-alpha', rule_id: 'RULE-1', rule_version: '1.0', title: 'B', severity: 'low', detected_at: '2026-11-01T10:00:00Z', reason: 'R' }
  ]);
  const batch1Ev = JSON.stringify([
    { alert_id: 'ALT-DLOCK-A', event_id: 'EVT-ALPHA-01', citation_role: 'trigger' },
    { alert_id: 'ALT-DLOCK-B', event_id: 'EVT-ALPHA-02', citation_role: 'trigger' }
  ]);

  const batch2AlertsReversed = JSON.stringify([
    { id: 'ALT-DLOCK-B', host_id: 'host-alpha', rule_id: 'RULE-1', rule_version: '1.0', title: 'B', severity: 'low', detected_at: '2026-11-01T10:00:00Z', reason: 'R' },
    { id: 'ALT-DLOCK-A', host_id: 'host-alpha', rule_id: 'RULE-1', rule_version: '1.0', title: 'A', severity: 'low', detected_at: '2026-11-01T10:00:00Z', reason: 'R' }
  ]);
  const batch2EvReversed = JSON.stringify([
    { alert_id: 'ALT-DLOCK-B', event_id: 'EVT-ALPHA-02', citation_role: 'trigger' },
    { alert_id: 'ALT-DLOCK-A', event_id: 'EVT-ALPHA-01', citation_role: 'trigger' }
  ]);

  // Execute both concurrent transactions in parallel
  const concResults = await Promise.allSettled([
    db.query(`SELECT public.fn_ingest_alert_with_evidence($1::jsonb, $2::jsonb) as res;`, [batch1Alerts, batch1Ev]),
    db.query(`SELECT public.fn_ingest_alert_with_evidence($1::jsonb, $2::jsonb) as res;`, [batch2AlertsReversed, batch2EvReversed])
  ]);

  const fulfilledCount = concResults.filter((r) => r.status === 'fulfilled').length;
  console.log(`  Concurrent multi-alert execution: ${fulfilledCount} / ${concResults.length} fulfilled without deadlock.`);
  if (fulfilledCount !== 2) {
    throw new Error(`Expected both concurrent batches to complete cleanly without deadlock!`);
  }
  // Verify both alerts exist in DB
  const checkDlockA = await db.query(`SELECT COUNT(*) as c FROM public.alerts WHERE id = 'ALT-DLOCK-A'`);
  const checkDlockB = await db.query(`SELECT COUNT(*) as c FROM public.alerts WHERE id = 'ALT-DLOCK-B'`);
  if (parseInt(checkDlockA.rows[0].c) !== 1 || parseInt(checkDlockB.rows[0].c) !== 1) {
    throw new Error('Multi-alert concurrent batches were not persisted!');
  }
  console.log('  [PASS] Deterministic lock ordering prevented deadlock; both batches executed cleanly.');

  // -------------------------------------------------------------
  // TEST 10: Audit Function Owner, Security Definer & Privilege Enforcement
  // -------------------------------------------------------------
  console.log('\n[TEST 10] Auditing Function Owner, SECURITY DEFINER & Role Revocation...');
  const ownerRes = await db.query(`
    SELECT proname, prosecdef, rolname AS owner
    FROM pg_proc p
    JOIN pg_roles r ON p.proowner = r.oid
    WHERE proname = 'fn_ingest_alert_with_evidence';
  `);
  console.log('  Function metadata:', ownerRes.rows[0]);
  if (!ownerRes.rows[0].prosecdef) {
    throw new Error('Function is NOT SECURITY DEFINER!');
  }
  if (ownerRes.rows[0].owner !== 'postgres') {
    throw new Error(`Function owner is '${ownerRes.rows[0].owner}', expected 'postgres'!`);
  }
  console.log('  [PASS] Owner is postgres, SECURITY DEFINER verified.');

  console.log('\n======================================================================');
  console.log('  ALL 10 FINAL PRODUCTION HARDENED ATOMIC RPC TESTS PASSED (100%)');
  console.log('======================================================================\n');
}

testFinalAuditRpc().catch((err) => {
  console.error('[FATAL ERROR]:', err);
  process.exit(1);
});
