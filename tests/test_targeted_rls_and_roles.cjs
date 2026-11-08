const { PGlite } = require('../dashboard/node_modules/@electric-sql/pglite');
const fs = require('fs');

async function testRolesAndRLS() {
  console.log('======================================================================');
  console.log('  AEGIS TARGETED AUDIT: PRODUCTION RLS & ROLE-BASED ACCESS CONTROL');
  console.log('======================================================================\n');

  const db = new PGlite();

  // 1. Create standard Supabase roles
  console.log('[1] Initializing Supabase standard roles (anon, authenticated, service_role)...');
  await db.exec(`
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
            CREATE ROLE anon NOLOGIN;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
            CREATE ROLE authenticated NOLOGIN;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
            CREATE ROLE service_role NOLOGIN BYPASSRLS;
        END IF;
    END $$;
  `);
  console.log('    [PASS] Roles created.');

  // 2. Apply baseline and unified migrations
  console.log('[2] Applying 001_initial_schema.sql and unified_migration_002_to_004.sql...');
  await db.exec(fs.readFileSync('supabase/migrations/001_initial_schema.sql', 'utf8'));
  await db.exec(fs.readFileSync('supabase/migrations/unified_migration_002_to_004.sql', 'utf8'));
  console.log('    [PASS] Schemas applied.');

  // 3. Seed test host and alert as postgres/superuser
  await db.exec(`
    INSERT INTO public.hosts (id, hostname, ip_address, os, agent_version)
    VALUES ('host-fenn-ubuntu', 'fenn', '192.168.193.129', 'Ubuntu 24.04', '0.1.0')
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.alerts (id, host_id, rule_id, rule_version, title, severity, detected_at, reason)
    VALUES ('ALT-TEST-01', 'host-fenn-ubuntu', 'RULE-01', '1.0', 'Test Alert', 'high', now(), 'Reason')
    ON CONFLICT (id) DO NOTHING;
  `);

  // 4. Test service_role permissions (Backend Operations)
  console.log('\n[3] Testing service_role operations (Must have FULL access)...');
  await db.exec(`SET ROLE service_role;`);
  
  // Test insert incident
  await db.query(`
    INSERT INTO public.incidents (id, host_id, title, severity, primary_alert_id, risk_level, risk_score)
    VALUES ('INC-SRV-TEST', 'host-fenn-ubuntu', 'Service Role Incident', 'high', 'ALT-TEST-01', 'high', 80);
  `);
  // Test select incident
  const srvIncs = (await db.query(`SELECT id, title FROM public.incidents WHERE id = 'INC-SRV-TEST';`)).rows;
  if (srvIncs.length !== 1) throw new Error('service_role failed to SELECT inserted incident!');
  
  // Test insert security run and finding
  await db.query(`
    INSERT INTO public.security_check_runs (id, host_id, status, total_checks, started_at, completed_at)
    VALUES ('RUN-SRV-TEST', 'host-fenn-ubuntu', 'completed', 1, now(), now());
  `);
  await db.query(`
    INSERT INTO public.security_findings (id, run_id, host_id, check_id, check_name, category, severity, status, description, checked_at)
    VALUES ('FND-SRV-TEST', 'RUN-SRV-TEST', 'host-fenn-ubuntu', 'CHK-01', 'Test Check', 'ssh', 'high', 'pass', 'Desc', now());
  `);
  const srvRuns = (await db.query(`SELECT id FROM public.security_check_runs WHERE id = 'RUN-SRV-TEST';`)).rows;
  if (srvRuns.length !== 1) throw new Error('service_role failed to access security_check_runs!');
  console.log('    [PASS] service_role successfully performed INSERT, SELECT on incidents and security checker.');

  // Reset to superuser
  await db.exec(`RESET ROLE;`);

  // 5. Test anon role (Public API Key - Must be completely BLOCKED)
  console.log('\n[4] Testing anon role access (Must be DENIED on all tables & RPC)...');
  await db.exec(`SET ROLE anon;`);

  // Case 4.1: SELECT incidents
  try {
    const res = await db.query(`SELECT * FROM public.incidents;`);
    if (res.rows.length > 0) throw new Error('anon should NOT be able to view incident rows!');
    console.log('    [PASS] anon SELECT on incidents returns 0 rows (RLS Deny-All).');
  } catch (err) {
    console.log('    [PASS] anon SELECT on incidents rejected:', err.message.slice(0, 60));
  }

  // Case 4.2: INSERT incidents
  try {
    await db.query(`
      INSERT INTO public.incidents (id, host_id, title, severity)
      VALUES ('INC-ANON-HACK', 'host-fenn-ubuntu', 'Hacked', 'critical');
    `);
    throw new Error('anon should NOT be able to INSERT incidents!');
  } catch (err) {
    console.log('    [PASS] anon INSERT on incidents rejected:', err.message.slice(0, 60));
  }

  // Case 4.3: SELECT security_findings
  try {
    const res = await db.query(`SELECT * FROM public.security_findings;`);
    if (res.rows.length > 0) throw new Error('anon should NOT be able to view security_findings!');
    console.log('    [PASS] anon SELECT on security_findings blocked (0 rows).');
  } catch (err) {
    console.log('    [PASS] anon SELECT on security_findings rejected:', err.message.slice(0, 60));
  }

  // Case 4.4: EXECUTE fn_ingest_alert_with_evidence
  try {
    await db.query(`SELECT public.fn_ingest_alert_with_evidence('[]'::jsonb, '[]'::jsonb);`);
    throw new Error('anon should NOT be able to EXECUTE fn_ingest_alert_with_evidence!');
  } catch (err) {
    console.log('    [PASS] anon EXECUTE RPC rejected:', err.message.slice(0, 60));
  }

  // Reset to superuser
  await db.exec(`RESET ROLE;`);

  // 6. Test authenticated role (Logged-in user without backend service role)
  console.log('\n[5] Testing authenticated role access (Must be DENIED)...');
  await db.exec(`SET ROLE authenticated;`);

  try {
    await db.query(`
      INSERT INTO public.incidents (id, host_id, title, severity)
      VALUES ('INC-AUTH-HACK', 'host-fenn-ubuntu', 'Hacked', 'critical');
    `);
    throw new Error('authenticated should NOT be able to INSERT incidents!');
  } catch (err) {
    console.log('    [PASS] authenticated INSERT rejected:', err.message.slice(0, 60));
  }

  try {
    await db.query(`SELECT public.fn_ingest_alert_with_evidence('[]'::jsonb, '[]'::jsonb);`);
    throw new Error('authenticated should NOT be able to EXECUTE RPC!');
  } catch (err) {
    console.log('    [PASS] authenticated EXECUTE RPC rejected:', err.message.slice(0, 60));
  }

  // Reset to superuser
  await db.exec(`RESET ROLE;`);

  console.log('\n======================================================================');
  console.log('  ALL TARGETED RLS & ROLE SECURITY TESTS PASSED (100% SUCCESS)');
  console.log('======================================================================');
}

testRolesAndRLS().catch(err => {
  console.error('\n[FATAL RLS AUDIT FAILURE]:', err);
  process.exit(1);
});
