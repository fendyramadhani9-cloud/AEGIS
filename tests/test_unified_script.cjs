const { PGlite } = require('../dashboard/node_modules/@electric-sql/pglite');
const fs = require('fs');

async function test() {
  const db = new PGlite();
  console.log('[1] Applying 001_initial_schema.sql...');
  await db.exec(fs.readFileSync('supabase/migrations/001_initial_schema.sql', 'utf8'));
  console.log('[2] Applying unified_migration_002_to_004.sql...');
  await db.exec(fs.readFileSync('supabase/migrations/unified_migration_002_to_004.sql', 'utf8'));
  console.log('[3] Verifying public schema tables...');
  const res = await db.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name;");
  console.log('Tables created:', res.rows.map(r => r.table_name).join(', '));
  console.log('SUCCESS: unified_migration_002_to_004.sql is 100% syntactically valid and executable!');
}
test().catch(e => { console.error('FAILED:', e); process.exit(1); });
