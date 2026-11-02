/**
 * SAMPLE DATA — for UI development and design review only.
 *
 * Every record here is fabricated and is shown in the UI behind a
 * persistent "Sample data" label. IP addresses use the RFC 5737
 * documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
 * and private 10.0.0.0/8. No secrets, passwords, tokens or keys appear.
 *
 * Timestamps are generated relative to page load so relative times
 * ("2 min ago") stay meaningful.
 */
import type {
  Alert,
  EvidenceSession,
  Finding,
  Host,
  NormalizedEvent,
  Report,
  SystemStatus,
  TelemetryGap,
} from './types';

const NOW = Date.now();
const MIN = 60_000;
const at = (minutesFromNow: number) => new Date(NOW + minutesFromNow * MIN).toISOString();
const ago = (minutes: number) => at(-minutes);

const startOfDay = (offsetDays: number) => {
  const d = new Date(NOW);
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() + offsetDays);
  return d;
};
const dayIso = (offsetDays: number) => startOfDay(offsetDays).toISOString();

/** Incident anchor on web-01: ~5.5 hours ago. */
const T0 = 330;
const t = (plusMinutes: number) => ago(T0 - plusMinutes);

export const sampleHosts: Host[] = [
  {
    id: 'h-web01',
    hostname: 'web-01',
    os: 'Ubuntu 22.04 LTS',
    agentVersion: '0.3.1',
    agentStatus: 'online',
    lastDataAt: ago(1),
    lastScRunAt: ago(185),
    sources: [
      { id: 'ssh-auth', path: '/var/log/auth.log', status: 'collecting', lastEventAt: ago(2) },
      { id: 'nginx-access', path: '/var/log/nginx/access.log', status: 'collecting', lastEventAt: ago(1) },
      { id: 'nginx-error', path: '/var/log/nginx/error.log', status: 'collecting', lastEventAt: ago(42) },
    ],
  },
  {
    id: 'h-api02',
    hostname: 'api-02',
    os: 'Ubuntu 24.04 LTS',
    agentVersion: '0.3.1',
    agentStatus: 'online',
    lastDataAt: ago(2),
    lastScRunAt: ago(190),
    sources: [
      { id: 'ssh-auth', path: '/var/log/auth.log', status: 'collecting', lastEventAt: ago(2) },
      {
        id: 'nginx-access',
        path: '/var/log/nginx/access.log',
        status: 'gap',
        lastEventAt: ago(51),
        detail: 'Permission denied reading file since last log rotation',
      },
      {
        id: 'nginx-error',
        path: '/var/log/nginx/error.log',
        status: 'error',
        lastEventAt: ago(51),
        detail: 'Permission denied reading file since last log rotation',
      },
    ],
  },
  {
    id: 'h-db01',
    hostname: 'db-01',
    os: 'Ubuntu 22.04 LTS',
    agentVersion: '0.3.0',
    agentStatus: 'delayed',
    lastDataAt: ago(18),
    lastScRunAt: ago(200),
    sources: [
      { id: 'ssh-auth', path: '/var/log/auth.log', status: 'collecting', lastEventAt: ago(19) },
      { id: 'nginx-access', path: '—', status: 'not_configured', lastEventAt: null, detail: 'Nginx is not configured as a source on this host' },
      { id: 'nginx-error', path: '—', status: 'not_configured', lastEventAt: null, detail: 'Nginx is not configured as a source on this host' },
    ],
  },
  {
    id: 'h-stg03',
    hostname: 'staging-03',
    os: 'Ubuntu 24.04 LTS',
    agentVersion: '0.2.4',
    agentStatus: 'offline',
    lastDataAt: ago(362),
    lastScRunAt: ago(430),
    sources: [
      { id: 'ssh-auth', path: '/var/log/auth.log', status: 'gap', lastEventAt: ago(365), detail: 'No data since agent stopped reporting' },
      { id: 'nginx-access', path: '/var/log/nginx/access.log', status: 'gap', lastEventAt: ago(363), detail: 'No data since agent stopped reporting' },
      { id: 'nginx-error', path: '/var/log/nginx/error.log', status: 'gap', lastEventAt: ago(900), detail: 'No data since agent stopped reporting' },
    ],
  },
  {
    id: 'h-bld04',
    hostname: 'build-04',
    os: 'Ubuntu 24.04 LTS',
    agentVersion: '0.3.1',
    agentStatus: 'unknown',
    lastDataAt: null,
    lastScRunAt: null,
    sources: [
      { id: 'ssh-auth', path: '/var/log/auth.log', status: 'gap', lastEventAt: null, detail: 'Registered, but no data has been received yet' },
    ],
  },
];

export const sampleGaps: TelemetryGap[] = [
  {
    id: 'g-001',
    hostId: 'h-web01',
    source: 'ssh-auth',
    start: t(5),
    end: t(21),
    reason:
      'Log rotation: the agent lost its file position and resumed on the new file. Lines written in this window were not read.',
  },
  {
    id: 'g-002',
    hostId: 'h-api02',
    source: 'nginx-access',
    start: ago(51),
    end: null,
    reason: 'Permission denied reading /var/log/nginx/access.log after rotation. Ongoing.',
  },
  {
    id: 'g-003',
    hostId: 'h-stg03',
    source: 'agent',
    start: ago(362),
    end: null,
    reason: 'No heartbeat or events from the agent. All sources on this host are unmonitored.',
  },
  {
    id: 'g-004',
    hostId: 'h-db01',
    source: 'ssh-auth',
    start: ago(1500),
    end: ago(1462),
    reason: 'Agent restarted after package upgrade; reading resumed from the current end of file.',
  },
];

export const sampleEvents: NormalizedEvent[] = [
  { id: 'e101', ts: t(0), hostId: 'h-web01', source: 'ssh-auth', type: 'auth.failed', message: 'Failed password for invalid user admin from 203.0.113.45 port 51122 ssh2', fields: { user: 'admin', src_ip: '203.0.113.45', method: 'password' } },
  { id: 'e102', ts: t(1), hostId: 'h-web01', source: 'ssh-auth', type: 'auth.failed', message: 'Failed password for root from 203.0.113.45 port 51388 ssh2', fields: { user: 'root', src_ip: '203.0.113.45', method: 'password' } },
  { id: 'e103', ts: t(2), hostId: 'h-web01', source: 'ssh-auth', type: 'auth.failed', message: 'Failed password for ubuntu from 203.0.113.45 port 51790 ssh2', fields: { user: 'ubuntu', src_ip: '203.0.113.45', method: 'password' } },
  { id: 'e104', ts: t(3.5), hostId: 'h-web01', source: 'ssh-auth', type: 'auth.failed', message: 'Failed password for ubuntu from 203.0.113.45 port 52011 ssh2 (38th failure in window)', fields: { user: 'ubuntu', src_ip: '203.0.113.45', method: 'password', count_in_window: '38' } },
  { id: 'e105', ts: t(22), hostId: 'h-web01', source: 'ssh-auth', type: 'auth.accepted', message: 'Accepted password for ubuntu from 203.0.113.45 port 52310 ssh2', fields: { user: 'ubuntu', src_ip: '203.0.113.45', method: 'password' } },
  { id: 'e106', ts: t(22.2), hostId: 'h-web01', source: 'ssh-auth', type: 'session.opened', message: 'pam_unix(sshd:session): session opened for user ubuntu(uid=1000)', fields: { user: 'ubuntu' } },
  { id: 'e107', ts: t(40), hostId: 'h-web01', source: 'nginx-access', type: 'http.request', message: 'GET /.env → 404 · client 198.51.100.23', fields: { client: '198.51.100.23', status: '404', path: '/.env' } },
  { id: 'e108', ts: t(40.5), hostId: 'h-web01', source: 'nginx-access', type: 'http.request', message: 'GET /wp-login.php → 404 · client 198.51.100.23', fields: { client: '198.51.100.23', status: '404', path: '/wp-login.php' } },
  { id: 'e109', ts: t(41), hostId: 'h-web01', source: 'nginx-access', type: 'http.request', message: 'GET /phpmyadmin/ → 404 · client 198.51.100.23 (64th 404 in window)', fields: { client: '198.51.100.23', status: '404', count_in_window: '64' } },
  { id: 'e110', ts: ago(2), hostId: 'h-web01', source: 'ssh-auth', type: 'auth.accepted', message: 'Accepted publickey for deploy from 10.0.4.12 port 40122 ssh2', fields: { user: 'deploy', src_ip: '10.0.4.12', method: 'publickey' } },
  { id: 'e201', ts: ago(1310), hostId: 'h-db01', source: 'ssh-auth', type: 'auth.failed', message: 'Failed password for postgres from 192.0.2.88 port 60211 ssh2', fields: { user: 'postgres', src_ip: '192.0.2.88' } },
  { id: 'e202', ts: ago(1306), hostId: 'h-db01', source: 'ssh-auth', type: 'auth.failed', message: 'Failed password for postgres from 192.0.2.88 port 60470 ssh2 (12th failure in window)', fields: { user: 'postgres', src_ip: '192.0.2.88', count_in_window: '12' } },
  { id: 'e301', ts: ago(3), hostId: 'h-api02', source: 'ssh-auth', type: 'auth.accepted', message: 'Accepted publickey for deploy from 10.0.4.12 port 41877 ssh2', fields: { user: 'deploy', src_ip: '10.0.4.12' } },
];

export const sampleAlerts: Alert[] = [
  {
    kind: 'alert',
    id: 'a-1042',
    ruleId: 'RM-SSH-002',
    ruleVersion: '1.0',
    title: 'Successful SSH login after repeated failures',
    severity: 'critical',
    hostId: 'h-web01',
    source: 'ssh-auth',
    detectedAt: t(22),
    reason:
      'A password login for "ubuntu" from 203.0.113.45 succeeded within 30 minutes after rule RM-SSH-001 matched for the same source address.',
    supportingEventIds: ['e104', 'e105', 'e106'],
    ai: { state: 'not_requested', role: 'RM Analysis Agent' },
  },
  {
    kind: 'alert',
    id: 'a-1041',
    ruleId: 'RM-SSH-001',
    ruleVersion: '1.2',
    title: 'Repeated failed SSH logins from one source',
    severity: 'high',
    hostId: 'h-web01',
    source: 'ssh-auth',
    detectedAt: t(4),
    reason:
      '38 failed SSH authentication attempts from 203.0.113.45 within 5 minutes. Rule threshold: 10 failures in 5 minutes from one address.',
    supportingEventIds: ['e101', 'e102', 'e103', 'e104'],
    ai: {
      state: 'ready',
      role: 'RM Analysis Agent',
      generatedAt: t(30),
      summary:
        'One external address produced 38 failed password attempts in about four minutes against the usernames admin, root and ubuntu. This pattern is consistent with automated password guessing. The rule matched on count and time window only; it does not determine whether any attempt succeeded.',
      evidenceRefs: ['Events e101–e104 (ssh-auth)', 'Rule RM-SSH-001 v1.2', 'Telemetry gap g-001'],
      uncertainty:
        'The SSH auth log was not collected for 16 minutes shortly after this alert (log rotation gap). Activity from this address during that window is unknown and is not shown.',
      nextSteps: [
        'Review alert RM-SSH-002 for the same source address.',
        'Confirm whether the "ubuntu" account is expected to accept password logins (see finding SC-SSH-002).',
        'If the investigation continues, consider starting Emergency Evidence Mode for web-01.',
      ],
    },
  },
  {
    kind: 'alert',
    id: 'a-1043',
    ruleId: 'RM-NGX-001',
    ruleVersion: '1.0',
    title: 'High rate of 404 responses from one client',
    severity: 'medium',
    hostId: 'h-web01',
    source: 'nginx-access',
    detectedAt: t(41),
    reason:
      '64 requests returning 404 from 198.51.100.23 within 2 minutes, including paths such as /.env and /wp-login.php. Rule threshold: 30 in 2 minutes.',
    supportingEventIds: ['e107', 'e108', 'e109'],
    ai: { state: 'not_requested', role: 'RM Analysis Agent' },
  },
  {
    kind: 'alert',
    id: 'a-1031',
    ruleId: 'RM-SSH-001',
    ruleVersion: '1.2',
    title: 'Repeated failed SSH logins from one source',
    severity: 'medium',
    hostId: 'h-db01',
    source: 'ssh-auth',
    detectedAt: ago(1306),
    reason:
      '12 failed SSH authentication attempts for "postgres" from 192.0.2.88 within 5 minutes. Rule threshold: 10 failures in 5 minutes.',
    supportingEventIds: ['e201', 'e202'],
    ai: {
      state: 'ready',
      role: 'RM Analysis Agent',
      generatedAt: ago(1290),
      summary:
        'A single address attempted password logins for the "postgres" account 12 times. No successful login from this address appears in the collected ssh-auth events.',
      evidenceRefs: ['Events e201–e202 (ssh-auth)', 'Rule RM-SSH-001 v1.2'],
      uncertainty:
        '"No successful login" only covers collected events. A separate ssh-auth gap on this host occurred earlier that day (g-004).',
      nextSteps: ['Check whether the postgres account should allow SSH logins at all.'],
    },
  },
];

export const sampleFindings: Finding[] = [
  {
    kind: 'finding',
    id: 'f-201',
    checkId: 'SC-SSH-001',
    title: 'Root login over SSH is permitted',
    status: 'fail',
    severity: 'high',
    hostId: 'h-web01',
    checkedAt: ago(185),
    indicators: ['sshd -T: permitrootlogin yes', 'Source: /etc/ssh/sshd_config line 34'],
    limits:
      'Reads the effective sshd configuration only. Does not check whether root has a usable password or authorized keys.',
    ai: {
      state: 'ready',
      role: 'SC Analysis Agent',
      generatedAt: ago(170),
      summary:
        'SSH is configured to accept logins as root. If a root credential is guessed or leaked, an attacker would gain full control directly, without needing a second privilege-escalation step.',
      evidenceRefs: ['Check SC-SSH-001 indicators', 'Alert RM-SSH-001 on the same host (password guessing observed)'],
      uncertainty: 'The check cannot see whether root actually has a password or keys configured.',
      nextSteps: [
        'Confirm whether any workflow requires direct root SSH access.',
        'Review the effective setting with `sshd -T | grep permitrootlogin` on the host.',
      ],
    },
  },
  {
    kind: 'finding',
    id: 'f-202',
    checkId: 'SC-SSH-002',
    title: 'Password authentication is enabled for SSH',
    status: 'fail',
    severity: 'medium',
    hostId: 'h-web01',
    checkedAt: ago(185),
    indicators: ['sshd -T: passwordauthentication yes'],
    limits: 'Reads the effective sshd configuration only. Per-user Match blocks are reported but not evaluated per account.',
    ai: {
      state: 'failed',
      role: 'SC Analysis Agent',
      error: 'AI provider timed out after 30 s. The finding and its evidence are unaffected.',
    },
  },
  {
    kind: 'finding',
    id: 'f-203',
    checkId: 'SC-NET-001',
    title: 'Service listening on all interfaces: port 6379',
    status: 'fail',
    severity: 'medium',
    hostId: 'h-web01',
    checkedAt: ago(185),
    indicators: ['0.0.0.0:6379 LISTEN · redis-server (pid 812)'],
    limits: 'Lists listening sockets only. Does not check firewall rules or whether the port is reachable from the internet.',
    ai: { state: 'not_requested', role: 'SC Analysis Agent' },
  },
  {
    kind: 'finding',
    id: 'f-204',
    checkId: 'SC-PKG-001',
    title: 'Package update status',
    status: 'not_checked',
    severity: 'info',
    hostId: 'h-web01',
    checkedAt: ago(185),
    indicators: [],
    limits:
      'APT metadata could not be read by the agent (insufficient permission). Result is unknown — this does not mean the host is up to date.',
    ai: { state: 'not_requested', role: 'SC Analysis Agent' },
  },
  {
    kind: 'finding',
    id: 'f-205',
    checkId: 'SC-FS-001',
    title: '/etc/shadow permissions',
    status: 'pass',
    severity: 'info',
    hostId: 'h-web01',
    checkedAt: ago(185),
    indicators: ['mode 0640 · owner root:shadow'],
    limits: 'Checks mode and ownership of the file only.',
    ai: { state: 'not_requested', role: 'SC Analysis Agent' },
  },
  {
    kind: 'finding',
    id: 'f-211',
    checkId: 'SC-SSH-001',
    title: 'Root login over SSH is permitted',
    status: 'pass',
    severity: 'info',
    hostId: 'h-api02',
    checkedAt: ago(190),
    indicators: ['sshd -T: permitrootlogin no'],
    limits: 'Reads the effective sshd configuration only.',
    ai: { state: 'not_requested', role: 'SC Analysis Agent' },
  },
  {
    kind: 'finding',
    id: 'f-221',
    checkId: 'SC-NET-001',
    title: 'Service listening on all interfaces: port 5432',
    status: 'fail',
    severity: 'medium',
    hostId: 'h-db01',
    checkedAt: ago(200),
    indicators: ['0.0.0.0:5432 LISTEN · postgres (pid 1022)'],
    limits: 'Lists listening sockets only. Does not check firewall rules or pg_hba.conf.',
    ai: { state: 'not_requested', role: 'SC Analysis Agent' },
  },
  {
    kind: 'finding',
    id: 'f-231',
    checkId: 'SC-SSH-002',
    title: 'Password authentication is enabled for SSH',
    status: 'fail',
    severity: 'medium',
    hostId: 'h-stg03',
    checkedAt: ago(430),
    indicators: ['sshd -T: passwordauthentication yes'],
    limits: 'Result is from the last successful check, before the agent went offline.',
    ai: { state: 'not_requested', role: 'SC Analysis Agent' },
  },
];

export const sampleEvidence: EvidenceSession[] = [
  {
    id: 'ev-07',
    hostId: 'h-web01',
    status: 'active',
    startedAt: ago(25),
    expiresAt: at(35),
    endedAt: null,
    startedBy: 'ops-admin',
    reason: 'Investigating RM-SSH-002: successful password login after brute force.',
    dataTypes: ['SSH auth log lines', 'Active login sessions', 'Listening sockets snapshot'],
    itemCount: 14,
    linkedAlertId: 'a-1042',
  },
  {
    id: 'ev-06',
    hostId: 'h-db01',
    status: 'expired',
    startedAt: ago(2 * 1440 + 120),
    expiresAt: ago(2 * 1440 + 90),
    endedAt: ago(2 * 1440 + 90),
    startedBy: 'ops-admin',
    reason: 'Follow-up on repeated postgres login failures.',
    dataTypes: ['SSH auth log lines', 'Active login sessions'],
    itemCount: 6,
  },
  {
    id: 'ev-05',
    hostId: 'h-stg03',
    status: 'stopped',
    startedAt: ago(4 * 1440 + 300),
    expiresAt: ago(4 * 1440 + 240),
    endedAt: ago(4 * 1440 + 285),
    startedBy: 'ops-admin',
    reason: 'Checking Nginx error spike after deploy.',
    dataTypes: ['Nginx access log lines', 'Nginx error log lines'],
    itemCount: 3,
  },
];

export const sampleReports: Report[] = [
  {
    id: 'r-0311',
    type: 'incident',
    title: 'Incident · web-01 SSH login after brute force',
    hostIds: ['h-web01'],
    periodStart: t(-30),
    periodEnd: ago(5),
    status: 'pending',
    requestedAt: ago(3),
  },
  {
    id: 'r-0310',
    type: 'daily',
    title: 'Daily report',
    hostIds: ['h-web01', 'h-api02', 'h-db01', 'h-stg03'],
    periodStart: dayIso(-1),
    periodEnd: dayIso(0),
    status: 'completed',
    requestedAt: dayIso(0),
    completedAt: new Date(startOfDay(0).getTime() + 4 * MIN).toISOString(),
    pages: 6,
    sizeKb: 412,
    alertCount: 1,
    findingCount: 7,
    gapCount: 1,
  },
  {
    id: 'r-0309',
    type: 'daily',
    title: 'Daily report',
    hostIds: ['h-web01', 'h-api02', 'h-db01', 'h-stg03'],
    periodStart: dayIso(-2),
    periodEnd: dayIso(-1),
    status: 'failed',
    requestedAt: dayIso(-1),
    error:
      'Reporting Agent request failed: AI provider unavailable. Monitoring data is intact. You can retry when the provider recovers.',
  },
  {
    id: 'r-0308',
    type: 'daily',
    title: 'Daily report',
    hostIds: ['h-web01', 'h-api02', 'h-db01', 'h-stg03'],
    periodStart: dayIso(-3),
    periodEnd: dayIso(-2),
    status: 'completed',
    requestedAt: dayIso(-2),
    completedAt: new Date(startOfDay(-2).getTime() + 3 * MIN).toISOString(),
    pages: 4,
    sizeKb: 288,
    alertCount: 0,
    findingCount: 6,
    gapCount: 0,
  },
];

export const sampleSystem: SystemStatus = {
  collector: 'ok',
  rulesEngine: 'ok',
  aiProvider: 'degraded',
  aiProviderNote: 'Intermittent timeouts in the last hour. Detection is not affected.',
  checkedAt: ago(1),
};

/** Evidence types the backend allows (PRD §7.7: configured + permitted only). */
export const allowedEvidenceTypes = [
  'SSH auth log lines',
  'Nginx access log lines',
  'Nginx error log lines',
  'Active login sessions',
  'Listening sockets snapshot',
];

/** Placeholder until the team locks the maximum duration (PRD §15). */
export const evidenceDurationOptions = [15, 30, 60];

