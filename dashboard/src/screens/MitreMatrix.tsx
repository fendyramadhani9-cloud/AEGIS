import { Link } from 'react-router-dom';
import { Crosshair, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { QueryView, SkeletonBlock } from '../components/states';
import { Group, PageIntro, Row, Section, Tag } from '../components/ui';
import { api, hostName } from '../data/api';
import type { Alert } from '../data/types';
import { useQuery } from '../lib/hooks';
import { useTimeFormat } from '../lib/time';

interface MitreTechniqueDef {
  id: string;
  name: string;
  tactic: string;
  rules: string[];
}

const MITRE_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Exfiltration',
] as const;

const MITRE_TECHNIQUES: MitreTechniqueDef[] = [
  { id: 'T1190', name: 'Exploit Public-Facing App', tactic: 'Initial Access', rules: ['RULE-WEB-ATTACK'] },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access', rules: ['RULE-AUTH-003'] },
  { id: 'T1609', name: 'Container / Pod Exec', tactic: 'Execution', rules: ['RULE-CONTAINER-EXEC', 'RULE-K8S-POD-EXEC'] },
  { id: 'T1059', name: 'Command & Scripting', tactic: 'Execution', rules: ['RULE-SUSP-SUDO'] },
  { id: 'T1053', name: 'Scheduled Task / Cron', tactic: 'Persistence', rules: ['RULE-CRON-PERSIST'] },
  { id: 'T1098', name: 'Account / SSH Key / RBAC Manipulation', tactic: 'Persistence', rules: ['RULE-ACCT-BACKDOOR', 'RULE-SSH-KEY-BACKDOOR', 'RULE-K8S-RBAC-ESCALATION'] },
  { id: 'T1548', name: 'Abuse Elevation Control (Sudo)', tactic: 'Privilege Escalation', rules: ['RULE-SUSP-SUDO'] },
  { id: 'T1611', name: 'Escape to Host (Privileged Container/Pod)', tactic: 'Privilege Escalation', rules: ['RULE-CONTAINER-ESCAPE-RISK', 'RULE-K8S-PRIVILEGED-POD'] },
  { id: 'T1547.006', name: 'Kernel Module / Rootkit Load', tactic: 'Privilege Escalation', rules: ['RULE-ROOTKIT-SNIFF'] },
  { id: 'T1562', name: 'Impair Defenses / Anti-Forensics', tactic: 'Defense Evasion', rules: ['RULE-DEFENSE-EVASION', 'RULE-ANTI-FORENSICS'] },
  { id: 'AML.T0051', name: 'LLM Prompt Injection / Log Poisoning', tactic: 'Defense Evasion', rules: ['RULE-AEGIS-PROMPT-INJECTION'] },
  { id: 'T1110', name: 'Brute Force (SSH)', tactic: 'Credential Access', rules: ['RULE-SSH-BRUTE'] },
  { id: 'T1552.007', name: 'Container / K8s Secret Access', tactic: 'Credential Access', rules: ['RULE-K8S-SECRET-ACCESS'] },
  { id: 'T1041', name: 'Exfiltration Over C2 / Archive', tactic: 'Exfiltration', rules: ['RULE-DATA-EXFIL'] },
];

export function MitreMatrixScreen() {
  const { when } = useTimeFormat();
  const q = useQuery(async () => {
    const [alerts, hosts] = await Promise.all([api.alerts(), api.hosts()]);
    return { alerts, hosts };
  });

  return (
    <Screen title="MITRE ATT&CK Matrix">
      <PageIntro>
        Live mapping of deterministic detections across MITRE ATT&CK and ATLAS kill-chain tactics (host, container, Kubernetes, and AI guardrail telemetry).
      </PageIntro>

      <QueryView query={q} loading={<SkeletonBlock height={240} />}>
        {({ alerts }) => {
          const matchAlerts = (t: MitreTechniqueDef): Alert[] =>
            alerts.filter((a) => t.rules.includes(a.ruleId) || a.title.includes(t.id));

          const activeTechniques = MITRE_TECHNIQUES.filter((t) => matchAlerts(t).length > 0);
          const totalCovered = MITRE_TECHNIQUES.length;

          return (
            <>
              <div className="kpi-grid" style={{ marginBottom: '20px' }}>
                <div className="kpi-card">
                  <div className="kpi-card__label">Active Techniques Triggered</div>
                  <div className="kpi-card__value">{activeTechniques.length}</div>
                  <div className="kpi-card__sub">of {totalCovered} monitored ATT&amp;CK / ATLAS techniques</div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-card__label">Mapped Detections</div>
                  <div className="kpi-card__value">
                    {MITRE_TECHNIQUES.reduce((acc, t) => acc + matchAlerts(t).length, 0)}
                  </div>
                  <div className="kpi-card__sub">Deterministic rule-to-tactic correlation</div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-card__label">Tactics Observed</div>
                  <div className="kpi-card__value">
                    {new Set(activeTechniques.map((t) => t.tactic)).size} / {MITRE_TACTICS.length}
                  </div>
                  <div className="kpi-card__sub">Kill-chain breadth</div>
                </div>
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: '12px',
                  marginBottom: '24px',
                }}
              >
                {MITRE_TACTICS.map((tactic) => {
                  const techs = MITRE_TECHNIQUES.filter((t) => t.tactic === tactic);
                  const tacticHits = techs.reduce((s, t) => s + matchAlerts(t).length, 0);
                  return (
                    <div
                      key={tactic}
                      style={{
                        border: '1px solid var(--color-border)',
                        borderRadius: '10px',
                        padding: '12px',
                        background: 'var(--color-surface)',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          marginBottom: '10px',
                          paddingBottom: '8px',
                          borderBottom: '1px solid var(--color-border)',
                        }}
                      >
                        <strong style={{ fontSize: '0.85rem', letterSpacing: '0.02em' }}>{tactic}</strong>
                        <Tag>{tacticHits} hits</Tag>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {techs.map((t) => {
                          const hits = matchAlerts(t);
                          const isHot = hits.length > 0;
                          return (
                            <div
                              key={t.id}
                              style={{
                                padding: '8px 10px',
                                borderRadius: '8px',
                                border: isHot
                                  ? '1px solid rgba(239, 68, 68, 0.45)'
                                  : '1px solid var(--color-border)',
                                background: isHot ? 'rgba(239, 68, 68, 0.08)' : 'transparent',
                              }}
                            >
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span className="mono" style={{ fontSize: '0.74rem', fontWeight: 700 }}>
                                  {t.id}
                                </span>
                                {isHot ? (
                                  <span style={{ fontSize: '0.72rem', fontWeight: 700, color: '#ef4444' }}>
                                    {hits.length} alert{hits.length > 1 ? 's' : ''}
                                  </span>
                                ) : (
                                  <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>0</span>
                                )}
                              </div>
                              <div style={{ fontSize: '0.78rem', marginTop: '3px', color: 'var(--color-text)' }}>
                                {t.name}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>

              <Section
                title={`Active Mapped Detections (${activeTechniques.length})`}
                description="Click any triggered detection to inspect grounded evidence and AI analysis."
              >
                {activeTechniques.length === 0 ? (
                  <Group>
                    <Row
                      leading={<ShieldCheck className="text-healthy" aria-hidden />}
                      title="No ATT&CK techniques triggered"
                      subtitle="All monitored rules across host, container, and Kubernetes telemetry are currently clear."
                    />
                  </Group>
                ) : (
                  <Group>
                    {activeTechniques.flatMap((t) =>
                      matchAlerts(t).slice(0, 3).map((a) => (
                        <Row
                          key={`${t.id}-${a.id}`}
                          to={`/alerts/${a.id}`}
                          leading={<ShieldAlert className="text-critical" aria-hidden />}
                          title={`${t.id} · ${t.name}`}
                          subtitle={a.title}
                          meta={
                            <>
                              <span>{t.tactic}</span>
                              <span aria-hidden>·</span>
                              <span>{hostName(a.hostId)}</span>
                              <span aria-hidden>·</span>
                              <span>{when(a.detectedAt)}</span>
                            </>
                          }
                          trailing={
                            <Link to={`/alerts/${a.id}`} style={{ fontSize: '0.78rem' }}>
                              <Crosshair size={14} />
                            </Link>
                          }
                        />
                      )),
                    )}
                  </Group>
                )}
              </Section>
            </>
          );
        }}
      </QueryView>
    </Screen>
  );
}
export default MitreMatrixScreen;
