import { useMemo, useState } from 'react';
import { Download, Info, Search, ShieldCheck, X } from 'lucide-react';
import { Screen } from '../components/AppShell';
import { AuditLogList } from '../components/domain';
import { EmptyState, QueryView, SkeletonBlock } from '../components/states';
import { Button, Chips, Notice, PageIntro, Section } from '../components/ui';
import { api } from '../data/api';
import type { OperatorAuditLog } from '../data/types';
import { useQuery } from '../lib/hooks';

type TargetFilter = 'all' | 'alert' | 'finding' | 'evidence_session' | 'report' | 'system';

export function AuditLogScreen() {
  const [searchQuery, setSearchQuery] = useState('');
  const [targetFilter, setTargetFilter] = useState<TargetFilter>('all');

  const q = useQuery(() => api.auditLogs());

  const handleExportJson = (logs: OperatorAuditLog[]) => {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AEGIS-Audit-Log-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Screen
      title="Audit Log"
      back="/"
      actions={
        q.data && q.data.length > 0 ? (
          <Button
            variant="secondary"
            size="sm"
            icon={Download}
            onClick={() => handleExportJson(q.data ?? [])}
          >
            Export JSON
          </Button>
        ) : undefined
      }
    >
      <PageIntro>
        Immutable operator and system audit trail recording every investigation update, AI analysis execution,
        Emergency Evidence Mode session, and report compilation.
      </PageIntro>

      <QueryView query={q} loading={<SkeletonBlock height={240} />}>
        {(logs) => (
          <FilteredAuditLogs
            logs={logs}
            searchQuery={searchQuery}
            setSearchQuery={setSearchQuery}
            targetFilter={targetFilter}
            setTargetFilter={setTargetFilter}
          />
        )}
      </QueryView>
    </Screen>
  );
}

function FilteredAuditLogs({
  logs,
  searchQuery,
  setSearchQuery,
  targetFilter,
  setTargetFilter,
}: {
  logs: OperatorAuditLog[];
  searchQuery: string;
  setSearchQuery: (v: string) => void;
  targetFilter: TargetFilter;
  setTargetFilter: (v: TargetFilter) => void;
}) {
  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return logs.filter((l) => {
      if (targetFilter !== 'all' && l.targetType !== targetFilter) return false;
      if (q) {
        const hay = `${l.id} ${l.actor} ${l.action} ${l.targetType} ${l.targetId} ${l.summary}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [logs, searchQuery, targetFilter]);

  return (
    <>
      <Notice tone="info" icon={Info} title="Append-Only Accountability Guarantee">
        Audit records are protected by PostgreSQL immutability triggers (`prevent_audit_log_mutation`) and cannot be
        modified or deleted by operators or AI agents.
      </Notice>

      <div
        style={{
          marginBottom: '0.85rem',
          padding: '0.65rem 0.85rem',
          borderRadius: '10px',
          background: 'var(--color-surface)',
          border: '1px solid var(--color-border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.55rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Search size={16} style={{ color: 'var(--color-text-tertiary)', flexShrink: 0 }} aria-hidden />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search audit log by actor (ops-admin, system), action, target ID, or summary…"
            aria-label="Search audit logs"
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--color-text-primary)',
              fontSize: '0.85rem',
            }}
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              aria-label="Clear search"
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--color-text-tertiary)',
                display: 'flex',
                alignItems: 'center',
              }}
            >
              <X size={15} />
            </button>
          )}
        </div>
      </div>

      <div className="filter-bar">
        <Chips
          label="Target entity filter"
          value={targetFilter}
          onChange={setTargetFilter}
          options={[
            { value: 'all', label: `All (${logs.length})` },
            { value: 'alert', label: `Alerts (${logs.filter((x) => x.targetType === 'alert').length})` },
            { value: 'finding', label: `Findings (${logs.filter((x) => x.targetType === 'finding').length})` },
            {
              value: 'evidence_session',
              label: `Evidence (${logs.filter((x) => x.targetType === 'evidence_session').length})`,
            },
            { value: 'report', label: `Reports (${logs.filter((x) => x.targetType === 'report').length})` },
            { value: 'system', label: `System (${logs.filter((x) => x.targetType === 'system').length})` },
          ]}
        />
      </div>

      <Section title={`Audit Entries (${filtered.length})`}>
        {filtered.length === 0 ? (
          <EmptyState icon={ShieldCheck} title="No matching audit entries">
            Try clearing the search query or selecting a different target filter.
          </EmptyState>
        ) : (
          <AuditLogList logs={filtered} />
        )}
      </Section>
    </>
  );
}
