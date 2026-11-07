/**
 * Single source of truth for how every status is presented.
 * Each status always has: a tone (colour), an icon (shape) and a text label,
 * so meaning never depends on colour alone.
 */
import {
  Ban,
  CircleCheck,
  CircleDashed,
  CircleDot,
  CircleHelp,
  CircleMinus,
  Clock,
  FileCheck2,
  FileX2,
  Info,
  LoaderCircle,
  OctagonAlert,
  Radio,
  TriangleAlert,
  CircleAlert,
  Unplug,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  AlertCircle,
  CheckCheck,
  type LucideIcon,
} from 'lucide-react';
import type {
  AgentStatus,
  Confidence,
  EvidenceStatus,
  FindingStatus,
  InvestigationStatus,
  ReportStatus,
  Severity,
  SourceStatus,
} from '../data/types';

export type Tone = 'healthy' | 'info' | 'warning' | 'high' | 'critical' | 'disabled' | 'unknown' | 'brand';

export interface StatusMeta {
  label: string;
  tone: Tone;
  icon: LucideIcon;
  /** Optional longer description for detail screens / accessibility. */
  hint?: string;
}

export const agentStatusMeta: Record<AgentStatus, StatusMeta> = {
  online: { label: 'Online', tone: 'healthy', icon: CircleCheck, hint: 'Data received within the last 5 minutes' },
  delayed: { label: 'Delayed', tone: 'warning', icon: Clock, hint: 'No data for 5–30 minutes' },
  offline: { label: 'Offline', tone: 'critical', icon: Unplug, hint: 'No data for more than 30 minutes' },
  unknown: { label: 'No data yet', tone: 'unknown', icon: CircleHelp, hint: 'Registered, but nothing received' },
};

export const severityMeta: Record<Severity, StatusMeta> = {
  critical: { label: 'Critical', tone: 'critical', icon: OctagonAlert },
  high: { label: 'High', tone: 'high', icon: TriangleAlert },
  medium: { label: 'Medium', tone: 'warning', icon: CircleAlert },
  low: { label: 'Low', tone: 'info', icon: CircleDot },
  info: { label: 'Info', tone: 'info', icon: Info },
};

export const findingStatusMeta: Record<FindingStatus, StatusMeta> = {
  fail: { label: 'Failed', tone: 'high', icon: TriangleAlert },
  pass: { label: 'Passed', tone: 'healthy', icon: CircleCheck },
  not_checked: {
    label: 'Not checked',
    tone: 'unknown',
    icon: CircleDashed,
    hint: 'Data unavailable or insufficient permission — result unknown',
  },
};

export const sourceStatusMeta: Record<SourceStatus, StatusMeta> = {
  collecting: { label: 'Collecting', tone: 'healthy', icon: Radio },
  gap: { label: 'Telemetry gap', tone: 'warning', icon: CircleDashed },
  error: { label: 'Read error', tone: 'critical', icon: Ban },
  not_configured: { label: 'Not configured', tone: 'disabled', icon: CircleMinus },
};

export const reportStatusMeta: Record<ReportStatus, StatusMeta> = {
  completed: { label: 'Ready', tone: 'healthy', icon: FileCheck2 },
  pending: { label: 'Generating', tone: 'info', icon: LoaderCircle },
  failed: { label: 'Failed', tone: 'critical', icon: FileX2 },
};

export const evidenceStatusMeta: Record<EvidenceStatus, StatusMeta> = {
  active: { label: 'Active', tone: 'brand', icon: Radio },
  expired: { label: 'Expired', tone: 'disabled', icon: Clock },
  stopped: { label: 'Stopped', tone: 'disabled', icon: CircleMinus },
};

export const confidenceMeta: Record<Confidence, StatusMeta> = {
  confirmed: {
    label: 'Confirmed (95%+)',
    tone: 'healthy',
    icon: ShieldCheck,
    hint: 'Direct deterministic match backed by cryptographic or full syscall evidence',
  },
  high: {
    label: 'High (80–94%)',
    tone: 'high',
    icon: CheckCircle2,
    hint: 'Strong correlation of multiple coherent event indicators',
  },
  suspected: {
    label: 'Suspected (50–79%)',
    tone: 'warning',
    icon: AlertTriangle,
    hint: 'Heuristic or volumetric anomaly matching rule thresholds',
  },
  low: {
    label: 'Low (<50%)',
    tone: 'info',
    icon: HelpCircle,
    hint: 'Partial telemetry or single unconfirmed anomalous signal',
  },
};

export const investigationStatusMeta: Record<InvestigationStatus, StatusMeta> = {
  new: { label: 'New', tone: 'high', icon: AlertCircle, hint: 'Unreviewed alert requiring triage' },
  investigating: { label: 'Investigating', tone: 'warning', icon: Clock, hint: 'Active triage under operator review' },
  resolved: { label: 'Resolved', tone: 'healthy', icon: CheckCheck, hint: 'Confirmed incident mitigated and closed' },
  false_positive: { label: 'False Positive', tone: 'disabled', icon: Ban, hint: 'Authorized test or benign administrative action' },
  reopened: { label: 'Reopened', tone: 'critical', icon: OctagonAlert, hint: 'Triggering condition recurred after resolution' },
  unverified: { label: 'Unverified', tone: 'warning', icon: CircleDashed, hint: 'Telemetry gap or observation window incomplete' },
  triaged: { label: 'Triaged', tone: 'info', icon: CircleDot, hint: 'Initial operator triage complete' },
  contained: { label: 'Contained', tone: 'info', icon: ShieldCheck, hint: 'Threat activity isolated pending full verification' },
  escalated: { label: 'Escalated', tone: 'critical', icon: TriangleAlert, hint: 'Escalated to senior incident response' },
  closed: { label: 'Closed', tone: 'healthy', icon: CircleCheck, hint: 'Investigation formally archived' },
};

export const sourceLabel: Record<string, string> = {
  'ssh-auth': 'SSH auth (/var/log/auth.log)',
  'nginx-access': 'Nginx access log',
  'nginx-error': 'Nginx error log',
  auditd: 'Linux Auditd (/var/log/audit/audit.log)',
  syslog: 'System syslog (/var/log/syslog)',
  agent: 'AEGIS Agent Core',
};

