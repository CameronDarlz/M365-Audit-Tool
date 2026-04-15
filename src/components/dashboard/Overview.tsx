import type { ScoredAudit } from '../../types/audit';
import { ScoreRing } from './ScoreRing';
import { FindingCard } from './FindingCard';
import { formatDate, gradeColor } from '../../lib/utils';
import { Building2, Calendar, Globe, AlertTriangle, ShieldAlert, AlertCircle, Info } from 'lucide-react';

interface OverviewProps {
  audit: ScoredAudit;
}

const SEVERITY_ICONS = {
  critical: { Icon: ShieldAlert,  color: 'text-red-400',    bg: 'bg-red-400/10',    border: 'border-red-400/20'    },
  high:     { Icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/20' },
  medium:   { Icon: AlertCircle,  color: 'text-yellow-400', bg: 'bg-yellow-400/10', border: 'border-yellow-400/20' },
  low:      { Icon: Info,         color: 'text-blue-400',   bg: 'bg-blue-400/10',   border: 'border-blue-400/20'   },
};

function SeverityCount({ label, count, type }: { label: string; count: number; type: keyof typeof SEVERITY_ICONS }) {
  const { Icon, color, bg, border } = SEVERITY_ICONS[type];
  return (
    <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${bg} ${border}`}>
      <Icon size={14} className={color} />
      <span className={`font-mono text-lg font-bold ${color}`}>{count}</span>
      <span className="text-xs text-muted">{label}</span>
    </div>
  );
}

export function Overview({ audit }: OverviewProps) {
  const { result, scores, overallScore, overallGrade, findings } = audit;
  const org = result.org.organization;

  const critCount   = findings.filter(f => f.severity === 'critical').length;
  const highCount   = findings.filter(f => f.severity === 'high').length;
  const medCount    = findings.filter(f => f.severity === 'medium').length;
  const lowCount    = findings.filter(f => f.severity === 'low').length;

  const topScores = Object.entries(scores)
    .filter(([, s]) => s.available)
    .sort((a, b) => a[1].score - b[1].score)
    .slice(0, 4);

  const primaryDomain = org?.verifiedDomains?.find(d => d.isDefault)?.name
    ?? org?.verifiedDomains?.[0]?.name ?? '—';

  return (
    <div className="p-6 grid grid-cols-1 xl:grid-cols-[1fr_400px] gap-6">
      {/* Left column */}
      <div className="space-y-6">

        {/* Score section */}
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
            {/* Main ring */}
            <ScoreRing
              score={overallScore}
              size={140}
              strokeWidth={12}
              grade={overallGrade}
              label="Overall Score"
            />

            {/* Sub-scores */}
            <div className="flex-1 grid grid-cols-2 gap-4">
              {topScores.map(([key, cat]) => (
                <div key={key} className="flex items-center gap-3">
                  <ScoreRing
                    score={cat.score}
                    size={64}
                    strokeWidth={6}
                    grade={cat.grade}
                    animate
                  />
                  <div>
                    <p className="text-xs font-medium text-text leading-tight">{cat.label}</p>
                    <p className="text-[10px] text-muted capitalize">{cat.grade}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Audit meta */}
          <div className="mt-5 pt-4 border-t border-[#1e3a5f] flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted">
            <span>Audited {formatDate(result.auditedAt)}</span>
            {org && (
              <span className="text-muted/60">
                Tenant ID: <span className="font-mono">{org.id.slice(0, 8)}…</span>
              </span>
            )}
          </div>
        </div>

        {/* Severity summary */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <SeverityCount label="Critical" count={critCount} type="critical" />
          <SeverityCount label="High"     count={highCount} type="high"     />
          <SeverityCount label="Medium"   count={medCount}  type="medium"   />
          <SeverityCount label="Low"      count={lowCount}  type="low"      />
        </div>

        {/* All category scores */}
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-4">Category Scores</h3>
          <div className="space-y-3">
            {Object.entries(scores).map(([key, cat]) => {
              const color = gradeColor(cat.grade);
              const w = cat.available ? `${cat.score}%` : '0%';
              return (
                <div key={key}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-muted">{cat.label}</span>
                    <div className="flex items-center gap-2">
                      {!cat.available && (
                        <span className="text-[10px] text-muted/50">unavailable</span>
                      )}
                      <span className="text-xs font-mono font-semibold" style={{ color }}>
                        {cat.available ? cat.score : '—'}
                      </span>
                    </div>
                  </div>
                  <div className="h-1.5 rounded-full bg-[#1e3a5f] overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{ width: w, backgroundColor: color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Right column */}
      <div className="space-y-4">
        {/* Tenant info */}
        {org && (
          <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
            <h3 className="text-sm font-semibold text-text mb-3">Tenant</h3>
            <div className="space-y-2.5">
              <Row icon={Building2} label="Organisation" value={org.displayName} />
              <Row icon={Globe} label="Primary domain" value={primaryDomain} mono />
              <Row icon={Calendar} label="Tenant created" value={formatDate(org.createdDateTime)} />
              <Row icon={Globe} label="Country" value={org.countryLetterCode} />
              {org.verifiedDomains.length > 1 && (
                <div>
                  <p className="text-[10px] text-muted mb-1">All verified domains</p>
                  <div className="flex flex-wrap gap-1">
                    {org.verifiedDomains.map(d => (
                      <span key={d.name} className="px-2 py-0.5 rounded-md bg-[#162032] border border-[#1e3a5f] text-xs font-mono text-muted">
                        {d.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Findings list */}
        <div>
          <h3 className="text-sm font-semibold text-text mb-3">
            All Findings
            <span className="ml-2 text-xs font-normal text-muted">({findings.length})</span>
          </h3>
          <div className="space-y-3">
            {findings.map(f => (
              <FindingCard key={f.id} finding={f} compact />
            ))}
            {findings.length === 0 && (
              <div className="text-center py-8 text-muted text-sm">
                No findings — excellent posture!
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Row({
  icon: Icon,
  label,
  value,
  mono,
}: {
  icon: React.ComponentType<{ size?: number; className?: string }>;
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center gap-2">
      <Icon size={13} className="text-muted flex-shrink-0" />
      <span className="text-xs text-muted">{label}</span>
      <span className={`ml-auto text-xs text-text truncate max-w-[160px] ${mono ? 'font-mono' : ''}`}>
        {value}
      </span>
    </div>
  );
}
