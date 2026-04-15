import type { ConditionalAccessData, Finding, CategoryScore } from '../../../types/audit';
import { FindingCard } from '../FindingCard';
import { ScoreRing } from '../ScoreRing';
import { CheckCircle2, XCircle, MinusCircle, MapPin } from 'lucide-react';
import { cn } from '../../../lib/utils';

interface TabConditionalAccessProps {
  data: ConditionalAccessData;
  score: CategoryScore;
  findings: Finding[];
}

const STATE_CONFIG = {
  enabled:                           { label: 'Enabled',      color: 'text-green-400',  Icon: CheckCircle2 },
  disabled:                          { label: 'Disabled',     color: 'text-muted',      Icon: XCircle      },
  enabledForReportingButNotEnforced: { label: 'Report only',  color: 'text-yellow-400', Icon: MinusCircle  },
};

export function TabConditionalAccess({ data, score, findings }: TabConditionalAccessProps) {
  const { policies, namedLocations } = data;

  const enabled    = policies.filter(p => p.state === 'enabled').length;
  const reportOnly = policies.filter(p => p.state === 'enabledForReportingButNotEnforced').length;
  const disabled   = policies.filter(p => p.state === 'disabled').length;

  const hasMfa     = policies.some(p => p.state === 'enabled' && p.grantControls?.builtInControls.includes('mfa'));
  const hasLegacy  = policies.some(p =>
    p.state === 'enabled' &&
    (p.conditions.clientAppTypes?.includes('exchangeActiveSync') || p.conditions.clientAppTypes?.includes('other')) &&
    p.grantControls?.builtInControls.includes('block'),
  );
  const hasAdmin   = policies.some(p => p.state === 'enabled' && (p.conditions.users?.includeRoles?.length ?? 0) > 0);
  const hasRisk    = policies.some(p =>
    p.state === 'enabled' &&
    ((p.conditions.userRiskLevels?.length ?? 0) > 0 || (p.conditions.signInRiskLevels?.length ?? 0) > 0),
  );

  return (
    <div className="p-6 space-y-6">
      {/* Score + counts */}
      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <ScoreRing score={score.score} grade={score.grade} label="Conditional Access" size={100} strokeWidth={8} />
        <div className="grid grid-cols-3 gap-4">
          <Stat label="Enabled"     value={enabled}    color="text-green-400" />
          <Stat label="Report only" value={reportOnly} color="text-yellow-400" />
          <Stat label="Disabled"    value={disabled}   color="text-muted" />
        </div>
      </div>

      {/* Baseline checks */}
      <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <h3 className="text-sm font-semibold text-text mb-4">Baseline Policy Checks</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <Check label="MFA enforcement policy"        pass={hasMfa}    />
          <Check label="Legacy auth block"             pass={hasLegacy} />
          <Check label="Admin-targeted policy"         pass={hasAdmin}  />
          <Check label="Risk-based policy"             pass={hasRisk}   />
          <Check label="Named locations configured"    pass={namedLocations.length > 0} />
        </div>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-text">Findings ({findings.length})</h3>
          {findings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}

      {/* Named locations */}
      {namedLocations.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-3">
            <MapPin size={14} className="inline mr-1.5 text-muted" />
            Named Locations ({namedLocations.length})
          </h3>
          <div className="space-y-2">
            {namedLocations.map(loc => (
              <div key={loc.id} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-[#162032] border border-[#1e3a5f]">
                <MapPin size={13} className="text-muted flex-shrink-0" />
                <span className="text-sm text-text">{loc.displayName}</span>
                <span className="ml-auto text-[10px] text-muted font-mono">
                  {loc['@odata.type']?.replace('#microsoft.graph.', '') ?? 'location'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Policy list */}
      {policies.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] overflow-hidden">
          <div className="px-5 py-3 border-b border-[#1e3a5f]">
            <h3 className="text-sm font-semibold text-text">All Policies ({policies.length})</h3>
          </div>
          <div className="divide-y divide-[#1e3a5f]/50">
            {policies.map(p => {
              const cfg = STATE_CONFIG[p.state] ?? STATE_CONFIG.disabled;
              const grants = p.grantControls?.builtInControls ?? [];
              const targets = [
                p.conditions.users?.includeUsers?.includes('All') && 'All users',
                (p.conditions.users?.includeRoles?.length ?? 0) > 0 && 'Admin roles',
                p.conditions.users?.includeGroups?.length && `${p.conditions.users.includeGroups.length} group(s)`,
              ].filter(Boolean);
              return (
                <div key={p.id} className="px-5 py-3 hover:bg-[#162032] transition-colors">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2 min-w-0">
                      <cfg.Icon size={14} className={cn('flex-shrink-0', cfg.color)} />
                      <span className="text-sm text-text truncate">{p.displayName}</span>
                    </div>
                    <span className={cn('text-xs font-medium flex-shrink-0', cfg.color)}>
                      {cfg.label}
                    </span>
                  </div>
                  <div className="mt-1.5 ml-6 flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] text-muted">
                    {targets.length > 0 && <span>Targets: {targets.join(', ')}</span>}
                    {grants.length > 0  && <span>Grant: {grants.join(', ')}</span>}
                    {p.grantControls?.builtInControls.includes('block') && (
                      <span className="text-red-400">Block</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {data.error && (
        <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-400">
          <strong>Collection error:</strong> {data.error}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color = 'text-text' }: { label: string; value: number; color?: string }) {
  return (
    <div>
      <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
      <p className="text-xs text-muted mt-0.5">{label}</p>
    </div>
  );
}

function Check({ label, pass }: { label: string; pass: boolean }) {
  return (
    <div className={cn(
      'flex items-center gap-2 px-3 py-2 rounded-lg border',
      pass ? 'bg-green-400/5 border-green-400/20' : 'bg-red-400/5 border-red-400/20',
    )}>
      {pass
        ? <CheckCircle2 size={13} className="text-green-400 flex-shrink-0" />
        : <XCircle size={13} className="text-red-400 flex-shrink-0" />}
      <span className="text-xs text-muted">{label}</span>
      <span className={cn('ml-auto text-xs font-medium', pass ? 'text-green-400' : 'text-red-400')}>
        {pass ? 'Yes' : 'Missing'}
      </span>
    </div>
  );
}
