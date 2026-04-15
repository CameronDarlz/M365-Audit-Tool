import { DevicesData } from '../../../types/audit';
import { FindingCard } from '../FindingCard';
import { ScoreRing } from '../ScoreRing';
import { Finding, CategoryScore } from '../../../types/audit';
import { pct, formatDateTime, daysSince, downloadCsv } from '../../../lib/utils';
import { Download, Monitor, ShieldCheck, ShieldX, Clock, Laptop, Smartphone, Apple, HelpCircle } from 'lucide-react';

interface TabDevicesProps {
  data: DevicesData;
  score: CategoryScore;
  findings: Finding[];
}

const OS_ICONS: Record<string, React.ComponentType<{ size?: number; className?: string }>> = {
  Windows: Laptop,
  iOS: Smartphone,
  Android: Smartphone,
  macOS: Apple,
};

const COMPLIANCE_LABELS: Record<string, { label: string; color: string }> = {
  compliant:      { label: 'Compliant',       color: 'text-green-400'  },
  noncompliant:   { label: 'Non-compliant',   color: 'text-red-400'    },
  unknown:        { label: 'Unknown',         color: 'text-muted'      },
  notApplicable:  { label: 'N/A',             color: 'text-muted'      },
  inGracePeriod:  { label: 'Grace period',    color: 'text-yellow-400' },
  conflict:       { label: 'Conflict',        color: 'text-orange-400' },
  error:          { label: 'Error',           color: 'text-red-400'    },
};

export function TabDevices({ data, score, findings }: TabDevicesProps) {
  const { managedDevices, compliancePolicies } = data;

  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  const compliant    = managedDevices.filter(d => d.complianceState === 'compliant').length;
  const nonCompliant = managedDevices.filter(d => d.complianceState === 'noncompliant').length;
  const stale        = managedDevices.filter(d => new Date(d.lastSyncDateTime) < thirtyDaysAgo).length;

  const osCounts = managedDevices.reduce<Record<string, number>>((acc, d) => {
    const os = d.operatingSystem || 'Unknown';
    acc[os] = (acc[os] ?? 0) + 1;
    return acc;
  }, {});

  const corporate = managedDevices.filter(d => d.managedDeviceOwnerType === 'company').length;
  const personal  = managedDevices.filter(d => d.managedDeviceOwnerType === 'personal').length;

  function exportCsv() {
    downloadCsv('devices.csv', managedDevices.map(d => ({
      Name: d.deviceName,
      OS: d.operatingSystem,
      Version: d.osVersion,
      Compliance: d.complianceState,
      Owner: d.managedDeviceOwnerType,
      LastSync: d.lastSyncDateTime,
      Enrolled: d.enrolledDateTime,
    })));
  }

  return (
    <div className="p-6 space-y-6">
      {/* Score + summary */}
      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <ScoreRing score={score.score} grade={score.grade} label="Device Compliance" size={100} strokeWidth={8} />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Stat label="Total devices"      value={managedDevices.length} icon={Monitor} />
          <Stat label="Compliant"          value={compliant}    sub={pct(compliant, managedDevices.length)}    color="text-green-400"  icon={ShieldCheck} />
          <Stat label="Non-compliant"      value={nonCompliant} sub={pct(nonCompliant, managedDevices.length)} color="text-red-400"    icon={ShieldX}     />
          <Stat label="Stale (30d+ no sync)" value={stale}     sub={pct(stale, managedDevices.length)}        color="text-yellow-400" icon={Clock}        />
        </div>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-text">Findings ({findings.length})</h3>
          {findings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}

      {/* OS breakdown */}
      {Object.keys(osCounts).length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-4">OS Breakdown</h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {Object.entries(osCounts).sort((a, b) => b[1] - a[1]).map(([os, count]) => {
              const Icon = OS_ICONS[os] ?? HelpCircle;
              return (
                <div key={os} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#162032] border border-[#1e3a5f]">
                  <Icon size={14} className="text-muted" />
                  <span className="text-sm text-text font-mono">{count}</span>
                  <span className="text-xs text-muted truncate">{os}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Ownership */}
      {managedDevices.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-4">Ownership</h3>
          <div className="flex gap-4">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-400" />
              <span className="text-xs text-muted">Corporate: </span>
              <span className="text-xs font-mono text-text">{corporate} ({pct(corporate, managedDevices.length)})</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-muted/40" />
              <span className="text-xs text-muted">Personal: </span>
              <span className="text-xs font-mono text-text">{personal} ({pct(personal, managedDevices.length)})</span>
            </div>
          </div>
        </div>
      )}

      {/* Compliance policies */}
      <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <h3 className="text-sm font-semibold text-text mb-3">
          Compliance Policies ({compliancePolicies.length})
        </h3>
        {compliancePolicies.length === 0 ? (
          <p className="text-sm text-muted">No compliance policies configured.</p>
        ) : (
          <div className="space-y-2">
            {compliancePolicies.map(p => (
              <div key={p.id} className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#162032] border border-[#1e3a5f]">
                <span className="text-sm text-text">{p.displayName}</span>
                <span className="text-xs text-muted">v{p.version}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Device table */}
      {managedDevices.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-[#1e3a5f]">
            <h3 className="text-sm font-semibold text-text">Devices ({managedDevices.length})</h3>
            <button onClick={exportCsv}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs text-muted hover:text-text
                hover:bg-[#1e3a5f]/40 border border-transparent hover:border-[#1e3a5f] transition-colors">
              <Download size={12} /> Export CSV
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e3a5f]">
                  {['Device name', 'OS', 'Compliance', 'Owner', 'Last sync'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-[10px] uppercase tracking-wider text-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e3a5f]/50">
                {managedDevices.slice(0, 50).map(d => {
                  const cs = COMPLIANCE_LABELS[d.complianceState] ?? { label: d.complianceState, color: 'text-muted' };
                  const ds = daysSince(d.lastSyncDateTime);
                  return (
                    <tr key={d.id} className="hover:bg-[#162032] transition-colors">
                      <td className="px-4 py-2.5 font-mono text-text">{d.deviceName}</td>
                      <td className="px-4 py-2.5 text-muted">{d.operatingSystem} {d.osVersion}</td>
                      <td className={`px-4 py-2.5 font-medium ${cs.color}`}>{cs.label}</td>
                      <td className="px-4 py-2.5 text-muted capitalize">{d.managedDeviceOwnerType}</td>
                      <td className={`px-4 py-2.5 ${ds !== null && ds > 30 ? 'text-yellow-400' : 'text-muted'}`}>
                        {ds !== null ? `${ds}d ago` : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {managedDevices.length > 50 && (
              <p className="text-center text-xs text-muted py-3">
                Showing 50 of {managedDevices.length} devices
              </p>
            )}
          </div>
        </div>
      )}

      {/* Error state */}
      {data.error && (
        <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-400">
          <strong>Collection error:</strong> {data.error}
        </div>
      )}
    </div>
  );
}

function Stat({
  label, value, sub, color = 'text-text', icon: Icon,
}: {
  label: string; value: number; sub?: string;
  color?: string; icon: React.ComponentType<{ size?: number; className?: string }>;
}) {
  return (
    <div className="flex items-center gap-2">
      <Icon size={14} className="text-muted flex-shrink-0" />
      <div>
        <p className={`text-lg font-bold font-mono ${color}`}>{value}</p>
        <p className="text-[10px] text-muted leading-tight">{label}</p>
        {sub && <p className={`text-[10px] font-mono ${color}`}>{sub}</p>}
      </div>
    </div>
  );
}
