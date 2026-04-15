import { ApplicationsData, Finding, CategoryScore } from '../../../types/audit';
import { FindingCard } from '../FindingCard';
import { ScoreRing } from '../ScoreRing';
import { daysUntil, daysSince, formatDate, downloadCsv } from '../../../lib/utils';
import { Download, AlertTriangle, CheckCircle2 } from 'lucide-react';

interface TabApplicationsProps {
  data: ApplicationsData;
  score: CategoryScore;
  findings: Finding[];
  tenantId?: string;
}

export function TabApplications({ data, score, findings, tenantId }: TabApplicationsProps) {
  const { appRegistrations, servicePrincipals } = data;
  const now = new Date();

  const appsWithSecrets     = appRegistrations.filter(a => a.passwordCredentials.length > 0);
  const appsWithNoOwner     = appRegistrations.filter(a => !a.owners || a.owners.length === 0);
  const thirdPartyApps      = servicePrincipals.filter(sp => sp.appOwnerOrganizationId !== tenantId);

  function exportCsv() {
    downloadCsv('app-registrations.csv', appRegistrations.map(a => {
      const secrets = a.passwordCredentials;
      const expiries = secrets.map(s => s.endDateTime ?? '').filter(Boolean);
      return {
        Name: a.displayName,
        AppId: a.appId,
        Created: formatDate(a.createdDateTime),
        Owners: (a.owners?.length ?? 0),
        Secrets: secrets.length,
        EarliestExpiry: expiries.length ? expiries.sort()[0] : 'None',
      };
    }));
  }

  return (
    <div className="p-6 space-y-6">
      {/* Score + stats */}
      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <ScoreRing score={score.score} grade={score.grade} label="Applications" size={100} strokeWidth={8} />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Stat label="App registrations"   value={appRegistrations.length} />
          <Stat label="With client secrets" value={appsWithSecrets.length} />
          <Stat label="No owners"           value={appsWithNoOwner.length} color={appsWithNoOwner.length > 0 ? 'text-orange-400' : 'text-green-400'} />
          <Stat label="3rd party apps"      value={thirdPartyApps.length} />
        </div>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-text">Findings ({findings.length})</h3>
          {findings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}

      {/* App registrations table */}
      {appRegistrations.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-[#1e3a5f]">
            <h3 className="text-sm font-semibold text-text">App Registrations ({appRegistrations.length})</h3>
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
                  {['App name', 'Created', 'Owners', 'Secrets', 'Earliest expiry'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-[10px] uppercase tracking-wider text-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e3a5f]/50">
                {appRegistrations.slice(0, 50).map(app => {
                  const secrets = app.passwordCredentials;
                  const expired  = secrets.filter(s => s.endDateTime && new Date(s.endDateTime) < now);
                  const expiring = secrets.filter(s => {
                    if (!s.endDateTime) return false;
                    const d = daysUntil(s.endDateTime);
                    return d !== null && d >= 0 && d <= 30;
                  });
                  const earliest = secrets
                    .map(s => s.endDateTime)
                    .filter(Boolean)
                    .sort()[0];
                  const du = earliest ? daysUntil(earliest) : null;

                  return (
                    <tr key={app.id} className="hover:bg-[#162032] transition-colors">
                      <td className="px-4 py-2.5 text-text">{app.displayName}</td>
                      <td className="px-4 py-2.5 text-muted">{formatDate(app.createdDateTime)}</td>
                      <td className="px-4 py-2.5">
                        {(app.owners?.length ?? 0) > 0
                          ? <CheckCircle2 size={13} className="text-green-400" />
                          : <AlertTriangle size={13} className="text-orange-400" />}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-text">{secrets.length}</td>
                      <td className="px-4 py-2.5">
                        {expired.length > 0 && <span className="text-red-400 font-medium">Expired ({expired.length})</span>}
                        {expiring.length > 0 && expired.length === 0 && (
                          <span className="text-orange-400 font-medium">
                            {du !== null ? `${du}d` : '—'}
                          </span>
                        )}
                        {expired.length === 0 && expiring.length === 0 && (
                          <span className="text-muted">
                            {earliest ? formatDate(earliest) : '—'}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {appRegistrations.length > 50 && (
              <p className="text-center text-xs text-muted py-3">
                Showing 50 of {appRegistrations.length} apps
              </p>
            )}
          </div>
        </div>
      )}

      {/* Enterprise apps */}
      {thirdPartyApps.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-3">
            Third-party Enterprise Apps ({thirdPartyApps.length})
          </h3>
          <div className="space-y-2">
            {thirdPartyApps.slice(0, 20).map(sp => (
              <div key={sp.id} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-[#162032] border border-[#1e3a5f]">
                <span className="text-sm text-text">{sp.displayName}</span>
                {sp.publisherName && (
                  <span className="text-xs text-muted">by {sp.publisherName}</span>
                )}
              </div>
            ))}
            {thirdPartyApps.length > 20 && (
              <p className="text-xs text-muted text-center py-2">
                +{thirdPartyApps.length - 20} more
              </p>
            )}
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
