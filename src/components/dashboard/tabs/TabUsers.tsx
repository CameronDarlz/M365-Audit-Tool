import { UsersData, LicencesData, Finding, CategoryScore } from '../../../types/audit';
import { FindingCard } from '../FindingCard';
import { ScoreRing } from '../ScoreRing';
import { pct, daysSince, formatDate, downloadCsv } from '../../../lib/utils';
import { Download } from 'lucide-react';

interface TabUsersProps {
  usersData: UsersData;
  licencesData: LicencesData;
  score: CategoryScore;
  findings: Finding[];
}

export function TabUsers({ usersData, licencesData, score, findings }: TabUsersProps) {
  const { users } = usersData;
  const now = new Date();
  const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);

  const active  = users.filter(u => u.accountEnabled && u.userType !== 'Guest').length;
  const blocked = users.filter(u => !u.accountEnabled).length;
  const guests  = users.filter(u => u.userType === 'Guest').length;
  const licensed = users.filter(u => (u.assignedLicenses?.length ?? 0) > 0).length;

  const staleCount = users.filter(u => {
    if (!u.accountEnabled || u.userType === 'Guest') return false;
    const last = u.signInActivity?.lastSignInDateTime;
    if (!last) return false;
    return new Date(last) < ninetyDaysAgo;
  }).length;

  const blockedWithLicence = users.filter(u => !u.accountEnabled && (u.assignedLicenses?.length ?? 0) > 0).length;

  // Licence waste
  const wastedSeats = licencesData.subscribedSkus.reduce((acc, sku) => {
    const waste = sku.prepaidUnits.enabled - sku.consumedUnits;
    return acc + (waste > 0 ? waste : 0);
  }, 0);

  function exportCsv() {
    downloadCsv('users.csv', users.map(u => ({
      UPN: u.userPrincipalName,
      DisplayName: u.displayName,
      Type: u.userType,
      Enabled: u.accountEnabled,
      Licensed: (u.assignedLicenses?.length ?? 0) > 0,
      LastSignIn: u.signInActivity?.lastSignInDateTime ?? '',
      Created: u.createdDateTime,
      PasswordNeverExpires: u.passwordPolicies?.includes('DisablePasswordExpiration') ?? false,
    })));
  }

  return (
    <div className="p-6 space-y-6">
      {/* Score + stats */}
      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <ScoreRing score={score.score} grade={score.grade} label="User Hygiene" size={100} strokeWidth={8} />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Stat label="Active users"    value={active}   />
          <Stat label="Blocked"         value={blocked}  color={blocked > 0 ? 'text-orange-400' : 'text-muted'} />
          <Stat label="Guest accounts"  value={guests}   color={guests > 20 ? 'text-yellow-400' : 'text-muted'} />
          <Stat label="Stale (90d+)"    value={staleCount} color={staleCount > 0 ? 'text-orange-400' : 'text-green-400'} />
        </div>
      </div>

      {/* Quick summary chips */}
      <div className="flex flex-wrap gap-2">
        <Chip label="Licensed" value={licensed} total={users.length} />
        <Chip label="Blocked with licence" value={blockedWithLicence} total={users.length} warn={blockedWithLicence > 0} />
        <Chip label="Unused licence seats" value={wastedSeats} warn={wastedSeats > 0} />
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-text">Findings ({findings.length})</h3>
          {findings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}

      {/* Licence summary */}
      {licencesData.subscribedSkus.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-3">Licence Summary</h3>
          <div className="space-y-2">
            {licencesData.subscribedSkus
              .filter(s => s.prepaidUnits.enabled > 0)
              .sort((a, b) => (b.prepaidUnits.enabled - b.consumedUnits) - (a.prepaidUnits.enabled - a.consumedUnits))
              .map(sku => {
                const unused = sku.prepaidUnits.enabled - sku.consumedUnits;
                return (
                  <div key={sku.id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-[#162032] border border-[#1e3a5f]">
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-text truncate">{sku.skuPartNumber}</p>
                      <div className="mt-1 h-1 rounded-full bg-[#1e3a5f] overflow-hidden w-32">
                        <div className="h-full rounded-full bg-blue-400"
                          style={{ width: pct(sku.consumedUnits, sku.prepaidUnits.enabled) }} />
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <p className="text-xs font-mono text-text">
                        {sku.consumedUnits} / {sku.prepaidUnits.enabled}
                      </p>
                      {unused > 0 && (
                        <p className="text-[10px] text-yellow-400">{unused} unused</p>
                      )}
                    </div>
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {/* User table */}
      <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3 border-b border-[#1e3a5f]">
          <h3 className="text-sm font-semibold text-text">All Users ({users.length})</h3>
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
                {['User', 'Type', 'Status', 'Licences', 'Last sign-in', 'Created'].map(h => (
                  <th key={h} className="text-left px-4 py-2.5 text-[10px] uppercase tracking-wider text-muted font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e3a5f]/50">
              {users.slice(0, 50).map(u => {
                const ds = daysSince(u.signInActivity?.lastSignInDateTime);
                const isStale = ds !== null && ds > 90;
                return (
                  <tr key={u.id} className="hover:bg-[#162032] transition-colors">
                    <td className="px-4 py-2.5 font-mono text-text truncate max-w-[220px]">{u.userPrincipalName}</td>
                    <td className="px-4 py-2.5 text-muted capitalize">{u.userType === 'Guest' ? 'Guest' : 'Member'}</td>
                    <td className="px-4 py-2.5">
                      <span className={u.accountEnabled ? 'text-green-400' : 'text-red-400'}>
                        {u.accountEnabled ? 'Active' : 'Blocked'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-muted">{u.assignedLicenses?.length ?? 0}</td>
                    <td className={`px-4 py-2.5 ${isStale ? 'text-yellow-400' : 'text-muted'}`}>
                      {ds !== null ? `${ds}d ago` : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-muted">{formatDate(u.createdDateTime)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {users.length > 50 && (
            <p className="text-center text-xs text-muted py-3">
              Showing 50 of {users.length} users
            </p>
          )}
        </div>
      </div>

      {usersData.error && (
        <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-400">
          <strong>Collection error:</strong> {usersData.error}
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

function Chip({ label, value, total, warn = false }: { label: string; value: number; total?: number; warn?: boolean }) {
  return (
    <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs
      ${warn ? 'bg-yellow-400/10 border-yellow-400/20 text-yellow-400' : 'bg-[#162032] border-[#1e3a5f] text-muted'}`}>
      <span className="font-mono font-semibold">{value}</span>
      <span>{label}{total !== undefined ? ` (${pct(value, total)})` : ''}</span>
    </div>
  );
}
