import type { RolesData, MfaData, UsersData, Finding, CategoryScore } from '../../../types/audit';
import { FindingCard } from '../FindingCard';
import { ScoreRing } from '../ScoreRing';
import { PRIVILEGED_ROLE_TEMPLATE_IDS } from '../../../engine/findings';
import { daysSince, downloadCsv } from '../../../lib/utils';
import { ShieldAlert, UserCheck, UserX, Download } from 'lucide-react';

interface TabPrivilegedProps {
  rolesData: RolesData;
  mfaData: MfaData;
  usersData: UsersData;
  score: CategoryScore;
  findings: Finding[];
}

export function TabPrivileged({ rolesData, mfaData, usersData, score, findings }: TabPrivilegedProps) {
  const { roleDefinitions, roleAssignments } = rolesData;

  const defById = new Map(roleDefinitions.map(d => [d.id, d]));
  const byTemplate = new Map<string, typeof roleAssignments>();
  for (const a of roleAssignments) {
    const tid = defById.get(a.roleDefinitionId)?.templateId ?? '';
    if (!byTemplate.has(tid)) byTemplate.set(tid, []);
    byTemplate.get(tid)!.push(a);
  }

  const mfaById = new Map(mfaData.registrationDetails.map(u => [u.id, u]));
  const userByUpn = new Map(usersData.users.map(u => [u.userPrincipalName?.toLowerCase(), u]));

  const privilegedAssignments = Object.entries(PRIVILEGED_ROLE_TEMPLATE_IDS)
    .map(([tid, roleName]) => ({
      roleName,
      tid,
      members: byTemplate.get(tid) ?? [],
    }))
    .filter(r => r.members.length > 0)
    .sort((a, b) => b.members.length - a.members.length);

  const allPrivilegedIds = new Set(
    [...byTemplate.entries()]
      .filter(([tid]) => PRIVILEGED_ROLE_TEMPLATE_IDS[tid])
      .flatMap(([, assigns]) => assigns.map(a => a.principalId)),
  );

  const adminsNoMfa = [...allPrivilegedIds].filter(id => {
    const detail = mfaById.get(id);
    return detail && !detail.isMfaRegistered;
  });

  const guestAdmins = [...byTemplate.values()].flat().filter(a =>
    a.principal?.userType === 'Guest' ||
    (a.principal?.userPrincipalName ?? '').includes('#EXT#'),
  );

  const globalAdminCount = (byTemplate.get('62e90394-69f5-4237-9190-012177145e10') ?? []).length;

  function exportCsv() {
    const rows = privilegedAssignments.flatMap(r =>
      r.members.map(a => ({
        Role: r.roleName,
        DisplayName: a.principal?.displayName ?? '',
        UPN: a.principal?.userPrincipalName ?? '',
        Type: a.principal?.userType ?? '',
        MFARegistered: mfaById.get(a.principalId)?.isMfaRegistered ?? 'unknown',
      })),
    );
    downloadCsv('privileged-roles.csv', rows);
  }

  return (
    <div className="p-6 space-y-6">
      {/* Score + stats */}
      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <ScoreRing score={score.score} grade={score.grade} label="Privileged Access" size={100} strokeWidth={8} />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Stat label="Global Admins"       value={globalAdminCount}     color={globalAdminCount > 5 ? 'text-red-400' : globalAdminCount >= 2 ? 'text-green-400' : 'text-yellow-400'} icon={ShieldAlert} />
          <Stat label="Privileged accounts" value={allPrivilegedIds.size} icon={UserCheck} />
          <Stat label="Admins without MFA"  value={adminsNoMfa.length}   color={adminsNoMfa.length > 0 ? 'text-red-400' : 'text-green-400'} icon={UserX} />
          <Stat label="Guest admins"         value={guestAdmins.length}  color={guestAdmins.length > 0 ? 'text-red-400' : 'text-green-400'} icon={UserX} />
        </div>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-text">Findings ({findings.length})</h3>
          {findings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}

      {/* Role membership table */}
      {privilegedAssignments.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-[#1e3a5f]">
            <h3 className="text-sm font-semibold text-text">
              Privileged Role Assignments ({roleAssignments.length})
            </h3>
            <button onClick={exportCsv}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs text-muted hover:text-text
                hover:bg-[#1e3a5f]/40 border border-transparent hover:border-[#1e3a5f] transition-colors">
              <Download size={12} /> Export CSV
            </button>
          </div>
          <div className="divide-y divide-[#1e3a5f]/50">
            {privilegedAssignments.map(role => (
              <div key={role.tid}>
                <div className="px-5 py-2.5 bg-[#162032] flex items-center justify-between">
                  <span className="text-xs font-semibold text-text">{role.roleName}</span>
                  <span className="text-xs font-mono text-muted">{role.members.length} member{role.members.length !== 1 ? 's' : ''}</span>
                </div>
                {role.members.map(a => {
                  const isGuest = a.principal?.userType === 'Guest' || (a.principal?.userPrincipalName ?? '').includes('#EXT#');
                  const mfa = mfaById.get(a.principalId);
                  const upn = (a.principal?.userPrincipalName ?? '').toLowerCase();
                  const user = userByUpn.get(upn);
                  const ds = daysSince(user?.signInActivity?.lastSignInDateTime);

                  return (
                    <div key={a.id} className="px-5 py-2.5 flex items-center gap-3 hover:bg-[#162032] transition-colors">
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-mono text-text truncate">
                          {a.principal?.userPrincipalName ?? a.principal?.displayName ?? a.principalId}
                        </p>
                        {isGuest && (
                          <span className="text-[10px] text-red-400 font-medium">GUEST</span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 flex-shrink-0 text-[11px]">
                        {mfa !== undefined && (
                          <span className={mfa.isMfaRegistered ? 'text-green-400' : 'text-red-400'}>
                            {mfa.isMfaRegistered ? 'MFA ✓' : 'No MFA'}
                          </span>
                        )}
                        {ds !== null && (
                          <span className={ds > 90 ? 'text-yellow-400' : 'text-muted'}>
                            {ds}d ago
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      )}

      {rolesData.error && (
        <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-400">
          <strong>Collection error:</strong> {rolesData.error}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color = 'text-text', icon: Icon }: {
  label: string; value: number; color?: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
}) {
  return (
    <div className="flex items-center gap-2">
      <Icon size={15} className="text-muted flex-shrink-0" />
      <div>
        <p className={`text-xl font-bold font-mono ${color}`}>{value}</p>
        <p className="text-[10px] text-muted leading-tight">{label}</p>
      </div>
    </div>
  );
}
