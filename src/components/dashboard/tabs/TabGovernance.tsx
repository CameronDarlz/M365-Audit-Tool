import type { GroupsData, ExternalCollabData, Finding, CategoryScore } from '../../../types/audit';
import { FindingCard } from '../FindingCard';
import { ScoreRing } from '../ScoreRing';
import { CheckCircle2, XCircle, Users } from 'lucide-react';
import { cn } from '../../../lib/utils';

interface TabGovernanceProps {
  groupsData: GroupsData;
  externalCollabData: ExternalCollabData;
  score: CategoryScore;
  findings: Finding[];
}

const INVITE_LABELS: Record<string, { label: string; color: string }> = {
  everyone:                          { label: 'Anyone (including guests)', color: 'text-red-400'    },
  adminsAndGuestInviters:            { label: 'Admins and guest inviters', color: 'text-green-400'  },
  adminsGuestInvitersAndAllMembers:  { label: 'All members and admins',    color: 'text-yellow-400' },
  adminsOnly:                        { label: 'Admins only',               color: 'text-green-400'  },
  none:                              { label: 'No one',                    color: 'text-muted'      },
};

export function TabGovernance({ groupsData, externalCollabData, score, findings }: TabGovernanceProps) {
  const { lifecyclePolicies, settings, groups } = groupsData;
  const { authorizationPolicy } = externalCollabData;

  const m365Groups = groups.filter(g => g.groupTypes?.includes('Unified'));
  const teamsEnabled = m365Groups.filter(g => g.resourceProvisioningOptions?.includes('Team'));
  const publicGroups = m365Groups.filter(g => g.visibility === 'Public');
  const noOwner = m365Groups.filter(g => !g.owners || g.owners.length === 0);

  const groupCreationSetting = settings.find(s => s.values.some(v => v.name === 'EnableGroupCreation'));
  const groupCreationRestricted = groupCreationSetting
    ? groupCreationSetting.values.find(v => v.name === 'EnableGroupCreation')?.value === 'false'
    : false;

  const inviteFrom = authorizationPolicy?.allowInvitesFrom;
  const inviteCfg = INVITE_LABELS[inviteFrom ?? ''] ?? { label: inviteFrom ?? '—', color: 'text-muted' };

  const memberLikeGuestRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3';
  const guestAccessLevel =
    authorizationPolicy?.guestUserRoleId === memberLikeGuestRoleId ? 'Same as member (full)' :
    authorizationPolicy?.guestUserRoleId === 'bf39b29e-dbfc-431d-8b48-afd4d741d24c' ? 'Limited access' :
    authorizationPolicy?.guestUserRoleId === '10dae51f-b6af-4016-8d66-8c2a99b929b3' ? 'Very limited' : '—';

  return (
    <div className="p-6 space-y-6">
      {/* Score + stats */}
      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <ScoreRing score={score.score} grade={score.grade} label="Governance" size={100} strokeWidth={8} />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Stat label="M365 Groups"  value={m365Groups.length} />
          <Stat label="Teams"        value={teamsEnabled.length} />
          <Stat label="No owners"    value={noOwner.length} color={noOwner.length > 0 ? 'text-orange-400' : 'text-green-400'} />
          <Stat label="Public"       value={publicGroups.length} color={publicGroups.length > 10 ? 'text-yellow-400' : 'text-muted'} />
        </div>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-text">Findings ({findings.length})</h3>
          {findings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}

      {/* Policy checks */}
      <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <h3 className="text-sm font-semibold text-text mb-4">Governance Policy Checks</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <PolicyRow label="Group expiration policy"      pass={lifecyclePolicies.length > 0} />
          <PolicyRow label="Group creation restricted"    pass={groupCreationRestricted}       />
          <PolicyRow label="No groups without owners"     pass={noOwner.length === 0}          />
        </div>
      </div>

      {/* External collab settings */}
      {authorizationPolicy && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-4">External Collaboration Settings</h3>
          <div className="space-y-2">
            <Row label="Guest invite permissions" value={inviteCfg.label} valueColor={inviteCfg.color} />
            <Row label="Guest access level" value={guestAccessLevel} />
            <Row label="Email-verified users can join"
              value={authorizationPolicy.allowEmailVerifiedUsersToJoinOrganization ? 'Enabled' : 'Disabled'}
              valueColor={authorizationPolicy.allowEmailVerifiedUsersToJoinOrganization ? 'text-red-400' : 'text-green-400'}
            />
          </div>
        </div>
      )}

      {/* Group expiry policies */}
      {lifecyclePolicies.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-3">Group Expiration Policies</h3>
          {lifecyclePolicies.map(p => (
            <div key={p.id} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-[#162032] border border-[#1e3a5f]">
              <CheckCircle2 size={13} className="text-green-400" />
              <span className="text-sm text-text">{p.groupLifetimeInDays} day lifetime</span>
              <span className="text-xs text-muted ml-auto">{p.managedGroupTypes}</span>
            </div>
          ))}
        </div>
      )}

      {/* Groups list */}
      {m365Groups.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] overflow-hidden">
          <div className="px-5 py-3 border-b border-[#1e3a5f]">
            <h3 className="text-sm font-semibold text-text">Microsoft 365 Groups ({m365Groups.length})</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e3a5f]">
                  {['Group name', 'Visibility', 'Teams', 'Owners', 'Members'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-[10px] uppercase tracking-wider text-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e3a5f]/50">
                {m365Groups.slice(0, 50).map(g => (
                  <tr key={g.id} className="hover:bg-[#162032] transition-colors">
                    <td className="px-4 py-2.5 text-text">{g.displayName}</td>
                    <td className={cn('px-4 py-2.5 font-medium',
                      g.visibility === 'Public' ? 'text-yellow-400' : 'text-muted')}>
                      {g.visibility ?? '—'}
                    </td>
                    <td className="px-4 py-2.5 text-muted">
                      {g.resourceProvisioningOptions?.includes('Team') ? '✓' : '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      {(g.owners?.length ?? 0) === 0
                        ? <span className="text-orange-400">None</span>
                        : <span className="text-muted">{g.owners!.length}</span>}
                    </td>
                    <td className="px-4 py-2.5 text-muted font-mono">
                      <Users size={11} className="inline mr-1" />
                      {g.members?.length ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {m365Groups.length > 50 && (
              <p className="text-center text-xs text-muted py-3">Showing 50 of {m365Groups.length} groups</p>
            )}
          </div>
        </div>
      )}

      {(groupsData.error || externalCollabData.error) && (
        <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-400">
          <strong>Collection error:</strong> {groupsData.error ?? externalCollabData.error}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color = 'text-text' }: { label: string; value: number; color?: string }) {
  return (
    <div><p className={`text-2xl font-bold font-mono ${color}`}>{value}</p><p className="text-xs text-muted mt-0.5">{label}</p></div>
  );
}

function PolicyRow({ label, pass }: { label: string; pass: boolean }) {
  return (
    <div className={cn('flex items-center gap-2 px-3 py-2 rounded-lg border',
      pass ? 'bg-green-400/5 border-green-400/20' : 'bg-red-400/5 border-red-400/20')}>
      {pass ? <CheckCircle2 size={13} className="text-green-400" /> : <XCircle size={13} className="text-red-400" />}
      <span className="text-xs text-muted">{label}</span>
      <span className={cn('ml-auto text-xs font-medium', pass ? 'text-green-400' : 'text-red-400')}>{pass ? 'Yes' : 'No'}</span>
    </div>
  );
}

function Row({ label, value, valueColor = 'text-text' }: { label: string; value: string; valueColor?: string }) {
  return (
    <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#162032] border border-[#1e3a5f]">
      <span className="text-xs text-muted">{label}</span>
      <span className={cn('text-xs font-medium', valueColor)}>{value}</span>
    </div>
  );
}
