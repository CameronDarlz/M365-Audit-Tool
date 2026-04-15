import { useState, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useMsal } from '@azure/msal-react';
import { type AccountInfo } from '@azure/msal-browser';
import { runAudit } from '../api/runAudit';
import { generateFindings } from '../engine/findings';
import { computeScores, computeOverallScore, getGrade } from '../engine/scoring';
import { buildAdminPrincipalIds } from '../engine/findings';
import type { AuditResult, CollectorState, ScoredAudit } from '../types/audit';

const AUDIT_KEY = 'tenantAudit';

export function useAudit(account: AccountInfo | null) {
  const { instance } = useMsal();
  const queryClient = useQueryClient();
  const [collectorStates, setCollectorStates] = useState<CollectorState[]>([]);

  const runAuditFn = useCallback(async (): Promise<ScoredAudit> => {
    if (!account) throw new Error('No account');

    const result: AuditResult = await runAudit(
      instance,
      account,
      (states) => setCollectorStates(states),
    );

    const adminIds = buildAdminPrincipalIds(result);

    // Gather privileged access stats for scoring
    const globalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10';
    const defById = new Map(result.roles.roleDefinitions.map(d => [d.id, d]));
    const byTemplate = new Map<string, typeof result.roles.roleAssignments>();
    for (const a of result.roles.roleAssignments) {
      const tid = defById.get(a.roleDefinitionId)?.templateId ?? '';
      if (!byTemplate.has(tid)) byTemplate.set(tid, []);
      byTemplate.get(tid)!.push(a);
    }

    const globalAdmins = byTemplate.get(globalAdminTemplateId) ?? [];
    const guestAdmins = [...byTemplate.values()].flat().filter(a =>
      a.principal?.userType === 'Guest' ||
      (a.principal?.userPrincipalName ?? '').includes('#EXT#'),
    ).length;

    const now = new Date();
    const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
    const userByUpn = new Map(result.users.users.map(u => [u.userPrincipalName?.toLowerCase(), u]));

    const staleAdminUpns = new Set<string>();
    for (const assignments of byTemplate.values()) {
      for (const a of assignments) {
        const upn = (a.principal?.userPrincipalName ?? '').toLowerCase();
        const user = userByUpn.get(upn);
        if (!user) continue;
        const last = user.signInActivity?.lastSignInDateTime;
        if (last && new Date(last) < ninetyDaysAgo) staleAdminUpns.add(upn);
      }
    }

    const mfaDetails = result.mfa.registrationDetails;
    const adminsWithoutMfa = [...adminIds].filter(id => {
      const detail = mfaDetails.find(d => d.id === id);
      return detail && !detail.isMfaRegistered;
    }).length;

    const scores = computeScores(
      result,
      adminIds,
      globalAdmins.length,
      guestAdmins,
      staleAdminUpns.size,
      adminsWithoutMfa,
      adminIds.size,
    );

    const overallScore = computeOverallScore(scores);
    const overallGrade = getGrade(overallScore);
    const findings = generateFindings(result);

    return { result, scores, overallScore, overallGrade, findings };
  }, [instance, account]);

  const query = useQuery<ScoredAudit, Error>({
    queryKey: [AUDIT_KEY, account?.homeAccountId],
    queryFn: runAuditFn,
    enabled: false,
    retry: false,
    staleTime: Infinity,
  });

  const startAudit = useCallback(() => {
    setCollectorStates([]);
    queryClient.removeQueries({ queryKey: [AUDIT_KEY, account?.homeAccountId] });
    query.refetch();
  }, [queryClient, account, query]);

  return {
    audit: query.data ?? null,
    isRunning: query.isFetching,
    isDone: query.isSuccess,
    error: query.error?.message ?? null,
    collectorStates,
    startAudit,
  };
}
