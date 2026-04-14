import {
  AuditResult,
  Finding,
  UserRegistrationDetail,
  ConditionalAccessPolicy,
  RoleAssignment,
  RoleDefinition,
  AppRegistration,
  User,
} from '../types/audit';

// ─── Known privileged role template IDs ──────────────────────────────────────
export const PRIVILEGED_ROLE_TEMPLATE_IDS: Record<string, string> = {
  '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator',
  'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator',
  '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator',
  '29232cdf-9323-42fd-aea2-88b2d4d9b1bd': 'Exchange Administrator',
  'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator',
  '69091246-20e8-4a56-aa4d-066075b2a7a8': 'Teams Administrator',
  'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator',
  'b0f54661-2d74-4c50-afa3-1ec803f12efe': 'Billing Administrator',
  '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': 'Application Administrator',
};

const GLOBAL_ADMIN_TEMPLATE_ID = '62e90394-69f5-4237-9190-012177145e10';

function cap(items: string[], max = 10): string[] {
  return items.slice(0, max);
}

function pct(n: number, total: number): string {
  if (total === 0) return '0%';
  return `${Math.round((n / total) * 100)}%`;
}

// ─── MFA Findings ─────────────────────────────────────────────────────────────

function mfaFindings(result: AuditResult, adminPrincipalIds: Set<string>): Finding[] {
  const findings: Finding[] = [];
  const details = result.mfa.registrationDetails;
  if (!details.length) return findings;

  const total = details.length;
  const notRegistered = details.filter(u => !u.isMfaRegistered);
  const mfaRate = (total - notRegistered.length) / total;

  if (mfaRate < 0.95) {
    const severity = mfaRate < 0.5 ? 'critical' : mfaRate < 0.8 ? 'high' : 'medium';
    findings.push({
      id: 'mfa-users-not-registered',
      severity,
      category: 'MFA & Authentication',
      title: `${notRegistered.length} user${notRegistered.length !== 1 ? 's' : ''} not registered for MFA`,
      description: `${pct(notRegistered.length, total)} of users (${notRegistered.length} of ${total}) have not registered any MFA method. These accounts are protected by password alone and cannot be covered by Conditional Access MFA enforcement policies.`,
      recommendation: 'Enable the MFA registration campaign in Entra ID to prompt all users to register at next sign-in. Set snooze to 0 days to enforce immediate registration.',
      affectedCount: notRegistered.length,
      affectedItems: cap(notRegistered.map(u => u.userPrincipalName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-registration-mfa-sspr-combined',
      effort: 'medium',
    });
  }

  // Admins without MFA
  const adminDetails = details.filter(u => adminPrincipalIds.has(u.id));
  const adminsNoMfa = adminDetails.filter(u => !u.isMfaRegistered);
  if (adminsNoMfa.length > 0) {
    findings.push({
      id: 'mfa-admin-no-mfa',
      severity: 'critical',
      category: 'MFA & Authentication',
      title: `${adminsNoMfa.length} admin account${adminsNoMfa.length !== 1 ? 's' : ''} without MFA`,
      description: `${adminsNoMfa.length} privileged account${adminsNoMfa.length !== 1 ? 's' : ''} hold${adminsNoMfa.length === 1 ? 's' : ''} administrative roles but have not registered MFA. A single stolen password grants full administrative control of this tenant.`,
      recommendation: 'Contact affected admins directly and have them register Microsoft Authenticator at aka.ms/mfasetup immediately. Enforce via a Conditional Access policy targeting admin roles.',
      affectedCount: adminsNoMfa.length,
      affectedItems: cap(adminsNoMfa.map(u => u.userPrincipalName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates',
      effort: 'medium',
    });
  }

  // Weak methods only (SMS/voice)
  const weakMethods = ['sms', 'voice'];
  const weakOnly = details.filter(u => {
    if (!u.isMfaRegistered) return false;
    return u.methodsRegistered.every(m => weakMethods.includes(m));
  });
  if (weakOnly.length > 0) {
    findings.push({
      id: 'mfa-weak-methods-only',
      severity: 'medium',
      category: 'MFA & Authentication',
      title: `${weakOnly.length} user${weakOnly.length !== 1 ? 's' : ''} using only SMS or voice MFA`,
      description: `${weakOnly.length} user${weakOnly.length !== 1 ? 's' : ''} ${weakOnly.length === 1 ? 'has' : 'have'} registered only SMS or voice call as MFA methods. These can be bypassed via SIM-swapping attacks and do not provide phishing-resistant authentication.`,
      recommendation: 'Enable Microsoft Authenticator with number matching and additional context. Run a targeted registration campaign for these users.',
      affectedCount: weakOnly.length,
      affectedItems: cap(weakOnly.map(u => u.userPrincipalName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods',
      effort: 'medium',
    });
  }

  // Auth methods policy checks
  const policy = result.mfa.authMethodsPolicy;
  if (policy) {
    const fido2 = policy.authenticationMethodConfigurations.find(c => c.id === 'Fido2');
    if (!fido2 || fido2.state === 'disabled') {
      findings.push({
        id: 'mfa-no-fido2',
        severity: 'low',
        category: 'MFA & Authentication',
        title: 'FIDO2 security keys not enabled',
        description: 'FIDO2 security keys are not enabled as an authentication method. They provide phishing-resistant MFA and are the strongest available method for high-privilege accounts.',
        recommendation: 'Enable FIDO2 security keys in Authentication Methods policies and issue them to all Global Administrators and Privileged Role Administrators.',
        learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key',
        effort: 'project',
      });
    }

    const smsConfig = policy.authenticationMethodConfigurations.find(c => c.id === 'Sms');
    if (smsConfig?.state === 'enabled' && (smsConfig as { smsSignInState?: string }).smsSignInState === 'enabled') {
      findings.push({
        id: 'mfa-sms-signin-enabled',
        severity: 'medium',
        category: 'MFA & Authentication',
        title: 'SMS sign-in (passwordless SMS) is enabled',
        description: 'SMS sign-in allows users to authenticate with only a phone number and SMS code, with no password required. This is a weak authentication flow.',
        recommendation: 'Disable SMS sign-in in Authentication Methods → SMS policies unless specifically required.',
        learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-sms-signin',
        effort: 'quick-win',
      });
    }

    const authenticatorConfig = policy.authenticationMethodConfigurations.find(c => c.id === 'MicrosoftAuthenticator');
    if (authenticatorConfig?.state === 'enabled') {
      const numberMatchState = authenticatorConfig.featureSettings?.numberMatchingRequiredState?.state;
      if (numberMatchState && numberMatchState !== 'enabled') {
        findings.push({
          id: 'mfa-no-number-matching',
          severity: 'medium',
          category: 'MFA & Authentication',
          title: 'Number matching not enforced on Authenticator push notifications',
          description: 'Number matching is not enforced on Microsoft Authenticator push notifications. Without it, users may approve MFA prompts they did not initiate (MFA fatigue / push bombing attacks).',
          recommendation: 'Enable number matching in Authentication Methods → Microsoft Authenticator → Configure → Number matching.',
          learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match',
          effort: 'quick-win',
        });
      }
    }
  }

  return findings;
}

// ─── Conditional Access Findings ─────────────────────────────────────────────

function caFindings(result: AuditResult): Finding[] {
  const findings: Finding[] = [];
  const policies = result.conditionalAccess.policies;
  const enabled = policies.filter(p => p.state === 'enabled');

  if (enabled.length === 0) {
    findings.push({
      id: 'ca-no-policies',
      severity: 'critical',
      category: 'Conditional Access',
      title: 'No Conditional Access policies are enabled',
      description: 'This tenant has no enforced Conditional Access policies. Every user can sign in from any device, location, or application with only a password. MFA, device compliance, and risk-based controls are completely absent.',
      recommendation: 'Create baseline Conditional Access policies: require MFA for all users, block legacy authentication, and target admin roles with stricter controls.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa',
      effort: 'medium',
    });
    return findings; // No point listing sub-findings if there are no policies at all
  }

  const hasMfaPolicy = enabled.some(p =>
    p.grantControls?.builtInControls.includes('mfa'),
  );
  if (!hasMfaPolicy) {
    findings.push({
      id: 'ca-no-mfa-policy',
      severity: 'high',
      category: 'Conditional Access',
      title: 'No Conditional Access policy enforces MFA',
      description: `${enabled.length} Conditional Access ${enabled.length === 1 ? 'policy is' : 'policies are'} enabled but none require multifactor authentication. Users who have not self-registered MFA can still sign in with only a password.`,
      recommendation: 'Create a Conditional Access policy targeting all users on all cloud apps with a grant control of Require multifactor authentication.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa',
      effort: 'medium',
    });
  }

  const hasLegacyBlock = enabled.some(p =>
    (p.conditions.clientAppTypes?.includes('exchangeActiveSync') ||
      p.conditions.clientAppTypes?.includes('other')) &&
    p.grantControls?.builtInControls.includes('block'),
  );
  if (!hasLegacyBlock) {
    findings.push({
      id: 'ca-no-legacy-block',
      severity: 'high',
      category: 'Conditional Access',
      title: 'Legacy authentication protocols are not blocked',
      description: 'No Conditional Access policy blocks legacy authentication (Basic Auth, IMAP, POP3, SMTP Auth). These protocols cannot process MFA challenges, meaning any account using them bypasses all MFA controls.',
      recommendation: 'Create a Conditional Access policy targeting Exchange ActiveSync clients and Other clients with a Block grant control.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication',
      effort: 'quick-win',
    });
  }

  const hasAdminPolicy = enabled.some(p =>
    (p.conditions.users?.includeRoles?.length ?? 0) > 0,
  );
  if (!hasAdminPolicy) {
    findings.push({
      id: 'ca-no-admin-policy',
      severity: 'high',
      category: 'Conditional Access',
      title: 'No Conditional Access policy targets admin roles',
      description: 'No enabled Conditional Access policy specifically targets privileged directory roles. Admin accounts should be subject to stricter controls than standard users.',
      recommendation: 'Create a dedicated Conditional Access policy targeting Global Administrator, Privileged Role Administrator, Security Administrator, and other key roles with MFA and optionally compliant device requirements.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa',
      effort: 'medium',
    });
  }

  const hasRiskPolicy = enabled.some(p =>
    (p.conditions.userRiskLevels?.length ?? 0) > 0 ||
    (p.conditions.signInRiskLevels?.length ?? 0) > 0,
  );
  if (!hasRiskPolicy) {
    findings.push({
      id: 'ca-no-risk-policy',
      severity: 'medium',
      category: 'Conditional Access',
      title: 'No risk-based Conditional Access policies configured',
      description: 'No Conditional Access policies use user risk or sign-in risk conditions. Risk-based policies automatically challenge or block sign-ins flagged as suspicious by Entra ID Identity Protection.',
      recommendation: 'Create risk-based policies requiring password change for high user risk, and MFA for medium/high sign-in risk. Requires Entra ID P2 licences.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies',
      effort: 'project',
    });
  }

  const namedLocations = result.conditionalAccess.namedLocations;
  if (namedLocations.length === 0) {
    findings.push({
      id: 'ca-no-named-locations',
      severity: 'low',
      category: 'Conditional Access',
      title: 'No named locations configured',
      description: 'No named locations (trusted IP ranges or countries) are defined. Named locations enable location-based Conditional Access conditions such as blocking sign-ins from high-risk countries.',
      recommendation: 'Define named locations for office IP ranges and trusted networks in Entra ID → Protection → Conditional Access → Named locations.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/location-condition',
      effort: 'quick-win',
    });
  }

  const reportOnlyCount = policies.filter(p => p.state === 'enabledForReportingButNotEnforced').length;
  if (reportOnlyCount > 0 && enabled.length === 0) {
    findings.push({
      id: 'ca-report-only',
      severity: 'medium',
      category: 'Conditional Access',
      title: `${reportOnlyCount} Conditional Access ${reportOnlyCount === 1 ? 'policy is' : 'policies are'} in report-only mode`,
      description: `${reportOnlyCount} ${reportOnlyCount === 1 ? 'policy exists' : 'policies exist'} in report-only mode and are not enforced. Users are not being challenged by these controls.`,
      recommendation: 'Review the sign-in logs under report-only mode to confirm no legitimate users would be blocked, then switch policies to Enabled.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only',
      effort: 'quick-win',
    });
  }

  return findings;
}

// ─── User Hygiene Findings ────────────────────────────────────────────────────

function userFindings(result: AuditResult): Finding[] {
  const findings: Finding[] = [];
  const users = result.users.users;
  const now = new Date();

  const blockedWithLicence = users.filter(
    u => !u.accountEnabled && (u.assignedLicenses?.length ?? 0) > 0,
  );
  if (blockedWithLicence.length > 0) {
    findings.push({
      id: 'users-blocked-with-licence',
      severity: 'medium',
      category: 'Users & Accounts',
      title: `${blockedWithLicence.length} blocked account${blockedWithLicence.length !== 1 ? 's' : ''} retaining active licences`,
      description: `${blockedWithLicence.length} disabled account${blockedWithLicence.length !== 1 ? 's are' : ' is'} still consuming paid licences. These accounts cannot sign in but are wasting licence spend and may retain delegated mailbox or group access.`,
      recommendation: 'Remove all licence assignments from blocked accounts in the Microsoft 365 admin centre. Reclaim the freed licences or reduce the count at next renewal.',
      affectedCount: blockedWithLicence.length,
      affectedItems: cap(blockedWithLicence.map(u => u.userPrincipalName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/microsoft-365/admin/manage/remove-licenses-from-users',
      effort: 'quick-win',
    });
  }

  const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
  const staleAccounts = users.filter(u => {
    if (!u.accountEnabled) return false;
    if (u.userType === 'Guest') return false;
    if (!u.assignedLicenses?.length) return false;
    const last = u.signInActivity?.lastSignInDateTime;
    if (!last) return false;
    return new Date(last) < ninetyDaysAgo;
  });
  if (staleAccounts.length > 0) {
    const severity = staleAccounts.length > 20 ? 'high' : 'medium';
    findings.push({
      id: 'users-stale-accounts',
      severity,
      category: 'Users & Accounts',
      title: `${staleAccounts.length} active licensed account${staleAccounts.length !== 1 ? 's' : ''} inactive for 90+ days`,
      description: `${staleAccounts.length} enabled, licensed account${staleAccounts.length !== 1 ? 's have' : ' has'} not signed in for over 90 days. These likely belong to former employees or unused service accounts and represent unnecessary attack surface and licence cost.`,
      recommendation: 'Cross-reference with HR to confirm leavers. Disable confirmed leaver accounts immediately, remove licences, and delete after 30 days. Investigate unconfirmed accounts with managers.',
      affectedCount: staleAccounts.length,
      affectedItems: cap(staleAccounts.map(u => u.userPrincipalName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts',
      effort: 'medium',
    });
  }

  const guestUsers = users.filter(u => u.userType === 'Guest');
  if (guestUsers.length > 20) {
    findings.push({
      id: 'users-excess-guests',
      severity: 'low',
      category: 'Users & Accounts',
      title: `${guestUsers.length} guest accounts in directory`,
      description: `The tenant has ${guestUsers.length} guest (external) accounts. A large guest population increases exposure if any guest account is compromised and can complicate governance and data access reviews.`,
      recommendation: 'Conduct a periodic guest access review. Remove guests who no longer require access. Consider enabling access reviews in Entra ID Governance.',
      affectedCount: guestUsers.length,
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions',
      effort: 'medium',
    });
  }

  const passwordNeverExpire = users.filter(u =>
    u.passwordPolicies?.includes('DisablePasswordExpiration'),
  );
  const pwNeverExpireRate = users.length > 0 ? passwordNeverExpire.length / users.length : 0;
  if (pwNeverExpireRate > 0.1 && passwordNeverExpire.length > 10) {
    findings.push({
      id: 'users-password-never-expires',
      severity: 'low',
      category: 'Users & Accounts',
      title: `${passwordNeverExpire.length} accounts have passwords set to never expire`,
      description: `${pct(passwordNeverExpire.length, users.length)} of accounts (${passwordNeverExpire.length}) have the DisablePasswordExpiration policy set. While acceptable for cloud-only accounts using MFA, this should be reviewed for any accounts not protected by MFA.`,
      recommendation: 'Ensure all accounts with non-expiring passwords are protected by MFA via Conditional Access. Cross-reference with MFA registration data.',
      affectedCount: passwordNeverExpire.length,
      learnMoreUrl: 'https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations',
      effort: 'quick-win',
    });
  }

  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const neverSignedIn = users.filter(u => {
    if (!u.accountEnabled) return false;
    const created = new Date(u.createdDateTime);
    if (created > thirtyDaysAgo) return false;
    const last = u.signInActivity?.lastSignInDateTime;
    return !last;
  });
  if (neverSignedIn.length > 0) {
    findings.push({
      id: 'users-never-signed-in',
      severity: 'low',
      category: 'Users & Accounts',
      title: `${neverSignedIn.length} account${neverSignedIn.length !== 1 ? 's' : ''} created 30+ days ago and never signed in`,
      description: `${neverSignedIn.length} account${neverSignedIn.length !== 1 ? 's were' : ' was'} created more than 30 days ago but ${neverSignedIn.length === 1 ? 'has' : 'have'} never been used. These may be orphaned provisioning artefacts or accounts created in error.`,
      recommendation: 'Review and disable or delete accounts that were never used. Investigate the provisioning process that created them.',
      affectedCount: neverSignedIn.length,
      affectedItems: cap(neverSignedIn.map(u => u.userPrincipalName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts',
      effort: 'quick-win',
    });
  }

  return findings;
}

// ─── Privileged Role Findings ─────────────────────────────────────────────────

function rolesFindings(
  result: AuditResult,
  adminPrincipalIds: Set<string>,
): Finding[] {
  const findings: Finding[] = [];
  const { roleDefinitions, roleAssignments } = result.roles;
  const now = new Date();
  const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);

  const defById = new Map<string, RoleDefinition>();
  for (const d of roleDefinitions) defById.set(d.id, d);

  const byTemplate = new Map<string, RoleAssignment[]>();
  for (const a of roleAssignments) {
    const def = defById.get(a.roleDefinitionId);
    const tid = def?.templateId ?? '';
    if (!byTemplate.has(tid)) byTemplate.set(tid, []);
    byTemplate.get(tid)!.push(a);
  }

  const globalAdmins = byTemplate.get(GLOBAL_ADMIN_TEMPLATE_ID) ?? [];
  const gaCount = globalAdmins.length;

  if (gaCount === 0) {
    findings.push({
      id: 'roles-no-global-admin',
      severity: 'critical',
      category: 'Privileged Access',
      title: 'No Global Administrator found',
      description: 'No active Global Administrator assignment was detected. This may indicate a data collection permission issue, but if accurate, the tenant has no emergency admin access.',
      recommendation: 'Verify Global Admin assignments in Entra ID. Ensure at least 2 break-glass Global Admin accounts exist.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access',
      effort: 'medium',
    });
  } else if (gaCount === 1) {
    findings.push({
      id: 'roles-single-global-admin',
      severity: 'high',
      category: 'Privileged Access',
      title: 'Only one Global Administrator account exists',
      description: 'A single Global Administrator is a lockout risk. If that account is compromised, inaccessible, or loses MFA access, tenant recovery requires contacting Microsoft Support.',
      recommendation: 'Create a dedicated break-glass emergency access account and assign Global Administrator. Store credentials offline. Exclude from all Conditional Access policies.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access',
      effort: 'medium',
    });
  } else if (gaCount > 5) {
    findings.push({
      id: 'roles-excess-global-admins',
      severity: 'high',
      category: 'Privileged Access',
      title: `${gaCount} Global Administrators — exceeds recommended maximum`,
      description: `This tenant has ${gaCount} Global Administrator accounts. Each is a potential full-tenant compromise vector. The recommended maximum is 4.`,
      recommendation: 'Review each Global Admin assignment. Reassign to the minimum required role. Retain 2–4 Global Admins maximum.',
      affectedCount: gaCount,
      affectedItems: cap(globalAdmins.map(a => a.principal?.userPrincipalName ?? a.principal?.displayName ?? a.principalId)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices',
      effort: 'medium',
    });
  }

  const guestAdmins: string[] = [];
  for (const assignments of byTemplate.values()) {
    for (const a of assignments) {
      if (
        a.principal?.userType === 'Guest' ||
        (a.principal?.userPrincipalName ?? '').includes('#EXT#')
      ) {
        guestAdmins.push(a.principal?.userPrincipalName ?? a.principal?.displayName ?? a.principalId);
      }
    }
  }
  if (guestAdmins.length > 0) {
    findings.push({
      id: 'roles-guest-in-admin-role',
      severity: 'critical',
      category: 'Privileged Access',
      title: `${guestAdmins.length} guest account${guestAdmins.length !== 1 ? 's' : ''} holding privileged roles`,
      description: `${guestAdmins.length} external guest account${guestAdmins.length !== 1 ? 's hold' : ' holds'} administrative role assignments. Guest accounts cannot be subject to your internal MFA or Conditional Access policies.`,
      recommendation: 'Remove guest accounts from all admin roles immediately. Provision a member account under your domain if external admin access is required.',
      affectedCount: guestAdmins.length,
      affectedItems: cap(guestAdmins),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices',
      effort: 'quick-win',
    });
  }

  const users = result.users.users;
  const userByUpn = new Map<string, User>();
  for (const u of users) userByUpn.set((u.userPrincipalName ?? '').toLowerCase(), u);

  const staleAdminUpns: string[] = [];
  for (const assignments of byTemplate.values()) {
    for (const a of assignments) {
      const upn = (a.principal?.userPrincipalName ?? '').toLowerCase();
      const user = userByUpn.get(upn);
      if (!user) continue;
      const last = user.signInActivity?.lastSignInDateTime;
      if (last && new Date(last) < ninetyDaysAgo) {
        staleAdminUpns.push(a.principal?.userPrincipalName ?? a.principalId);
      }
    }
  }
  const uniqueStaleAdmins = [...new Set(staleAdminUpns)];
  if (uniqueStaleAdmins.length > 0) {
    findings.push({
      id: 'roles-stale-admins',
      severity: 'high',
      category: 'Privileged Access',
      title: `${uniqueStaleAdmins.length} admin account${uniqueStaleAdmins.length !== 1 ? 's' : ''} inactive for 90+ days`,
      description: `${uniqueStaleAdmins.length} account${uniqueStaleAdmins.length !== 1 ? 's hold' : ' holds'} privileged role assignments but ${uniqueStaleAdmins.length === 1 ? 'has' : 'have'} not signed in for over 90 days.`,
      recommendation: 'Investigate each stale admin account. Remove role assignments from accounts that are no longer needed.',
      affectedCount: uniqueStaleAdmins.length,
      affectedItems: cap(uniqueStaleAdmins),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices',
      effort: 'medium',
    });
  }

  const privRoleAdmins = byTemplate.get('e8611ab8-c189-46e8-94e1-60213ab1f814') ?? [];
  if (privRoleAdmins.length > 2) {
    findings.push({
      id: 'roles-excess-pra',
      severity: 'medium',
      category: 'Privileged Access',
      title: `${privRoleAdmins.length} Privileged Role Administrators`,
      description: `${privRoleAdmins.length} accounts hold Privileged Role Administrator, which can assign any role including Global Administrator. Recommended maximum is 2.`,
      recommendation: 'Reduce Privileged Role Administrator assignments to 2 or fewer.',
      affectedCount: privRoleAdmins.length,
      affectedItems: cap(privRoleAdmins.map(a => a.principal?.userPrincipalName ?? a.principal?.displayName ?? a.principalId)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices',
      effort: 'medium',
    });
  }

  return findings;
}

// ─── Application Findings ─────────────────────────────────────────────────────

function appFindings(result: AuditResult): Finding[] {
  const findings: Finding[] = [];
  const { appRegistrations } = result.applications;
  const now = new Date();
  const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  const ninetyDaysFromNow = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
  const oneYearAgo = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);

  const noOwners = appRegistrations.filter(a => !a.owners || a.owners.length === 0);
  if (noOwners.length > 0) {
    findings.push({
      id: 'apps-no-owners',
      severity: 'medium',
      category: 'Applications',
      title: `${noOwners.length} app registration${noOwners.length !== 1 ? 's' : ''} with no owners`,
      description: `${noOwners.length} app registration${noOwners.length !== 1 ? 's have' : ' has'} no assigned owner. Ownerless apps have no accountable person to rotate credentials or decommission the app.`,
      recommendation: 'Assign at least one owner to each app registration.',
      affectedCount: noOwners.length,
      affectedItems: cap(noOwners.map(a => a.displayName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps',
      effort: 'quick-win',
    });
  }

  const expiredApps: AppRegistration[] = [];
  const expiringThirtyApps: AppRegistration[] = [];
  const expiringSoonApps: AppRegistration[] = [];
  const oldSecretApps: AppRegistration[] = [];

  for (const app of appRegistrations) {
    let hasExpired = false, hasThirty = false, hasSoon = false, hasOld = false;
    for (const secret of app.passwordCredentials) {
      if (!secret.endDateTime) continue;
      const end = new Date(secret.endDateTime);
      if (end < now) hasExpired = true;
      else if (end <= thirtyDaysFromNow) hasThirty = true;
      else if (end <= ninetyDaysFromNow) hasSoon = true;
      if (secret.startDateTime && new Date(secret.startDateTime) < oneYearAgo) hasOld = true;
    }
    if (hasExpired) expiredApps.push(app);
    else if (hasThirty) expiringThirtyApps.push(app);
    else if (hasSoon) expiringSoonApps.push(app);
    if (hasOld) oldSecretApps.push(app);
  }

  if (expiredApps.length > 0) {
    findings.push({
      id: 'apps-expired-secrets',
      severity: 'critical',
      category: 'Applications',
      title: `${expiredApps.length} app${expiredApps.length !== 1 ? 's' : ''} with expired client secrets`,
      description: `${expiredApps.length} app registration${expiredApps.length !== 1 ? 's have' : ' has'} expired client secrets. These applications are likely experiencing authentication failures.`,
      recommendation: 'Immediately create new client secrets, update application configuration, verify auth, then delete the expired secrets.',
      affectedCount: expiredApps.length,
      affectedItems: cap(expiredApps.map(a => a.displayName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal',
      effort: 'medium',
    });
  }

  if (expiringThirtyApps.length > 0) {
    findings.push({
      id: 'apps-expiring-secrets',
      severity: 'high',
      category: 'Applications',
      title: `${expiringThirtyApps.length} app${expiringThirtyApps.length !== 1 ? 's' : ''} with secrets expiring within 30 days`,
      description: `${expiringThirtyApps.length} app registration${expiringThirtyApps.length !== 1 ? 's have' : ' has'} client secrets expiring within 30 days. Failure to rotate will cause application outages.`,
      recommendation: 'Rotate client secrets now. Create new secret, update app config, verify, then delete old secret.',
      affectedCount: expiringThirtyApps.length,
      affectedItems: cap(expiringThirtyApps.map(a => a.displayName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal',
      effort: 'medium',
    });
  }

  if (expiringSoonApps.length > 0) {
    findings.push({
      id: 'apps-expiring-secrets-90d',
      severity: 'medium',
      category: 'Applications',
      title: `${expiringSoonApps.length} app${expiringSoonApps.length !== 1 ? 's' : ''} with secrets expiring within 90 days`,
      description: `${expiringSoonApps.length} app registration${expiringSoonApps.length !== 1 ? 's have' : ' has'} client secrets expiring within 90 days.`,
      recommendation: 'Schedule secret rotation for each affected application.',
      affectedCount: expiringSoonApps.length,
      affectedItems: cap(expiringSoonApps.map(a => a.displayName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal',
      effort: 'medium',
    });
  }

  if (oldSecretApps.length > 0) {
    findings.push({
      id: 'apps-old-secrets',
      severity: 'low',
      category: 'Applications',
      title: `${oldSecretApps.length} app${oldSecretApps.length !== 1 ? 's' : ''} with secrets not rotated in 1+ year`,
      description: `${oldSecretApps.length} app registration${oldSecretApps.length !== 1 ? 's have' : ' has'} client secrets older than 365 days.`,
      recommendation: 'Rotate secrets and establish a maximum 12-month rotation policy. Consider certificate-based auth.',
      affectedCount: oldSecretApps.length,
      affectedItems: cap(oldSecretApps.map(a => a.displayName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal',
      effort: 'medium',
    });
  }

  return findings;
}

// ─── Device Findings ──────────────────────────────────────────────────────────

function deviceFindings(result: AuditResult): Finding[] {
  const findings: Finding[] = [];
  const { managedDevices, compliancePolicies } = result.devices;
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  if (managedDevices.length === 0) {
    findings.push({
      id: 'devices-no-enrolment',
      severity: 'high',
      category: 'Device Compliance',
      title: 'No devices enrolled in Intune',
      description: 'No managed devices found in Intune. Without device management, Conditional Access cannot enforce device compliance and security baselines cannot be applied.',
      recommendation: 'Begin an Intune device enrolment project starting with a Windows pilot group.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/mem/intune/enrollment/device-enrollment',
      effort: 'project',
    });
    return findings;
  }

  if (compliancePolicies.length === 0) {
    findings.push({
      id: 'devices-no-compliance-policy',
      severity: 'high',
      category: 'Device Compliance',
      title: 'No device compliance policies configured',
      description: `${managedDevices.length} device${managedDevices.length !== 1 ? 's are' : ' is'} enrolled in Intune but no compliance policies exist. All devices default to compliant.`,
      recommendation: 'Create compliance policies for each platform in Intune defining minimum OS version, encryption, and screen lock requirements.',
      learnMoreUrl: 'https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started',
      effort: 'medium',
    });
  }

  const nonCompliant = managedDevices.filter(d => d.complianceState === 'noncompliant');
  const nonCompliantRate = nonCompliant.length / managedDevices.length;
  if (nonCompliant.length > 0 && nonCompliantRate > 0.1) {
    findings.push({
      id: 'devices-high-noncompliance',
      severity: nonCompliantRate > 0.25 ? 'high' : 'medium',
      category: 'Device Compliance',
      title: `${nonCompliant.length} non-compliant device${nonCompliant.length !== 1 ? 's' : ''} (${pct(nonCompliant.length, managedDevices.length)})`,
      description: `${pct(nonCompliant.length, managedDevices.length)} of enrolled devices are non-compliant. If Conditional Access requires device compliance, these users may be blocked.`,
      recommendation: 'Review each non-compliant device. Remediate OS updates, encryption, and screen lock issues.',
      affectedCount: nonCompliant.length,
      affectedItems: cap(nonCompliant.map(d => d.deviceName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started',
      effort: 'medium',
    });
  }

  const staleDevices = managedDevices.filter(d => new Date(d.lastSyncDateTime) < thirtyDaysAgo);
  if (staleDevices.length > 0) {
    findings.push({
      id: 'devices-stale-sync',
      severity: 'low',
      category: 'Device Compliance',
      title: `${staleDevices.length} device${staleDevices.length !== 1 ? 's' : ''} not synced in 30+ days`,
      description: `${staleDevices.length} enrolled device${staleDevices.length !== 1 ? 's have' : ' has'} not checked in with Intune for over 30 days. Their compliance state may be stale.`,
      recommendation: 'Retire devices no longer in use. Troubleshoot the Intune management agent on active devices.',
      affectedCount: staleDevices.length,
      affectedItems: cap(staleDevices.map(d => d.deviceName)),
      learnMoreUrl: 'https://learn.microsoft.com/en-us/mem/intune/remote-actions/devices-wipe',
      effort: 'medium',
    });
  }

  return findings;
}
