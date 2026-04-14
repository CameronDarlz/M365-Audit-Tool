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
