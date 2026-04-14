import { CategoryScore, AuditResult, UserRegistrationDetail, ConditionalAccessPolicy } from '../types/audit';

export const CATEGORY_WEIGHTS: Record<string, number> = {
  mfa: 0.22,
  conditionalAccess: 0.20,
  privilegedAccess: 0.18,
  identityProtection: 0.10,
  applications: 0.08,
  devices: 0.07,
  emailSecurity: 0.07,
  userHygiene: 0.05,
  governance: 0.03,
};

export function getGrade(score: number): CategoryScore['grade'] {
  if (score >= 80) return 'good';
  if (score >= 60) return 'fair';
  if (score >= 40) return 'poor';
  return 'critical';
}

export function clamp(val: number, min = 0, max = 100): number {
  return Math.max(min, Math.min(max, val));
}

// ─── MFA Score ────────────────────────────────────────────────────────────────

export function scoreMfa(
  registrationDetails: UserRegistrationDetail[],
  adminIds: Set<string>,
): { score: number; mfaRate: number; adminMfaRate: number; strongMethodRate: number } {
  const licensedMembers = registrationDetails.filter(u => !u.isAdmin || adminIds.has(u.id));
  const total = registrationDetails.length;
  if (total === 0) return { score: 0, mfaRate: 0, adminMfaRate: 0, strongMethodRate: 0 };

  const mfaRegistered = registrationDetails.filter(u => u.isMfaRegistered).length;
  const mfaRate = total > 0 ? mfaRegistered / total : 0;

  const admins = registrationDetails.filter(u => adminIds.has(u.id));
  const adminMfaCount = admins.filter(u => u.isMfaRegistered).length;
  const adminMfaRate = admins.length > 0 ? adminMfaCount / admins.length : 1;

  const weakMethods = ['sms', 'voice', 'softwareOneTimePasscode'];
  const strongUsers = registrationDetails.filter(u => {
    if (!u.isMfaRegistered) return false;
    return u.methodsRegistered.some(m => !weakMethods.includes(m));
  }).length;
  const strongMethodRate = mfaRegistered > 0 ? strongUsers / mfaRegistered : 0;

  const score = clamp(Math.round(mfaRate * 60 + adminMfaRate * 25 + strongMethodRate * 15));

  return { score, mfaRate, adminMfaRate, strongMethodRate };
}

// ─── Conditional Access Score ─────────────────────────────────────────────────

export function scoreConditionalAccess(policies: ConditionalAccessPolicy[]): number {
  const enabled = policies.filter(p => p.state === 'enabled');
  if (enabled.length === 0) return 0;

  let score = 0;
  score += 20; // Has at least one enabled policy

  const hasMfaPolicy = enabled.some(p =>
    p.grantControls?.builtInControls.includes('mfa'),
  );
  if (hasMfaPolicy) score += 30;

  const hasLegacyBlock = enabled.some(p =>
    (p.conditions.clientAppTypes?.includes('exchangeActiveSync') ||
      p.conditions.clientAppTypes?.includes('other')) &&
    p.grantControls?.builtInControls.includes('block'),
  );
  if (hasLegacyBlock) score += 25;

  const hasRiskPolicy = enabled.some(p =>
    (p.conditions.userRiskLevels?.length ?? 0) > 0 ||
    (p.conditions.signInRiskLevels?.length ?? 0) > 0,
  );
  if (hasRiskPolicy) score += 15;

  const hasAdminPolicy = enabled.some(p =>
    (p.conditions.users?.includeRoles?.length ?? 0) > 0,
  );
  if (hasAdminPolicy) score += 10;

  return clamp(score);
}

// ─── Privileged Access Score ──────────────────────────────────────────────────

export function scorePrivilegedAccess(
  globalAdminCount: number,
  guestAdmins: number,
  staleAdmins: number,
  adminsWithoutMfa: number,
  totalAdmins: number,
): number {
  let score = 0;

  if (globalAdminCount >= 2 && globalAdminCount <= 4) score += 30;
  else if (globalAdminCount >= 1 && globalAdminCount <= 7) score += 15;

  const mfaRate = totalAdmins > 0 ? (totalAdmins - adminsWithoutMfa) / totalAdmins : 1;
  score += Math.round(mfaRate * 40);

  if (guestAdmins === 0) score += 20;
  if (staleAdmins === 0) score += 10;

  return clamp(score);
}

// ─── Email Security Score ─────────────────────────────────────────────────────

export function scoreEmailSecurity(
  spfRecord: string | null,
  dmarcRecord: string | null,
  dkim1Record: string | null,
  dkim2Record: string | null,
): number {
  let score = 0;

  if (spfRecord) {
    if (spfRecord.includes('-all')) score += 35;
    else if (spfRecord.includes('~all')) score += 20;
    else score += 10;
  }

  if (dmarcRecord) {
    if (dmarcRecord.includes('p=reject')) score += 40;
    else if (dmarcRecord.includes('p=quarantine')) score += 28;
    else if (dmarcRecord.includes('p=none')) score += 10;
  }

  if (dkim1Record || dkim2Record) score += 25;

  return clamp(score);
}

// ─── Device Compliance Score ──────────────────────────────────────────────────

export function scoreDevices(
  totalDevices: number,
  nonCompliantDevices: number,
  staleDevices: number,
  compliancePolicies: number,
): number {
  if (totalDevices === 0) return 0;
  if (compliancePolicies === 0) return 10;

  let score = 40; // Has devices enrolled and policies

  const nonCompliantRate = nonCompliantDevices / totalDevices;
  if (nonCompliantRate === 0) score += 35;
  else if (nonCompliantRate <= 0.05) score += 25;
  else if (nonCompliantRate <= 0.10) score += 15;
  else if (nonCompliantRate <= 0.20) score += 5;

  const staleRate = staleDevices / totalDevices;
  if (staleRate === 0) score += 25;
  else if (staleRate <= 0.05) score += 15;
  else if (staleRate <= 0.15) score += 5;

  return clamp(score);
}

// ─── Identity Protection Score ────────────────────────────────────────────────

export function scoreIdentityProtection(
  highRiskUsers: number,
  mediumRiskUsers: number,
  limited: boolean,
): number {
  if (limited) return 50; // Neutral — can't assess without P2
  if (highRiskUsers > 5) return 0;
  if (highRiskUsers > 0) return 20;
  if (mediumRiskUsers > 5) return 45;
  if (mediumRiskUsers > 0) return 65;
  return 100;
}

// ─── User Hygiene Score ───────────────────────────────────────────────────────

export function scoreUserHygiene(
  staleUsers: number,
  blockedWithLicence: number,
  guestCount: number,
  passwordNeverExpireRate: number,
  totalActiveUsers: number,
): number {
  if (totalActiveUsers === 0) return 50;
  let score = 100;

  const staleRate = staleUsers / totalActiveUsers;
  if (staleRate > 0.2) score -= 30;
  else if (staleRate > 0.1) score -= 20;
  else if (staleRate > 0.05) score -= 10;

  if (blockedWithLicence > 5) score -= 20;
  else if (blockedWithLicence > 0) score -= 10;

  if (guestCount > 50) score -= 20;
  else if (guestCount > 20) score -= 10;

  if (passwordNeverExpireRate > 0.5) score -= 20;
  else if (passwordNeverExpireRate > 0.1) score -= 10;

  return clamp(score);
}

// ─── Applications Score ───────────────────────────────────────────────────────

export function scoreApplications(
  appsWithNoOwners: number,
  expiredSecrets: number,
  expiringSecrets: number,
  totalApps: number,
): number {
  if (totalApps === 0) return 80;
  let score = 100;

  const noOwnerRate = appsWithNoOwners / totalApps;
  if (noOwnerRate > 0.3) score -= 30;
  else if (noOwnerRate > 0.1) score -= 15;
  else if (noOwnerRate > 0) score -= 5;

  if (expiredSecrets > 0) score -= 30;
  if (expiringSecrets > 0) score -= 15;

  return clamp(score);
}

// ─── Governance Score ─────────────────────────────────────────────────────────

export function scoreGovernance(
  hasExpirationPolicy: boolean,
  groupCreationRestricted: boolean,
  groupsWithNoOwners: number,
  totalGroups: number,
): number {
  let score = 0;
  if (hasExpirationPolicy) score += 35;
  if (groupCreationRestricted) score += 35;

  if (totalGroups > 0) {
    const noOwnerRate = groupsWithNoOwners / totalGroups;
    if (noOwnerRate === 0) score += 30;
    else if (noOwnerRate <= 0.1) score += 20;
    else if (noOwnerRate <= 0.2) score += 10;
  } else {
    score += 30;
  }

  return clamp(score);
}

// ─── Overall Score ────────────────────────────────────────────────────────────

export function computeOverallScore(scores: Record<string, CategoryScore>): number {
  const available = Object.values(scores).filter(s => s.available);
  if (available.length === 0) return 0;

  const totalWeight = available.reduce((sum, s) => sum + s.weight, 0);
  const weightedSum = available.reduce((sum, s) => sum + s.score * s.weight, 0);

  return clamp(Math.round(weightedSum / totalWeight));
}

// ─── Full Score Computation ───────────────────────────────────────────────────

export function computeScores(
  result: AuditResult,
  adminIds: Set<string>,
  globalAdminCount: number,
  guestAdmins: number,
  staleAdmins: number,
  adminsWithoutMfa: number,
  totalAdmins: number,
): Record<string, CategoryScore> {
  // MFA
  const mfaCalc = scoreMfa(result.mfa.registrationDetails, adminIds);

  // Conditional Access
  const caScore = scoreConditionalAccess(result.conditionalAccess.policies);

  // Privileged Access
  const privScore = scorePrivilegedAccess(globalAdminCount, guestAdmins, staleAdmins, adminsWithoutMfa, totalAdmins);

  // Email Security
  const emailScore = scoreEmailSecurity(
    result.emailSecurity.spfRecord,
    result.emailSecurity.dmarcRecord,
    result.emailSecurity.dkim1Record,
    result.emailSecurity.dkim2Record,
  );

  // Devices
  const devices = result.devices.managedDevices;
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const nonCompliant = devices.filter(d => d.complianceState === 'noncompliant').length;
  const staleDevices = devices.filter(d => new Date(d.lastSyncDateTime) < thirtyDaysAgo).length;
  const deviceScore = scoreDevices(devices.length, nonCompliant, staleDevices, result.devices.compliancePolicies.length);

  // Identity Protection
  const highRisk = result.identityProtection.riskyUsers.filter(u => u.riskLevel === 'high').length;
  const medRisk = result.identityProtection.riskyUsers.filter(u => u.riskLevel === 'medium').length;
  const ipScore = scoreIdentityProtection(highRisk, medRisk, result.identityProtection.limited);

  // User Hygiene
  const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
  const activeUsers = result.users.users.filter(u => u.accountEnabled && u.userType !== 'Guest' && (u.assignedLicenses?.length ?? 0) > 0);
  const staleUsers = activeUsers.filter(u => {
    const lastSignIn = u.signInActivity?.lastSignInDateTime;
    if (!lastSignIn) return false;
    return new Date(lastSignIn) < ninetyDaysAgo;
  }).length;
  const blockedWithLicence = result.users.users.filter(u => !u.accountEnabled && (u.assignedLicenses?.length ?? 0) > 0).length;
  const guestCount = result.users.users.filter(u => u.userType === 'Guest').length;
  const passwordNeverExpireCount = result.users.users.filter(u => u.passwordPolicies?.includes('DisablePasswordExpiration')).length;
  const passwordNeverExpireRate = result.users.users.length > 0 ? passwordNeverExpireCount / result.users.users.length : 0;
  const hygScore = scoreUserHygiene(staleUsers, blockedWithLicence, guestCount, passwordNeverExpireRate, activeUsers.length);

  // Applications
  const apps = result.applications.appRegistrations;
  const appsNoOwner = apps.filter(a => !a.owners || a.owners.length === 0).length;
  const expiredSecrets = apps.filter(a =>
    a.passwordCredentials.some(c => c.endDateTime && new Date(c.endDateTime) < now),
  ).length;
  const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  const expiringSecrets = apps.filter(a =>
    a.passwordCredentials.some(c => c.endDateTime && new Date(c.endDateTime) >= now && new Date(c.endDateTime) <= thirtyDaysFromNow),
  ).length;
  const appScore = scoreApplications(appsNoOwner, expiredSecrets, expiringSecrets, apps.length);

  // Governance
  const hasExpiry = result.groups.lifecyclePolicies.length > 0;
  const groupCreationSetting = result.groups.settings.find(s =>
    s.values.some(v => v.name === 'EnableGroupCreation'),
  );
  const groupCreationRestricted = groupCreationSetting
    ? groupCreationSetting.values.find(v => v.name === 'EnableGroupCreation')?.value === 'false'
    : false;
  const groupsNoOwner = result.groups.groups.filter(g => !g.owners || g.owners.length === 0).length;
  const govScore = scoreGovernance(hasExpiry, groupCreationRestricted, groupsNoOwner, result.groups.groups.length);

  return {
    mfa: { label: 'MFA & Authentication', score: mfaCalc.score, weight: CATEGORY_WEIGHTS.mfa, available: !result.mfa.error || result.mfa.registrationDetails.length > 0, grade: getGrade(mfaCalc.score) },
    conditionalAccess: { label: 'Conditional Access', score: caScore, weight: CATEGORY_WEIGHTS.conditionalAccess, available: !result.conditionalAccess.error || result.conditionalAccess.policies.length > 0, grade: getGrade(caScore) },
    privilegedAccess: { label: 'Privileged Access', score: privScore, weight: CATEGORY_WEIGHTS.privilegedAccess, available: !result.roles.error || result.roles.roleAssignments.length > 0, grade: getGrade(privScore) },
    identityProtection: { label: 'Identity Protection', score: ipScore, weight: CATEGORY_WEIGHTS.identityProtection, available: true, grade: getGrade(ipScore) },
    applications: { label: 'Applications', score: appScore, weight: CATEGORY_WEIGHTS.applications, available: !result.applications.error || result.applications.appRegistrations.length > 0, grade: getGrade(appScore) },
    devices: { label: 'Device Compliance', score: deviceScore, weight: CATEGORY_WEIGHTS.devices, available: !result.devices.error || result.devices.managedDevices.length > 0, grade: getGrade(deviceScore) },
    emailSecurity: { label: 'Email Security', score: emailScore, weight: CATEGORY_WEIGHTS.emailSecurity, available: !result.emailSecurity.error, grade: getGrade(emailScore) },
    userHygiene: { label: 'User Hygiene', score: hygScore, weight: CATEGORY_WEIGHTS.userHygiene, available: !result.users.error || result.users.users.length > 0, grade: getGrade(hygScore) },
    governance: { label: 'Governance', score: govScore, weight: CATEGORY_WEIGHTS.governance, available: !result.groups.error || result.groups.groups.length > 0, grade: getGrade(govScore) },
  };
}
