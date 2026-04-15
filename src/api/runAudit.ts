import { type IPublicClientApplication, type AccountInfo } from '@azure/msal-browser';
import type { AuditResult, CollectorState } from '../types/audit';
import { collectOrganisation } from './collectors/organisation';
import { collectUsers } from './collectors/users';
import { collectMfa } from './collectors/mfa';
import { collectConditionalAccess } from './collectors/conditionalAccess';
import { collectRoles } from './collectors/roles';
import { collectApplications } from './collectors/applications';
import { collectDevices } from './collectors/devices';
import { collectIdentityProtection } from './collectors/identityProtection';
import { collectExternalCollab } from './collectors/externalCollab';
import { collectGroups } from './collectors/groups';
import { collectLicences } from './collectors/licences';
import { collectDns } from './collectors/dns';
import { collectSecureScore } from './collectors/secureScore';

export type ProgressCallback = (states: CollectorState[]) => void;

const COLLECTOR_IDS = [
  'organisation', 'users', 'mfa', 'conditionalAccess', 'roles',
  'applications', 'devices', 'identityProtection', 'externalCollab',
  'groups', 'licences', 'emailSecurity', 'secureScore',
] as const;

const COLLECTOR_LABELS: Record<string, string> = {
  organisation: 'Organisation',
  users: 'Users & Accounts',
  mfa: 'MFA & Authentication',
  conditionalAccess: 'Conditional Access',
  roles: 'Privileged Roles',
  applications: 'App Registrations',
  devices: 'Device Compliance',
  identityProtection: 'Identity Protection',
  externalCollab: 'External Collaboration',
  groups: 'Groups & Teams',
  licences: 'Licence Optimisation',
  emailSecurity: 'Email Security (DNS)',
  secureScore: 'Secure Score',
};

function makeStates(): CollectorState[] {
  return COLLECTOR_IDS.map(id => ({
    id,
    label: COLLECTOR_LABELS[id],
    status: 'pending',
  }));
}

async function runWithTracking<T>(
  id: string,
  fn: () => Promise<T>,
  states: CollectorState[],
  onProgress: ProgressCallback,
): Promise<T | undefined> {
  const idx = states.findIndex(s => s.id === id);
  states[idx] = { ...states[idx], status: 'running' };
  onProgress([...states]);
  try {
    const result = await fn();
    states[idx] = { ...states[idx], status: 'complete' };
    onProgress([...states]);
    return result;
  } catch (e) {
    const error = (e as Error).message;
    states[idx] = { ...states[idx], status: 'failed', error };
    onProgress([...states]);
    return undefined;
  }
}

export async function runAudit(
  instance: IPublicClientApplication,
  account: AccountInfo,
  onProgress: ProgressCallback,
): Promise<AuditResult> {
  const states = makeStates();
  onProgress([...states]);

  // Run org first to get primary domain for DNS check
  const org = await runWithTracking('organisation', () => collectOrganisation(instance, account), states, onProgress);
  const primaryDomain = org?.organization?.verifiedDomains?.find(d => d.isDefault)?.name
    ?? org?.organization?.verifiedDomains?.[0]?.name
    ?? '';

  // Run remaining collectors in parallel (except DNS needs domain)
  const [
    users, mfa, conditionalAccess, roles, applications,
    devices, identityProtection, externalCollab, groups, licences, secureScore,
  ] = await Promise.all([
    runWithTracking('users', () => collectUsers(instance, account), states, onProgress),
    runWithTracking('mfa', () => collectMfa(instance, account), states, onProgress),
    runWithTracking('conditionalAccess', () => collectConditionalAccess(instance, account), states, onProgress),
    runWithTracking('roles', () => collectRoles(instance, account), states, onProgress),
    runWithTracking('applications', () => collectApplications(instance, account), states, onProgress),
    runWithTracking('devices', () => collectDevices(instance, account), states, onProgress),
    runWithTracking('identityProtection', () => collectIdentityProtection(instance, account), states, onProgress),
    runWithTracking('externalCollab', () => collectExternalCollab(instance, account), states, onProgress),
    runWithTracking('groups', () => collectGroups(instance, account), states, onProgress),
    runWithTracking('licences', () => collectLicences(instance, account), states, onProgress),
    runWithTracking('secureScore', () => collectSecureScore(instance, account), states, onProgress),
  ]);

  // DNS is last — needs the domain
  const emailSecurity = await runWithTracking(
    'emailSecurity',
    () => primaryDomain ? collectDns(primaryDomain) : Promise.resolve({ domain: '', spfRecord: null, dmarcRecord: null, dkim1Record: null, dkim2Record: null, mxRecords: [], error: 'No domain found' }),
    states,
    onProgress,
  );

  return {
    auditedAt: new Date().toISOString(),
    org: org ?? { organization: null, error: 'Collection failed' },
    users: users ?? { users: [], error: 'Collection failed' },
    mfa: mfa ?? { registrationDetails: [], authMethodsPolicy: null, error: 'Collection failed' },
    conditionalAccess: conditionalAccess ?? { policies: [], namedLocations: [], error: 'Collection failed' },
    roles: roles ?? { roleDefinitions: [], roleAssignments: [], error: 'Collection failed' },
    applications: applications ?? { appRegistrations: [], servicePrincipals: [], error: 'Collection failed' },
    devices: devices ?? { managedDevices: [], compliancePolicies: [], error: 'Collection failed' },
    identityProtection: identityProtection ?? { riskyUsers: [], riskDetections: [], error: 'Collection failed', limited: false },
    externalCollab: externalCollab ?? { externalIdentitiesPolicy: null, authorizationPolicy: null, error: 'Collection failed' },
    groups: groups ?? { lifecyclePolicies: [], settings: [], groups: [], error: 'Collection failed' },
    licences: licences ?? { subscribedSkus: [], error: 'Collection failed' },
    emailSecurity: emailSecurity ?? { domain: '', spfRecord: null, dmarcRecord: null, dkim1Record: null, dkim2Record: null, mxRecords: [], error: 'Collection failed' },
    secureScore: secureScore ?? { secureScores: [], error: 'Collection failed' },
  };
}
