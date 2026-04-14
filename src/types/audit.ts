// ─── Core Types ──────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  recommendation: string;
  affectedCount?: number;
  affectedItems?: string[];
  learnMoreUrl?: string;
  effort: 'quick-win' | 'medium' | 'project';
}

export interface CategoryScore {
  label: string;
  score: number;
  weight: number;
  available: boolean;
  grade: 'critical' | 'poor' | 'fair' | 'good';
}

export type CollectorStatus = 'pending' | 'running' | 'complete' | 'failed';

export interface CollectorState {
  id: string;
  label: string;
  status: CollectorStatus;
  error?: string;
}

// ─── Graph API Response Types ──────────────────────────────────────────────

export interface GraphListResponse<T> {
  value: T[];
  '@odata.nextLink'?: string;
  '@odata.count'?: number;
}

// Organisation
export interface VerifiedDomain {
  capabilities: string;
  isDefault: boolean;
  isInitial: boolean;
  name: string;
  type: string;
}

export interface Organization {
  id: string;
  displayName: string;
  countryLetterCode: string;
  verifiedDomains: VerifiedDomain[];
  createdDateTime: string;
  tenantType?: string;
}

// Users
export interface SignInActivity {
  lastSignInDateTime?: string | null;
  lastNonInteractiveSignInDateTime?: string | null;
}

export interface AssignedLicense {
  skuId: string;
  disabledPlans: string[];
}

export interface User {
  id: string;
  displayName: string;
  userPrincipalName: string;
  accountEnabled: boolean;
  assignedLicenses: AssignedLicense[];
  signInActivity?: SignInActivity | null;
  userType: string;
  passwordPolicies?: string | null;
  createdDateTime: string;
}

// MFA / Auth Methods
export interface UserRegistrationDetail {
  id: string;
  userPrincipalName: string;
  userDisplayName: string;
  isAdmin: boolean;
  isSsprRegistered: boolean;
  isSsprEnabled: boolean;
  isSsprCapable: boolean;
  isMfaRegistered: boolean;
  isMfaCapable: boolean;
  isPasswordlessCapable: boolean;
  methodsRegistered: string[];
  defaultMfaMethod: string;
  isSystemPreferredAuthenticationMethodEnabled: boolean;
  systemPreferredAuthenticationMethods: string[];
}

export interface AuthMethodState {
  id: string;
  state: 'enabled' | 'disabled';
}

export interface AuthMethodTarget {
  id: string;
  targetType: string;
  authenticationMode?: string;
  isRegistrationRequired?: boolean;
  isNumberMatchingRequired?: boolean;
  isAdditionalContextEnabled?: boolean;
}

export interface AuthenticationMethodConfiguration {
  id: string;
  state: 'enabled' | 'disabled';
  includeTargets?: AuthMethodTarget[];
  excludeTargets?: AuthMethodTarget[];
  featureSettings?: {
    numberMatchingRequiredState?: { state: string };
    displayAppInformationRequiredState?: { state: string };
    companionAppAllowedState?: { state: string };
  };
  smsSignInState?: string;
}

export interface AuthMethodsPolicy {
  id: string;
  description: string;
  displayName: string;
  lastModifiedDateTime: string;
  authenticationMethodConfigurations: AuthenticationMethodConfiguration[];
}

// Conditional Access
export interface CAConditions {
  users?: {
    includeUsers?: string[];
    excludeUsers?: string[];
    includeGroups?: string[];
    excludeGroups?: string[];
    includeRoles?: string[];
    excludeRoles?: string[];
  };
  applications?: {
    includeApplications?: string[];
    excludeApplications?: string[];
    includeUserActions?: string[];
  };
  clientAppTypes?: string[];
  platforms?: {
    includePlatforms?: string[];
    excludePlatforms?: string[];
  };
  locations?: {
    includeLocations?: string[];
    excludeLocations?: string[];
  };
  signInRiskLevels?: string[];
  userRiskLevels?: string[];
}

export interface CAGrantControls {
  operator: 'AND' | 'OR';
  builtInControls: string[];
  customAuthenticationFactors?: string[];
  termsOfUse?: string[];
}

export interface CASessionControls {
  applicationEnforcedRestrictions?: { isEnabled: boolean };
  cloudAppSecurity?: { isEnabled: boolean; cloudAppSecurityType: string };
  signInFrequency?: { value: number; type: string; isEnabled: boolean };
  persistentBrowser?: { mode: string; isEnabled: boolean };
}

export interface ConditionalAccessPolicy {
  id: string;
  displayName: string;
  state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced';
  conditions: CAConditions;
  grantControls?: CAGrantControls | null;
  sessionControls?: CASessionControls | null;
  createdDateTime: string;
  modifiedDateTime: string;
}

export interface NamedLocation {
  id: string;
  displayName: string;
  '@odata.type': string;
}

// Role Management
export interface RoleDefinition {
  id: string;
  displayName: string;
  description: string;
  rolePermissions: unknown[];
  isBuiltIn: boolean;
  templateId: string;
}

export interface RoleAssignment {
  id: string;
  roleDefinitionId: string;
  principalId: string;
  directoryScopeId: string;
  principal?: {
    id: string;
    displayName: string;
    userPrincipalName?: string;
    userType?: string;
    '@odata.type'?: string;
  };
}

// Applications
export interface PasswordCredential {
  keyId: string;
  displayName?: string | null;
  startDateTime?: string | null;
  endDateTime?: string | null;
  hint?: string | null;
}

export interface KeyCredential {
  keyId: string;
  displayName?: string | null;
  startDateTime?: string | null;
  endDateTime?: string | null;
  type?: string | null;
  usage?: string | null;
}

export interface RequiredResourceAccess {
  resourceAppId: string;
  resourceAccess: { id: string; type: 'Role' | 'Scope' }[];
}

export interface AppRegistration {
  id: string;
  displayName: string;
  appId: string;
  createdDateTime: string;
  owners?: { id: string; displayName?: string }[];
  passwordCredentials: PasswordCredential[];
  keyCredentials: KeyCredential[];
  requiredResourceAccess: RequiredResourceAccess[];
}

export interface ServicePrincipal {
  id: string;
  displayName: string;
  appId: string;
  appOwnerOrganizationId: string;
  publisherName?: string;
  permissionScopes?: { id: string; value: string; adminConsentDisplayName: string }[];
  tags?: string[];
}

// Devices
export interface ManagedDevice {
  id: string;
  deviceName: string;
  operatingSystem: string;
  osVersion: string;
  complianceState: 'compliant' | 'noncompliant' | 'unknown' | 'notApplicable' | 'inGracePeriod' | 'conflict' | 'error';
  lastSyncDateTime: string;
  managedDeviceOwnerType: 'company' | 'personal' | 'unknown';
  enrolledDateTime: string;
}

export interface DeviceCompliancePolicy {
  id: string;
  displayName: string;
  lastModifiedDateTime: string;
  version: number;
}

// Identity Protection
export interface RiskyUser {
  id: string;
  userDisplayName: string;
  userPrincipalName: string;
  riskDetail: string;
  riskLastUpdatedDateTime: string;
  riskLevel: 'high' | 'medium' | 'low' | 'hidden' | 'none' | 'unknownFutureValue';
  riskState: string;
  isDeleted: boolean;
  isProcessing: boolean;
}

export interface RiskDetection {
  id: string;
  userDisplayName: string;
  userPrincipalName: string;
  riskEventType: string;
  riskLevel: string;
  riskState: string;
  detectedDateTime: string;
  activityDateTime?: string;
  ipAddress?: string;
  location?: { city: string; countryOrRegion: string; state: string };
  additionalInfo?: string;
}

// External Collaboration
export interface ExternalIdentitiesPolicy {
  id: string;
  allowExternalIdentitiesToLeave: boolean;
  allowDeletedIdentitiesDataRemoval: boolean;
}

export interface AuthorizationPolicy {
  id: string;
  allowInvitesFrom: string;
  allowedToSignUpEmailBasedSubscriptions: boolean;
  allowEmailVerifiedUsersToJoinOrganization: boolean;
  guestUserRoleId?: string;
  defaultUserRolePermissions: {
    allowedToCreateApps: boolean;
    allowedToCreateSecurityGroups: boolean;
    allowedToCreateTenants: boolean;
    allowedToReadBitlockerKeysForOwnedDevice: boolean;
    allowedToReadOtherUsers: boolean;
  };
}

// Groups
export interface GroupLifecyclePolicy {
  id: string;
  groupLifetimeInDays: number;
  managedGroupTypes: string;
  alternateNotificationEmails: string;
}

export interface Group {
  id: string;
  displayName: string;
  visibility?: string | null;
  resourceProvisioningOptions?: string[];
  members?: { id: string; displayName?: string; userType?: string }[];
  owners?: { id: string; displayName?: string }[];
  groupTypes?: string[];
}

export interface DirectorySetting {
  id: string;
  displayName: string;
  values: { name: string; value: string }[];
}

// Subscribed SKUs
export interface SubscribedSku {
  id: string;
  skuId: string;
  skuPartNumber: string;
  capabilityStatus: string;
  consumedUnits: number;
  prepaidUnits: {
    enabled: number;
    suspended: number;
    warning: number;
  };
  servicePlans: { servicePlanId: string; servicePlanName: string; provisioningStatus: string; appliesTo: string }[];
}

// Secure Score
export interface SecureScore {
  id: string;
  azureTenantId: string;
  activeUserCount: number;
  createdDateTime: string;
  currentScore: number;
  enabledServices: string[];
  licensedUserCount: number;
  maxScore: number;
  controlScores: { controlName: string; score: number; description: string; controlCategory: string }[];
}

// DNS / Email Security
export interface DnsRecord {
  name: string;
  type: number;
  TTL: number;
  data: string[];
  Answer?: { name: string; type: number; TTL: number; data: string }[];
}

export interface DnsResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question: { name: string; type: number }[];
  Answer?: { name: string; type: number; TTL: number; data: string }[];
}

// ─── Collector Result Types ───────────────────────────────────────────────────

export interface OrgData {
  organization: Organization | null;
  error: string | null;
}

export interface UsersData {
  users: User[];
  error: string | null;
}

export interface MfaData {
  registrationDetails: UserRegistrationDetail[];
  authMethodsPolicy: AuthMethodsPolicy | null;
  error: string | null;
}

export interface ConditionalAccessData {
  policies: ConditionalAccessPolicy[];
  namedLocations: NamedLocation[];
  error: string | null;
}

export interface RolesData {
  roleDefinitions: RoleDefinition[];
  roleAssignments: RoleAssignment[];
  error: string | null;
}

export interface ApplicationsData {
  appRegistrations: AppRegistration[];
  servicePrincipals: ServicePrincipal[];
  error: string | null;
}

export interface DevicesData {
  managedDevices: ManagedDevice[];
  compliancePolicies: DeviceCompliancePolicy[];
  error: string | null;
}

export interface IdentityProtectionData {
  riskyUsers: RiskyUser[];
  riskDetections: RiskDetection[];
  error: string | null;
  limited: boolean;
}

export interface ExternalCollabData {
  externalIdentitiesPolicy: ExternalIdentitiesPolicy | null;
  authorizationPolicy: AuthorizationPolicy | null;
  error: string | null;
}

export interface GroupsData {
  lifecyclePolicies: GroupLifecyclePolicy[];
  settings: DirectorySetting[];
  groups: Group[];
  error: string | null;
}

export interface LicencesData {
  subscribedSkus: SubscribedSku[];
  error: string | null;
}

export interface EmailSecurityData {
  domain: string;
  spfRecord: string | null;
  dmarcRecord: string | null;
  dkim1Record: string | null;
  dkim2Record: string | null;
  mxRecords: string[];
  error: string | null;
}

export interface SecureScoreData {
  secureScores: SecureScore[];
  error: string | null;
}

// ─── Full Audit Result ────────────────────────────────────────────────────────

export interface AuditResult {
  auditedAt: string;
  org: OrgData;
  users: UsersData;
  mfa: MfaData;
  conditionalAccess: ConditionalAccessData;
  roles: RolesData;
  applications: ApplicationsData;
  devices: DevicesData;
  identityProtection: IdentityProtectionData;
  externalCollab: ExternalCollabData;
  groups: GroupsData;
  licences: LicencesData;
  emailSecurity: EmailSecurityData;
  secureScore: SecureScoreData;
}

export interface ScoredAudit {
  result: AuditResult;
  scores: Record<string, CategoryScore>;
  overallScore: number;
  overallGrade: 'critical' | 'poor' | 'fair' | 'good';
  findings: Finding[];
}
