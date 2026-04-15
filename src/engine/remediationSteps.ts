// src/engine/remediationSteps.ts
// Step-by-step remediation guides keyed on finding.id
// Used by TabRemediation and AuditReportPDF

export interface RemediationGuide {
  whyItMatters: string;
  steps: string[];
  estimatedMinutes: number;
  docsUrl: string;
  caveats?: string;
}

export const remediationSteps: Record<string, RemediationGuide> = {

  // ─── MFA & Authentication ──────────────────────────────────────────────────

  'mfa-users-not-registered': {
    whyItMatters: 'Users without MFA registered cannot be protected by Conditional Access MFA enforcement policies. Their accounts rely on password alone.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Authentication methods → Registration campaign.',
      'Set State to Enabled. Set "Days allowed to snooze" to 0 to force immediate registration.',
      'Under Include, select All users (or target a specific group first for a phased rollout).',
      'Communicate to users: they will be prompted to register MFA at next sign-in.',
      'Monitor registration progress: Entra ID → Users → Authentication methods activity.',
      'After 14 days, check remaining unregistered users and follow up directly.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-registration-mfa-sspr-combined',
    caveats: 'Do not enforce a blocking MFA CA policy until registration reaches >95%. Combine with the MFA enforcement CA policy set to Report-only during the registration window.',
  },

  'mfa-admin-no-mfa': {
    whyItMatters: 'A Global Admin account without MFA is a critical risk. Full tenant control can be gained with a single stolen password.',
    steps: [
      'Identify the affected admin accounts from the Privileged Access tab.',
      'Contact each admin directly — do not rely on email alone.',
      'Direct them to aka.ms/mfasetup to register Microsoft Authenticator immediately.',
      'Once registered, enforce via the admin-targeted CA policy (see finding ca-no-admin-policy).',
      'Consider issuing a FIDO2 security key for highest-privilege accounts.',
    ],
    estimatedMinutes: 15,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates',
    caveats: 'This is a P0 action item. Do not wait for a scheduled change window.',
  },

  'mfa-weak-methods-only': {
    whyItMatters: 'SMS and voice call MFA can be bypassed via SIM-swapping attacks. Users relying solely on these methods have weaker protection than Authenticator app users.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Authentication methods → Policies.',
      'Enable Microsoft Authenticator for all users.',
      'Under Microsoft Authenticator settings, enable Number matching and Additional context.',
      'Run a registration campaign targeting users currently using SMS or voice only.',
      'Consider disabling SMS and Voice call methods once Authenticator adoption exceeds 90%.',
    ],
    estimatedMinutes: 25,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods',
  },

  'mfa-no-fido2': {
    whyItMatters: 'FIDO2 security keys are the strongest MFA method available and are phishing-resistant. Required for the highest-privilege accounts.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Authentication methods → Policies.',
      'Select FIDO2 security key → Enable.',
      'Under Include, target admin roles first (create a group containing all admins).',
      'Procure FIDO2 keys for admin accounts (recommended: YubiKey 5 series).',
      'Register keys: user navigates to aka.ms/mysecurityinfo → Add sign-in method → Security key.',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key',
  },

  'mfa-no-number-matching': {
    whyItMatters: 'Without number matching, users may approve MFA push prompts they did not initiate — a technique known as MFA fatigue or push bombing.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Authentication methods → Policies.',
      'Select Microsoft Authenticator → Configure.',
      'Under Number matching, set to Enabled.',
      'Optionally also enable Additional context to show the application name in push notifications.',
      'Click Save. The change takes effect immediately for all new authentication requests.',
    ],
    estimatedMinutes: 5,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match',
  },

  'mfa-sms-signin-enabled': {
    whyItMatters: 'SMS sign-in allows authentication with only a phone number and SMS code — no password required. This is a weak authentication flow susceptible to SIM-swapping.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Authentication methods → Policies.',
      'Select SMS → Disable SMS sign-in state.',
      'Confirm no users rely on SMS sign-in as their only authentication method before disabling.',
      'Click Save.',
    ],
    estimatedMinutes: 10,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-sms-signin',
  },

  // ─── Conditional Access ────────────────────────────────────────────────────

  'ca-no-policies': {
    whyItMatters: 'Without Conditional Access, every account is protected only by password. Any leaked credential grants full access with no additional verification.',
    steps: [
      'Sign in to entra.microsoft.com as a Global Administrator.',
      'Navigate to Protection → Conditional Access → Policies → New policy.',
      'Name it "Baseline — Require MFA for all users".',
      'Under Users, select All users. Under Target resources, select All cloud apps.',
      'Under Grant, select Grant access and check Require multifactor authentication.',
      'Set Enable policy to Report-only first; monitor for 48 hours, then switch to On.',
      'Create a second policy "Baseline — Block legacy authentication" (see ca-no-legacy-block).',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa',
    caveats: 'Enable in Report-only mode first. Check Sign-in logs under Report-only to confirm no legitimate users would be blocked before enforcing.',
  },

  'ca-no-mfa-policy': {
    whyItMatters: 'Without an enforced MFA policy, users who have not self-registered for MFA can still sign in with only a password.',
    steps: [
      'Sign in to entra.microsoft.com as a Global Administrator.',
      'Navigate to Protection → Conditional Access → Policies → New policy.',
      'Name: "Require MFA — All users".',
      'Users: All users. Exclude your break-glass emergency access account(s).',
      'Target resources: All cloud apps.',
      'Grant: Grant access → Require multifactor authentication.',
      'Enable policy: start with Report-only for 48 hours, then set to On.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa',
    caveats: 'Ensure all users have registered for MFA before enforcing, or combine with a registration campaign. Users without MFA registered will be blocked on enforcement.',
  },

  'ca-no-legacy-block': {
    whyItMatters: 'Legacy authentication protocols cannot process MFA challenges. Any account using IMAP, POP3, SMTP Auth, or Basic Auth bypasses all MFA policies.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Conditional Access → New policy.',
      'Name: "Block legacy authentication".',
      'Users: All users.',
      'Target resources: All cloud apps.',
      'Conditions → Client apps: tick Exchange ActiveSync clients and Other clients.',
      'Grant: Block access.',
      'Enable policy: On (safe to enforce immediately — modern clients are unaffected).',
    ],
    estimatedMinutes: 15,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication',
    caveats: 'Before enabling, check Sign-in logs filtered to "Other clients" to identify any services still using legacy auth. Common culprits: older printers, MFDs, and scripts using basic SMTP.',
  },

  'ca-no-admin-policy': {
    whyItMatters: 'Admin accounts are the highest-value targets. Applying the same controls as standard users is insufficient — privileged accounts warrant stricter requirements.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Conditional Access → New policy.',
      'Name: "Require strong MFA — Admin roles".',
      'Users → Select users and groups → Directory roles. Add: Global Administrator, Privileged Role Administrator, Security Administrator, Exchange Administrator, SharePoint Administrator.',
      'Target resources: All cloud apps.',
      'Grant: Grant access → Require multifactor authentication. Optionally also require compliant device.',
      'Enable policy: On.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa',
  },

  'ca-no-risk-policy': {
    whyItMatters: 'Without risk-based policies, compromised accounts flagged by Identity Protection are not automatically challenged or blocked.',
    steps: [
      'Ensure the tenant has Entra ID P2 licences (required for risk-based CA).',
      'Navigate to entra.microsoft.com → Protection → Conditional Access → New policy.',
      'Name: "Block high user risk".',
      'Users: All users. Conditions → User risk → High.',
      'Grant: Block access (or Require password change).',
      'Enable policy: On.',
      'Create a second policy: "Require MFA for medium/high sign-in risk" using Sign-in risk conditions.',
    ],
    estimatedMinutes: 25,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies',
    caveats: 'Requires Entra ID P2 or Microsoft 365 E5. Verify licence availability before configuring.',
  },

  'ca-no-named-locations': {
    whyItMatters: 'Without named locations, Conditional Access cannot distinguish between sign-ins from trusted office networks and external untrusted locations.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Conditional Access → Named locations.',
      'Click New location → IP ranges location.',
      'Name: "Corporate offices". Add each office\'s public IP range.',
      'Mark as Trusted location.',
      'Optionally create country-based locations to block sign-ins from high-risk countries.',
    ],
    estimatedMinutes: 15,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/location-condition',
  },

  'ca-report-only': {
    whyItMatters: 'Policies in report-only mode are not enforced. Users are not being challenged and the controls provide no actual protection.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Conditional Access → Policies.',
      'Open each report-only policy.',
      'Review the Sign-in logs: Monitoring → Sign-in logs → Filter by CA policy name to see impact.',
      'Confirm no legitimate users would be blocked.',
      'Change Enable policy from Report-only to On.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only',
    caveats: 'Always review the report-only impact before enforcing. Check for service accounts or legacy systems that may be affected.',
  },

  // ─── Users & Accounts ─────────────────────────────────────────────────────

  'users-blocked-with-licence': {
    whyItMatters: 'Disabled accounts retaining licences waste budget and may retain delegated mailbox access or group memberships that could be exploited.',
    steps: [
      'Open admin.microsoft.com → Users → Active users. Filter by "Sign-in blocked".',
      'Alternatively, use the affected account list from the Users & Accounts tab in this tool.',
      'For each blocked account: select the user → Licences and apps → uncheck all licences → Save.',
      'Verify the account has no active shared mailbox delegation or distribution list membership.',
      'Reclaim the freed licences for active users or reduce the licence count at next renewal.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/admin/manage/remove-licenses-from-users',
  },

  'users-stale-accounts': {
    whyItMatters: 'Accounts inactive for 90+ days likely belong to former employees or unused service accounts and represent unnecessary attack surface and licence cost.',
    steps: [
      'Export the stale account list from the Users & Accounts tab.',
      'Cross-reference with HR to confirm which accounts belong to former employees.',
      'For confirmed leavers: block sign-in immediately, remove licences, and schedule deletion after 30 days.',
      'For unconfirmed accounts: contact the account owner\'s manager to verify status.',
      'For service accounts: document their purpose. If unused, disable and monitor for 30 days before deleting.',
    ],
    estimatedMinutes: 45,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts',
    caveats: 'Do not delete accounts immediately — disable first and wait 30 days to catch dependencies that were not apparent.',
  },

  'users-excess-guests': {
    whyItMatters: 'A large unmanaged guest population increases exposure and complicates data access governance. Former partner or vendor guests may retain access after the relationship ends.',
    steps: [
      'Navigate to entra.microsoft.com → Users → All users → Filter by User type: Guest.',
      'Export the guest list.',
      'For each guest, confirm whether they still require access by contacting the inviting user or manager.',
      'Remove guests that no longer require access: select user → Delete.',
      'Consider enabling Access Reviews in Entra ID Governance for ongoing quarterly guest reviews.',
    ],
    estimatedMinutes: 45,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions',
    caveats: 'Deleting a guest removes their access to all shared resources. Confirm with the inviting business owner before removing.',
  },

  'users-password-never-expires': {
    whyItMatters: 'Non-expiring passwords on accounts without strong MFA increase the window of opportunity if credentials are ever compromised.',
    steps: [
      'Cross-reference these accounts against MFA registration data (MFA & Auth tab).',
      'For any account with a non-expiring password that is NOT protected by MFA, enforce MFA registration immediately.',
      'To change the password policy for cloud-only accounts: admin.microsoft.com → Settings → Org settings → Security & privacy → Password expiration policy.',
      'For hybrid accounts, update the policy via on-premises Active Directory.',
      'Note: Non-expiring passwords are acceptable for cloud-only accounts that are fully protected by MFA and Conditional Access.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations',
  },

  'users-never-signed-in': {
    whyItMatters: 'Accounts created more than 30 days ago that have never been used are likely provisioning errors or orphaned accounts, and represent unmonitored access.',
    steps: [
      'Review each account in the affected list.',
      'Check whether the account has an assigned manager or department.',
      'Contact the account\'s manager or HR to confirm if the account is expected.',
      'Disable accounts that cannot be confirmed as intentional.',
      'Delete after 30 days if no service failures are observed.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts',
  },

  // ─── Privileged Roles ─────────────────────────────────────────────────────

  'roles-no-global-admin': {
    whyItMatters: 'Without a reachable Global Administrator, critical tenant operations and security responses are blocked until Microsoft Support restores access.',
    steps: [
      'Navigate to entra.microsoft.com → Roles and administrators → Global Administrator.',
      'If no accounts are listed, contact Microsoft Support immediately.',
      'Create a dedicated break-glass account (e.g. breakglass@yourdomain.com).',
      'Assign Global Administrator to this account.',
      'Store the credentials in a physical safe or offline password manager.',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access',
  },

  'roles-single-global-admin': {
    whyItMatters: 'A single Global Admin is a lockout risk. If the account is compromised, loses MFA access, or is unavailable, tenant recovery requires Microsoft Support.',
    steps: [
      'Create a dedicated break-glass emergency access account.',
      'Use a format like breakglass@yourdomain.com — not tied to any individual.',
      'Set a strong random password (20+ characters). Store it in a physical safe or offline password manager.',
      'Exclude this account from all Conditional Access policies.',
      'Assign Global Administrator role to this account.',
      'Set up an alert to notify when this account signs in — it should never sign in under normal operations.',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access',
  },

  'roles-excess-global-admins': {
    whyItMatters: 'Each Global Admin account is a potential full-tenant compromise vector. Reducing the count minimises the blast radius of a credential breach.',
    steps: [
      'Navigate to entra.microsoft.com → Roles and administrators → Global Administrator.',
      'Review each account listed.',
      'For each admin that does not require full Global Admin access, identify the minimum required role: Exchange Admin, User Admin, Security Admin, etc.',
      'Click the account → Remove assignment from Global Administrator.',
      'Assign the appropriate scoped role instead.',
      'Retain 2–4 Global Admin accounts maximum, including at least one break-glass account.',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices',
  },

  'roles-guest-in-admin-role': {
    whyItMatters: 'Guest accounts originate outside your organisation and cannot be subject to your internal identity governance policies. An external user holding an admin role is a critical exposure.',
    steps: [
      'Navigate to entra.microsoft.com → Roles and administrators.',
      'For each privileged role, check the member list for guest accounts (identified by #EXT# in UPN).',
      'Remove the guest from the admin role immediately.',
      'If the external party requires administrative access, create a member account under your domain for them instead.',
    ],
    estimatedMinutes: 15,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices',
  },

  'roles-stale-admins': {
    whyItMatters: 'Dormant admin accounts hold elevated privileges that can be exploited long after the original user stopped working. They are unlikely to notice a compromise.',
    steps: [
      'Export the stale admin list from the Privileged Access tab.',
      'For each account, confirm the user\'s employment status with HR.',
      'For former employees: remove all role assignments immediately and block sign-in.',
      'For active employees who no longer need the role: remove the assignment.',
      'For service accounts with admin roles: document the necessity or replace with a managed identity or service principal with scoped permissions.',
    ],
    estimatedMinutes: 45,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices',
    caveats: 'Remove role assignments before disabling accounts to avoid confusion in future audits.',
  },

  'roles-excess-pra': {
    whyItMatters: 'Privileged Role Administrator can assign any role including Global Administrator. Too many holders creates uncontrolled privilege escalation paths.',
    steps: [
      'Navigate to entra.microsoft.com → Roles and administrators → Privileged Role Administrator.',
      'Review the list of current holders.',
      'Retain a maximum of 2 accounts in this role.',
      'Remove assignments for all others — reassign to Security Administrator or Global Administrator as appropriate.',
      'Consider using Privileged Identity Management (PIM) to make this role eligible rather than permanently assigned (requires P2).',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices',
  },

  // ─── Applications ─────────────────────────────────────────────────────────

  'apps-no-owners': {
    whyItMatters: 'App registrations without owners have no accountable person to rotate credentials, review permissions, or decommission the app when no longer needed.',
    steps: [
      'Navigate to entra.microsoft.com → App registrations → select the affected application.',
      'Go to Owners → Add owners.',
      'Assign at least one owner who is responsible for the application.',
      'Document the app\'s purpose in the Notes field under Branding & properties.',
    ],
    estimatedMinutes: 10,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps',
  },

  'apps-expired-secrets': {
    whyItMatters: 'Expired client secrets cause immediate application authentication failures and service outages.',
    steps: [
      'Navigate to entra.microsoft.com → App registrations → select the affected application.',
      'Go to Certificates & secrets → New client secret.',
      'Set an expiry of 12 months (or less). Copy the new secret value immediately — it is only shown once.',
      'Update the secret in the application\'s configuration (app settings, Key Vault, or wherever it is stored).',
      'Verify the application authenticates successfully with the new secret.',
      'Delete the old expired secret.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal',
    caveats: 'Coordinate with the application owner before rotating secrets. Rotating without updating the app config will cause immediate auth failures.',
  },

  'apps-expiring-secrets': {
    whyItMatters: 'Expiring secrets are a known, predictable outage risk. Rotation must be planned and coordinated before the expiry date.',
    steps: [
      'Navigate to entra.microsoft.com → App registrations → select the affected application.',
      'Go to Certificates & secrets → New client secret.',
      'Set an expiry of 12 months. Copy the new secret value immediately.',
      'Update the secret in the application\'s configuration.',
      'Verify authentication works with the new secret.',
      'Delete the old expiring secret once confirmed working.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal',
    caveats: 'Coordinate with the application owner. Do not rotate without updating the config first.',
  },

  'apps-expiring-secrets-90d': {
    whyItMatters: 'Secrets expiring within 90 days need to be scheduled for rotation to avoid a future outage.',
    steps: [
      'Add secret rotation tasks to your team\'s backlog for each affected application.',
      'Contact each app owner to confirm the rotation process and who holds the configuration access.',
      'Rotate each secret using the same process as apps-expiring-secrets.',
      'Consider moving to certificate-based authentication or managed identities for apps that support it.',
    ],
    estimatedMinutes: 15,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal',
  },

  'apps-old-secrets': {
    whyItMatters: 'Long-lived secrets that are never rotated become a significant risk if credentials are ever leaked — attackers may have had access for an extended period without detection.',
    steps: [
      'Review each affected application in entra.microsoft.com → App registrations.',
      'Rotate the secret using the process in apps-expiring-secrets.',
      'Establish a policy: maximum 12-month secret lifetime. Set calendar reminders or use Azure Key Vault with automatic rotation.',
      'Consider migrating high-privilege apps to certificate-based authentication, which is more secure than secrets.',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal',
  },

  // ─── Devices ──────────────────────────────────────────────────────────────

  'devices-no-enrolment': {
    whyItMatters: 'Without device management, you cannot enforce compliance conditions in Conditional Access, apply security baselines, or remotely wipe devices if lost or stolen.',
    steps: [
      'This is a project-level change. Begin with a pilot group before full rollout.',
      'Navigate to intune.microsoft.com → Devices → Enrol devices.',
      'For Windows: configure Windows Autopilot or deploy the Intune MDM enrolment package via Group Policy.',
      'For iOS/Android: deploy the Microsoft Intune app and configure an enrolment profile.',
      'Create a compliance policy per platform: intune.microsoft.com → Devices → Compliance policies → Create policy.',
      'Once devices are enrolled and compliant, add a Require compliant device condition to your admin CA policy.',
    ],
    estimatedMinutes: 240,
    docsUrl: 'https://learn.microsoft.com/en-us/mem/intune/enrollment/device-enrollment',
    caveats: 'Full device enrolment is a significant project. Scope and plan carefully — do not attempt to enrol all devices without a tested pilot and user communication plan.',
  },

  'devices-no-compliance-policy': {
    whyItMatters: 'Without compliance policies, all enrolled devices default to compliant — making device-based Conditional Access controls completely ineffective.',
    steps: [
      'Navigate to intune.microsoft.com → Devices → Compliance policies → Create policy.',
      'Create a policy for each platform in use (Windows, iOS, Android, macOS).',
      'For Windows: require BitLocker encryption, minimum OS version, password required, firewall enabled.',
      'For iOS/Android: require device encryption, minimum OS version, screen lock.',
      'Assign each policy to All devices or the relevant device group.',
      'Set a grace period of 7 days for initial rollout to avoid immediate lockouts.',
    ],
    estimatedMinutes: 60,
    docsUrl: 'https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started',
  },

  'devices-high-noncompliance': {
    whyItMatters: 'Non-compliant devices may lack encryption, security updates, or screen locks — making them easier targets for physical or network-based attacks.',
    steps: [
      'Navigate to intune.microsoft.com → Devices → Monitor → Noncompliant devices.',
      'Export the list and sort by compliance issue type.',
      'For OS version issues: push a Windows Update policy or notify users to update.',
      'For encryption issues: push a BitLocker policy (Windows) or enable encryption enforcement (iOS/Android).',
      'For devices that cannot be remediated: consider retiring and re-enrolling.',
      'Set up automatic emails to device owners when their device becomes non-compliant.',
    ],
    estimatedMinutes: 60,
    docsUrl: 'https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started',
  },

  'devices-stale-sync': {
    whyItMatters: 'Devices not syncing with Intune are not receiving policy updates and their compliance state may be outdated, creating a false sense of security.',
    steps: [
      'Navigate to intune.microsoft.com → Devices → All devices → Filter by Last check-in: > 30 days.',
      'For each stale device, check the device\'s ownership and last known user.',
      'Contact the device owner to investigate — the device may be powered off, reimaged, or lost.',
      'For devices confirmed as decommissioned: Retire the device in Intune to remove it from management.',
      'For active devices with sync issues: troubleshoot the Intune management agent (run dsregcmd /status on Windows).',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/mem/intune/remote-actions/devices-wipe',
  },

  // ─── Identity Protection ──────────────────────────────────────────────────

  'idp-high-risk-users': {
    whyItMatters: 'High-risk users have been flagged by Microsoft\'s threat intelligence as likely compromised. These accounts may have active attacker sessions right now.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Identity Protection → Risky users.',
      'Filter by Risk level: High.',
      'For each high-risk user: click the account → select Confirm user compromised.',
      'Immediately require a password reset: select the user → Reset password.',
      'Review the user\'s recent sign-in activity for suspicious sign-ins.',
      'Once remediated, dismiss the risk: select user → Dismiss user risk.',
      'Enable a risk-based CA policy to automate this in future (see ca-no-risk-policy).',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock',
    caveats: 'Treat high-risk users as actively compromised until proven otherwise. Prioritise admin accounts above all others.',
  },

  'idp-medium-risk-users': {
    whyItMatters: 'Medium-risk users have exhibited anomalous sign-in behaviour that warrants investigation, such as atypical travel or unfamiliar sign-in properties.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Identity Protection → Risky users.',
      'Filter by Risk level: Medium.',
      'For each account, review the risk detections to understand why the account was flagged.',
      'Contact the user to confirm whether the sign-in was legitimate.',
      'If confirmed legitimate: dismiss the risk.',
      'If suspicious: require password reset and MFA re-registration.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock',
  },

  'idp-no-p2': {
    whyItMatters: 'Without Entra ID P2, risk-based sign-in policies and leaked credential detection are unavailable, leaving the tenant blind to identity-based attacks.',
    steps: [
      'Review current licence assignments: admin.microsoft.com → Billing → Your products.',
      'Identify how many users require P2 features (typically all licensed users).',
      'Compare cost of Entra ID P2 add-on vs upgrading to Microsoft 365 E3 or E5.',
      'If budget allows, procure Entra ID P2 or Microsoft 365 E5 licences.',
      'Once licences are assigned, configure risk-based CA policies (see ca-no-risk-policy).',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection',
  },

  'idp-recent-detections': {
    whyItMatters: 'Recent risk detections indicate suspicious activity has occurred. Even if accounts appear uncompromised, each detection warrants review.',
    steps: [
      'Navigate to entra.microsoft.com → Protection → Identity Protection → Risk detections.',
      'Review each detection in the past 30 days.',
      'For each detection, open the associated sign-in and confirm it was legitimate with the user.',
      'For detections that cannot be confirmed: treat the account as compromised — reset password and MFA.',
      'Enable a risk-based CA policy to automatically challenge risky sign-ins in future.',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks',
  },

  // ─── External Collaboration ───────────────────────────────────────────────

  'extcollab-open-guest-invite': {
    whyItMatters: 'When any user including existing guests can invite external users, the guest population grows uncontrolled and without IT visibility.',
    steps: [
      'Navigate to entra.microsoft.com → External Identities → External collaboration settings.',
      'Under Guest invite settings, change to "Member users and users assigned to specific admin roles can invite guest users".',
      'Click Save.',
    ],
    estimatedMinutes: 5,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure',
  },

  'extcollab-email-verified-join': {
    whyItMatters: 'Allowing email-verified users to self-join creates an open registration flow — any person with a valid email can gain access to your tenant resources.',
    steps: [
      'Navigate to entra.microsoft.com → External Identities → External collaboration settings.',
      'Find "Allow external users to sign up through Azure AD B2B collaboration" or "Email one-time passcode" settings.',
      'Disable "Allow email verified users to join your organization".',
      'Click Save.',
    ],
    estimatedMinutes: 5,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure',
  },

  'extcollab-guest-full-access': {
    whyItMatters: 'Guests with member-level access can enumerate all users, groups, and other guests in the directory — giving them a full map of your organisation.',
    steps: [
      'Navigate to entra.microsoft.com → External Identities → External collaboration settings.',
      'Under Guest user access, select "Guest users have limited access to properties and memberships of directory objects".',
      'Click Save.',
      'This limits guests to seeing only their own profile and the resources they have been explicitly granted access to.',
    ],
    estimatedMinutes: 5,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions',
  },

  // ─── Governance ───────────────────────────────────────────────────────────

  'governance-no-group-expiry': {
    whyItMatters: 'Without expiration policies, Microsoft 365 groups and Teams accumulate indefinitely. Abandoned groups retain access to files and data even after projects end.',
    steps: [
      'Navigate to entra.microsoft.com → Groups → Expiration.',
      'Set Group lifetime (days) to 180 or 365 depending on your organisation\'s preference.',
      'Enable expiration for All groups, or select a pilot group first.',
      'Set the notification email address for groups with no owners.',
      'Click Save. Group owners will receive renewal prompts 30 days before expiry.',
    ],
    estimatedMinutes: 10,
    docsUrl: 'https://learn.microsoft.com/en-us/entra/identity/users/groups-lifecycle',
  },

  'governance-open-group-creation': {
    whyItMatters: 'Unrestricted group creation leads to Teams and SharePoint sprawl, making governance, data classification, and access reviews unmanageable.',
    steps: [
      'Create a security group called "Group-Creators" (or similar) in entra.microsoft.com → Groups → New group.',
      'Add approved users or the IT team as members.',
      'Navigate to entra.microsoft.com → Groups → Settings.',
      'Under the "General" settings, find "Users who can create Microsoft 365 groups in Azure portals, API or PowerShell".',
      'Change to Selected and select the Group-Creators security group.',
      'Click Save.',
    ],
    estimatedMinutes: 15,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups',
    caveats: 'Communicate this change to users before enforcing — they will receive an error if they try to create a team or group without being in the approved group.',
  },

  'governance-groups-no-owners': {
    whyItMatters: 'Ownerless groups cannot receive expiration renewal requests and have no accountable person to manage membership or decommission the group.',
    steps: [
      'Export the ownerless group list from the Governance tab.',
      'For each group, identify who created it or who the primary stakeholders are.',
      'Assign an owner: navigate to the group in entra.microsoft.com → Groups → select group → Owners → Add owners.',
      'For groups with no identifiable owner that appear inactive, consider deleting them after confirming no active members require the resource.',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/solutions/microsoft-365-groups-expiration-policy',
  },

  'governance-public-groups': {
    whyItMatters: 'Public groups allow any tenant user to view content and join without approval, which may expose sensitive project data or internal communications.',
    steps: [
      'Review the list of public groups in the Governance tab.',
      'For each group, assess whether the content is appropriate for all-staff visibility.',
      'To change visibility: navigate to admin.microsoft.com → Teams & groups → Active teams & groups → select group → Settings → Privacy → Private.',
      'Communicate the change to group members before switching to Private.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/solutions/groups-teams-access-governance',
  },

  // ─── Email Security ───────────────────────────────────────────────────────

  'email-no-spf': {
    whyItMatters: 'Without an SPF record, any server can send email appearing to come from your domain. This enables phishing and spoofing attacks against your clients and staff.',
    steps: [
      'Log in to your DNS provider (e.g. Cloudflare, GoDaddy, 123-reg).',
      'Add a TXT record on the root domain (@).',
      'Value: v=spf1 include:spf.protection.outlook.com -all',
      'TTL: 3600 (1 hour) or your provider\'s default.',
      'If you send email from other services (Mailchimp, HubSpot, etc.), add their include mechanisms before -all.',
      'Verify after propagation using mxtoolbox.com/spf.',
    ],
    estimatedMinutes: 15,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-spf-configure',
  },

  'email-spf-not-enforced': {
    whyItMatters: 'An SPF record ending in ~all or ?all does not instruct receiving servers to reject spoofed email — it only suggests they might flag it.',
    steps: [
      'Log in to your DNS provider.',
      'Find your existing TXT record for the root domain containing v=spf1.',
      'Change the final mechanism from ~all or ?all to -all.',
      'Example result: v=spf1 include:spf.protection.outlook.com -all',
      'Save the record and verify at mxtoolbox.com/spf.',
    ],
    estimatedMinutes: 10,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-spf-configure',
    caveats: 'Before switching to -all, confirm all legitimate sending sources are included in the SPF record. Use mxtoolbox.com/emailhealth to check all sending IPs.',
  },

  'email-no-dmarc': {
    whyItMatters: 'Without DMARC, receiving servers have no instruction on what to do with email that fails SPF or DKIM authentication. Spoofed email may still be delivered.',
    steps: [
      'Log in to your DNS provider.',
      'Add a TXT record at _dmarc.yourdomain.com.',
      'Start with: v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com',
      'The p=none policy enables monitoring without rejecting email.',
      'Review DMARC aggregate reports for 2–4 weeks to confirm all legitimate mail passes.',
      'Update to p=quarantine, then after another 2–4 weeks, update to p=reject.',
    ],
    estimatedMinutes: 20,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure',
    caveats: 'Never start with p=reject. Always begin with p=none, review reports, then escalate incrementally.',
  },

  'email-dmarc-not-enforced': {
    whyItMatters: 'A DMARC record with p=none means receiving servers take no action on emails that fail authentication. The record exists but provides no protection.',
    steps: [
      'Review your DMARC aggregate reports (sent to the rua= address) to confirm all legitimate mail passes SPF and DKIM.',
      'Use a DMARC reporting tool (e.g. dmarcian.com or Google Postmaster Tools) to visualise failures.',
      'Once confident all legitimate mail passes, update the DNS TXT record at _dmarc.yourdomain.com.',
      'Change p=none to p=quarantine.',
      'Monitor for 2–4 weeks. If no issues, change to p=reject.',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure',
  },

  'email-dmarc-no-reporting': {
    whyItMatters: 'Without a DMARC reporting address, you have no visibility into authentication failures or spoofing attempts against your domain.',
    steps: [
      'Log in to your DNS provider.',
      'Find your existing TXT record at _dmarc.yourdomain.com.',
      'Add rua=mailto:dmarc-reports@yourdomain.com to the record.',
      'Example: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com',
      'Save and verify with mxtoolbox.com/dmarc.',
    ],
    estimatedMinutes: 10,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure',
  },

  'email-no-dkim': {
    whyItMatters: 'Without DKIM, email from your domain cannot be cryptographically verified. DKIM is required for DMARC alignment and prevents message tampering in transit.',
    steps: [
      'Navigate to security.microsoft.com → Email & collaboration → Policies & rules → Threat policies → Email authentication settings → DKIM.',
      'Select your domain and click Enable.',
      'Microsoft will display two CNAME records: selector1._domainkey.yourdomain.com and selector2._domainkey.yourdomain.com.',
      'Add both CNAME records to your DNS provider.',
      'Wait for DNS propagation (up to 48 hours), then return to the DKIM page and click Enable again.',
      'Verify with mxtoolbox.com/dkim.',
    ],
    estimatedMinutes: 25,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dkim-configure',
  },

  'email-third-party-mx': {
    whyItMatters: 'A third-party mail gateway changes the SPF and DKIM alignment requirements. Misconfiguration here can cause legitimate mail to fail authentication.',
    steps: [
      'Identify the mail gateway in use from the MX record.',
      'Ensure the gateway\'s sending IPs are included in your SPF record.',
      'Confirm DKIM signing is configured in the gateway (not just Exchange Online).',
      'Verify DMARC alignment — the From domain must align with either the SPF or DKIM signing domain.',
      'Consult your gateway vendor\'s documentation for Microsoft 365 integration.',
    ],
    estimatedMinutes: 30,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-about',
  },

  // ─── Secure Score ─────────────────────────────────────────────────────────

  'securescore-low': {
    whyItMatters: 'Microsoft Secure Score reflects the overall implementation of recommended security controls across identity, data, devices, and apps.',
    steps: [
      'Navigate to security.microsoft.com → Secure score.',
      'Click the Recommended actions tab.',
      'Filter by: Status = To address, Category = Identity. Sort by Points impact descending.',
      'Work through the top 5 highest-impact actions — each has a step-by-step guide within the portal.',
      'After completing each action, mark it as Addressed to update your score.',
    ],
    estimatedMinutes: 60,
    docsUrl: 'https://learn.microsoft.com/en-us/microsoft-365/security/defender/microsoft-secure-score-improvement-actions',
    caveats: 'Some improvements require Entra ID P2 or Defender for Office 365 Plan 2. Filter by your available licence tier.',
  },

};
