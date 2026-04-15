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

};
