import { ClipboardList, Globe, Key, Shield, ExternalLink } from 'lucide-react';

const STEPS = [
  {
    icon: Globe,
    title: 'Register an Azure App',
    body: 'In the Azure Portal (portal.azure.com), go to Microsoft Entra ID → App registrations → New registration.',
    detail: [
      'Name: North Stream TenantAudit',
      'Supported account types: Accounts in any organizational directory (Multitenant)',
      'Redirect URI type: Single-page application (SPA)',
      `Redirect URI: ${window.location.origin}`,
      'Also add http://localhost:5173 for local development',
    ],
  },
  {
    icon: Key,
    title: 'Grant API permissions',
    body: 'Under the new app registration, go to API permissions → Add a permission → Microsoft Graph → Delegated permissions. Add all of the following, then grant admin consent.',
    detail: [
      'User.Read, User.Read.All, Directory.Read.All',
      'Policy.Read.All, Organization.Read.All',
      'Reports.Read.All, SecurityEvents.Read.All',
      'AuditLog.Read.All, IdentityRiskyUser.Read.All',
      'DeviceManagementManagedDevices.Read.All',
      'RoleManagement.Read.Directory',
      'Application.Read.All, GroupMember.Read.All',
    ],
  },
  {
    icon: ClipboardList,
    title: 'Copy the Application (Client) ID',
    body: 'From the app registration Overview page, copy the Application (client) ID.',
    detail: [
      'Set VITE_AZURE_CLIENT_ID in your .env.local file',
      'Set VITE_AZURE_REDIRECT_URI to your deployment URL',
      'In Vercel: add both as Environment Variables under Project Settings',
    ],
  },
  {
    icon: Shield,
    title: 'Deploy and test',
    body: 'Push to GitHub. Vercel will auto-deploy. Once live, sign in — your client\'s Global Admin will see a consent screen on first login and approve the permissions.',
    detail: [
      'First login in each client tenant triggers an admin consent prompt',
      'After consent, any admin in that tenant can run audits',
      'No data is stored — all processing is done client-side',
    ],
  },
];

export function SetupGuide() {
  return (
    <div className="min-h-screen bg-[#080d18] flex items-center justify-center p-6">
      <div className="max-w-2xl w-full">
        {/* Header */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-4"
            style={{ background: 'linear-gradient(135deg, #38bdf8, #0284c7)' }}>
            <svg width="28" height="28" viewBox="0 0 32 32" fill="none">
              <text x="16" y="22" textAnchor="middle" fontFamily="DM Sans, sans-serif"
                fontWeight="700" fontSize="14" fill="white" letterSpacing="-0.5">NS</text>
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-text mb-2">TenantAudit Setup</h1>
          <p className="text-muted text-sm">
            Complete the one-time Azure app registration to get started.
          </p>
          <div className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 rounded-full
            bg-yellow-400/10 border border-yellow-400/20 text-yellow-400 text-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse" />
            VITE_AZURE_CLIENT_ID not set — setup required
          </div>
        </div>

        {/* Steps */}
        <div className="space-y-4">
          {STEPS.map((step, i) => (
            <div key={i} className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0 flex items-center justify-center w-9 h-9
                  rounded-lg bg-blue-400/10 border border-blue-400/20">
                  <step.icon size={16} className="text-blue-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[11px] font-mono text-muted">Step {i + 1}</span>
                  </div>
                  <h3 className="text-sm font-semibold text-text mb-1">{step.title}</h3>
                  <p className="text-sm text-muted mb-3">{step.body}</p>
                  <ul className="space-y-1">
                    {step.detail.map((d, j) => (
                      <li key={j} className="flex items-start gap-2 text-xs text-muted">
                        <span className="mt-0.5 text-blue-400">→</span>
                        <span className="font-mono">{d}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Docs link */}
        <div className="mt-6 text-center">
          <a
            href="https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            Microsoft Entra app registration docs
            <ExternalLink size={11} />
          </a>
        </div>
      </div>
    </div>
  );
}
