import { useState } from 'react';
import { useMsal } from '@azure/msal-react';
import { loginRequest } from '../auth/msalConfig';
import { Shield, AlertTriangle, ExternalLink } from 'lucide-react';

export function LoginPage() {
  const { instance } = useMsal();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleLogin() {
    setError(null);
    setLoading(true);
    try {
      await instance.loginPopup(loginRequest);
    } catch (e: unknown) {
      const err = e as { errorCode?: string; message?: string };
      if (err?.errorCode === 'user_cancelled') {
        // silent — user dismissed popup
      } else if (err?.errorCode === 'popup_window_error') {
        setError('Popup was blocked. Please allow popups for this site and try again.');
      } else if (err?.errorCode === 'consent_required' || err?.errorCode === 'interaction_required') {
        setError('Admin consent is required. Ask your Global Administrator to sign in first and approve the permissions.');
      } else {
        setError(err?.message ?? 'Sign-in failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#080d18] flex items-center justify-center p-6">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4"
            style={{ background: 'linear-gradient(135deg, #38bdf8, #0284c7)' }}>
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
              <text x="16" y="22" textAnchor="middle" fontFamily="DM Sans, sans-serif"
                fontWeight="700" fontSize="16" fill="white" letterSpacing="-0.5">NS</text>
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-text mb-1">TenantAudit</h1>
          <p className="text-sm text-muted">M365 security auditing for managed service providers</p>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-[#1e3a5f] bg-[#0f172a] p-6">
          <div className="flex items-center gap-2 mb-5">
            <Shield size={15} className="text-blue-400" />
            <span className="text-sm font-medium text-text">Sign in to begin audit</span>
          </div>

          <p className="text-xs text-muted mb-5 leading-relaxed">
            Sign in with a Microsoft 365 admin account. On first use in a client tenant,
            the Global Administrator will be prompted to grant consent for the required permissions.
          </p>

          {error && (
            <div className="flex items-start gap-2 mb-4 p-3 rounded-lg bg-red-400/10 border border-red-400/20">
              <AlertTriangle size={14} className="text-red-400 mt-0.5 flex-shrink-0" />
              <p className="text-xs text-red-400">{error}</p>
            </div>
          )}

          <button
            onClick={handleLogin}
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg
              bg-blue-400 text-[#080d18] font-semibold text-sm
              hover:bg-blue-300 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? (
              <>
                <span className="w-4 h-4 border-2 border-[#080d18]/30 border-t-[#080d18] rounded-full animate-spin" />
                Signing in…
              </>
            ) : (
              <>
                {/* Microsoft M logo */}
                <svg width="16" height="16" viewBox="0 0 21 21" fill="none">
                  <rect x="1" y="1" width="9" height="9" fill="#f25022" />
                  <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
                  <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
                  <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
                </svg>
                Sign in with Microsoft
              </>
            )}
          </button>
        </div>

        {/* Footer */}
        <div className="mt-6 text-center space-y-1">
          <p className="text-[11px] text-muted">
            Prepared by North Stream Systems — point-in-time audit, no data stored
          </p>
          <a
            href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-[11px] text-muted/60 hover:text-muted transition-colors"
          >
            About required permissions <ExternalLink size={10} />
          </a>
        </div>
      </div>
    </div>
  );
}
