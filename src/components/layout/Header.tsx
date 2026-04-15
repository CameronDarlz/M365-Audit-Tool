import { useMsal } from '@azure/msal-react';
import { LogOut, RefreshCw, Shield } from 'lucide-react';
import { Organization } from '../../types/audit';

interface HeaderProps {
  organization?: Organization | null;
  onReaudit?: () => void;
  isRunning?: boolean;
}

function NSLogo() {
  return (
    <svg width="32" height="32" viewBox="0 0 32 32" fill="none" aria-label="North Stream Systems">
      <rect width="32" height="32" rx="8" fill="url(#ns-grad)" />
      <text x="16" y="22" textAnchor="middle" fontFamily="DM Sans, sans-serif"
        fontWeight="700" fontSize="14" fill="white" letterSpacing="-0.5">NS</text>
      <defs>
        <linearGradient id="ns-grad" x1="0" y1="0" x2="32" y2="32" gradientUnits="userSpaceOnUse">
          <stop stopColor="#38bdf8" />
          <stop offset="1" stopColor="#0284c7" />
        </linearGradient>
      </defs>
    </svg>
  );
}

export function Header({ organization, onReaudit, isRunning }: HeaderProps) {
  const { accounts, instance } = useMsal();
  const account = accounts[0];

  function handleSignOut() {
    instance.logoutPopup({ account }).catch(() => {
      instance.logoutRedirect({ account });
    });
  }

  return (
    <header className="sticky top-0 z-50 flex items-center gap-3 px-6 py-3 border-b border-[#1e3a5f] bg-[#080d18]/95 backdrop-blur-sm">
      {/* Logo + name */}
      <NSLogo />
      <div className="flex flex-col leading-none">
        <span className="text-sm font-semibold text-text tracking-tight">TenantAudit</span>
        <span className="text-[10px] text-muted">North Stream Systems</span>
      </div>

      {/* Tenant badge */}
      {organization && (
        <div className="ml-4 flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#1e3a5f]/50 border border-[#1e3a5f]">
          <Shield size={12} className="text-blue-400" />
          <span className="text-xs font-medium text-text">{organization.displayName}</span>
        </div>
      )}

      <div className="ml-auto flex items-center gap-3">
        {/* Signed-in account */}
        {account && (
          <span className="text-xs text-muted hidden sm:block truncate max-w-[220px]">
            {account.username}
          </span>
        )}

        {/* Re-audit */}
        {onReaudit && (
          <button
            onClick={onReaudit}
            disabled={isRunning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium
              bg-blue-400/10 text-blue-400 border border-blue-400/30
              hover:bg-blue-400/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <RefreshCw size={12} className={isRunning ? 'animate-spin' : ''} />
            {isRunning ? 'Running…' : 'Re-audit'}
          </button>
        )}

        {/* Sign out */}
        <button
          onClick={handleSignOut}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium
            text-muted hover:text-text hover:bg-[#1e3a5f]/40 border border-transparent
            hover:border-[#1e3a5f] transition-colors"
        >
          <LogOut size={12} />
          <span className="hidden sm:inline">Sign out</span>
        </button>
      </div>
    </header>
  );
}
