import { cn } from '../../lib/utils';

export type TabId =
  | 'overview'
  | 'mfa'
  | 'conditionalAccess'
  | 'privilegedAccess'
  | 'applications'
  | 'devices'
  | 'emailSecurity'
  | 'users'
  | 'governance'
  | 'secureScore'
  | 'remediation'
  | 'report';

export const TABS: { id: TabId; label: string }[] = [
  { id: 'overview',          label: 'Overview' },
  { id: 'mfa',               label: 'MFA & Auth' },
  { id: 'conditionalAccess', label: 'Conditional Access' },
  { id: 'privilegedAccess',  label: 'Privileged Access' },
  { id: 'applications',      label: 'Applications' },
  { id: 'devices',           label: 'Devices' },
  { id: 'emailSecurity',     label: 'Email Security' },
  { id: 'users',             label: 'Users' },
  { id: 'governance',        label: 'Governance' },
  { id: 'secureScore',       label: 'Secure Score' },
  { id: 'remediation',       label: 'Remediation' },
  { id: 'report',            label: 'Report' },
];

interface TabBarProps {
  active: TabId;
  onChange: (id: TabId) => void;
}

export function TabBar({ active, onChange }: TabBarProps) {
  return (
    <div className="sticky top-[57px] z-40 bg-[#0f172a] border-b border-[#1e3a5f] overflow-x-auto">
      <nav className="flex min-w-max px-4" aria-label="Dashboard tabs">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => onChange(tab.id)}
            className={cn(
              'px-4 py-3 text-sm font-medium whitespace-nowrap border-b-2 transition-colors',
              active === tab.id
                ? 'border-blue-400 text-blue-400'
                : 'border-transparent text-muted hover:text-text hover:border-[#1e3a5f]',
            )}
          >
            {tab.label}
          </button>
        ))}
      </nav>
    </div>
  );
}
