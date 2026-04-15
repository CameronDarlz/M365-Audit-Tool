import { useState } from 'react';
import { type AccountInfo } from '@azure/msal-browser';
import { useAudit } from '../hooks/useAudit';
import { Header } from '../components/layout/Header';
import { TabBar, type TabId } from '../components/layout/TabBar';
import { Overview } from '../components/dashboard/Overview';
import { TabMfa } from '../components/dashboard/tabs/TabMfa';
import { TabConditionalAccess } from '../components/dashboard/tabs/TabConditionalAccess';
import { TabPrivileged } from '../components/dashboard/tabs/TabPrivileged';
import { TabApplications } from '../components/dashboard/tabs/TabApplications';
import { TabDevices } from '../components/dashboard/tabs/TabDevices';
import { TabEmailSecurity } from '../components/dashboard/tabs/TabEmailSecurity';
import { TabUsers } from '../components/dashboard/tabs/TabUsers';
import { TabGovernance } from '../components/dashboard/tabs/TabGovernance';
import { TabSecureScore } from '../components/dashboard/tabs/TabSecureScore';
import { TabRemediation } from '../components/dashboard/tabs/TabRemediation';
import { TabReport } from '../components/dashboard/tabs/TabReport';
import { LoadingPage } from './LoadingPage';
import { Shield } from 'lucide-react';

interface DashboardPageProps {
  account: AccountInfo;
}

export function DashboardPage({ account }: DashboardPageProps) {
  const { audit, isRunning, isDone, error, collectorStates, startAudit } = useAudit(account);
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  // ── Loading state ─────────────────────────────────────────────────────────
  if (isRunning || (!isDone && !error)) {
    return (
      <div className="min-h-screen bg-background text-text">
        <Header organization={null} isRunning={isRunning} />
        {isRunning
          ? <LoadingPage states={collectorStates} />
          : <StartAuditPrompt onStart={startAudit} />}
      </div>
    );
  }

  // ── Error state ───────────────────────────────────────────────────────────
  if (error) {
    return (
      <div className="min-h-screen bg-background text-text">
        <Header organization={null} onReaudit={startAudit} />
        <div className="max-w-lg mx-auto mt-16 p-6">
          <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-6 text-center space-y-3">
            <p className="text-red-400 font-semibold">Audit failed</p>
            <p className="text-sm text-muted">{error}</p>
            <button
              onClick={startAudit}
              className="px-4 py-2 rounded-lg bg-[#1e3a5f] text-text text-sm hover:bg-[#1e3a5f]/80 transition-colors"
            >
              Try again
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ── No audit yet ─────────────────────────────────────────────────────────
  if (!audit) {
    return (
      <div className="min-h-screen bg-background text-text">
        <Header organization={null} isRunning={false} />
        <StartAuditPrompt onStart={startAudit} />
      </div>
    );
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  const { result, scores, findings } = audit;
  const findingsFor = (category: string) => findings.filter(f => f.category === category);

  // ── Dashboard ─────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-background text-text">
      <Header
        organization={result.org.organization}
        onReaudit={startAudit}
        isRunning={isRunning}
      />
      <TabBar active={activeTab} onChange={setActiveTab} />

      <main>
        {activeTab === 'overview' && (
          <Overview audit={audit} />
        )}

        {activeTab === 'mfa' && (
          <TabMfa
            data={result.mfa}
            score={scores['mfa']}
            findings={findingsFor('MFA & Authentication')}
          />
        )}

        {activeTab === 'conditionalAccess' && (
          <TabConditionalAccess
            data={result.conditionalAccess}
            score={scores['conditionalAccess']}
            findings={findingsFor('Conditional Access')}
          />
        )}

        {activeTab === 'privilegedAccess' && (
          <TabPrivileged
            rolesData={result.roles}
            mfaData={result.mfa}
            usersData={result.users}
            score={scores['privilegedAccess']}
            findings={findingsFor('Privileged Access')}
          />
        )}

        {activeTab === 'applications' && (
          <TabApplications
            data={result.applications}
            score={scores['applications']}
            findings={findingsFor('Applications')}
          />
        )}

        {activeTab === 'devices' && (
          <TabDevices
            data={result.devices}
            score={scores['devices']}
            findings={findingsFor('Devices')}
          />
        )}

        {activeTab === 'emailSecurity' && (
          <TabEmailSecurity
            data={result.emailSecurity}
            score={scores['emailSecurity']}
            findings={findingsFor('Email Security')}
          />
        )}

        {activeTab === 'users' && (
          <TabUsers
            usersData={result.users}
            licencesData={result.licences}
            score={scores['userHygiene']}
            findings={findingsFor('User Hygiene')}
          />
        )}

        {activeTab === 'governance' && (
          <TabGovernance
            groupsData={result.groups}
            externalCollabData={result.externalCollab}
            score={scores['governance']}
            findings={findingsFor('Governance')}
          />
        )}

        {activeTab === 'secureScore' && (
          <TabSecureScore
            data={result.secureScore}
            findings={findingsFor('Secure Score')}
          />
        )}

        {activeTab === 'remediation' && (
          <TabRemediation findings={findings} />
        )}

        {activeTab === 'report' && (
          <TabReport audit={audit} />
        )}
      </main>
    </div>
  );
}

function StartAuditPrompt({ onStart }: { onStart: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] px-4">
      <div className="max-w-sm text-center space-y-6">
        <div className="w-16 h-16 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center mx-auto">
          <Shield size={28} className="text-blue-400" />
        </div>
        <div className="space-y-2">
          <h2 className="text-xl font-bold text-text">Ready to audit</h2>
          <p className="text-sm text-muted leading-relaxed">
            Run a full Microsoft 365 security assessment against this tenant. The audit collects data
            from Microsoft Graph and typically completes in 30–90 seconds.
          </p>
        </div>
        <button
          onClick={onStart}
          className="w-full py-3 rounded-xl bg-blue-500 hover:bg-blue-400 text-white font-semibold
            transition-colors text-sm"
        >
          Start Audit
        </button>
        <p className="text-[11px] text-muted/50">
          Read-only permissions only. No changes are made to your tenant.
        </p>
      </div>
    </div>
  );
}
