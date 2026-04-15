import type { MfaData, Finding, CategoryScore } from '../../../types/audit';
import { FindingCard } from '../FindingCard';
import { ScoreRing } from '../ScoreRing';
import { pct, downloadCsv } from '../../../lib/utils';
import { Download, CheckCircle2, XCircle, ShieldCheck } from 'lucide-react';

interface TabMfaProps {
  data: MfaData;
  score: CategoryScore;
  findings: Finding[];
}

const METHOD_LABELS: Record<string, string> = {
  microsoftAuthenticatorPush:    'Authenticator (push)',
  microsoftAuthenticatorPasswordless: 'Authenticator (passwordless)',
  softwareOneTimePasscode:       'Software TOTP',
  hardwareOneTimePasscode:       'Hardware TOTP',
  sms:                           'SMS',
  voice:                         'Voice call',
  email:                         'Email OTP',
  fido2:                         'FIDO2 / Security key',
  windowsHelloForBusiness:       'Windows Hello',
  temporaryAccessPass:           'Temporary Access Pass',
};

export function TabMfa({ data, score, findings }: TabMfaProps) {
  const { registrationDetails, authMethodsPolicy } = data;

  const total        = registrationDetails.length;
  const registered   = registrationDetails.filter(u => u.isMfaRegistered).length;
  const passwordless = registrationDetails.filter(u => u.isPasswordlessCapable).length;

  const methodCounts = registrationDetails.reduce<Record<string, number>>((acc, u) => {
    for (const m of u.methodsRegistered) {
      acc[m] = (acc[m] ?? 0) + 1;
    }
    return acc;
  }, {});

  const weakMethods = ['sms', 'voice'];
  const weakOnly = registrationDetails.filter(u =>
    u.isMfaRegistered && u.methodsRegistered.every(m => weakMethods.includes(m)),
  ).length;

  function exportCsv() {
    downloadCsv('mfa-registration.csv', registrationDetails.map(u => ({
      UPN: u.userPrincipalName,
      DisplayName: u.userDisplayName,
      MFARegistered: u.isMfaRegistered,
      PasswordlessCapable: u.isPasswordlessCapable,
      DefaultMethod: u.defaultMfaMethod,
      Methods: u.methodsRegistered.join('; '),
    })));
  }

  // Auth method policy status
  const methodConfigs = authMethodsPolicy?.authenticationMethodConfigurations ?? [];
  const fido2    = methodConfigs.find(c => c.id === 'Fido2');
  const authApp  = methodConfigs.find(c => c.id === 'MicrosoftAuthenticator');
  const sms      = methodConfigs.find(c => c.id === 'Sms');
  const voice    = methodConfigs.find(c => c.id === 'Voice');
  const numMatch = authApp?.featureSettings?.numberMatchingRequiredState?.state;
  const addCtx   = authApp?.featureSettings?.displayAppInformationRequiredState?.state;

  return (
    <div className="p-6 space-y-6">
      {/* Score + key metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <ScoreRing score={score.score} grade={score.grade} label="MFA & Auth" size={100} strokeWidth={8} />
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
          <Stat label="MFA registered" value={`${registered} / ${total}`} sub={pct(registered, total)} color={registered / total >= 0.9 ? 'text-green-400' : 'text-red-400'} />
          <Stat label="Passwordless capable" value={passwordless} sub={pct(passwordless, total)} />
          <Stat label="Weak method only (SMS/voice)" value={weakOnly} color={weakOnly > 0 ? 'text-orange-400' : 'text-green-400'} />
        </div>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-text">Findings ({findings.length})</h3>
          {findings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}

      {/* Auth methods policy */}
      {authMethodsPolicy && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-4">Authentication Method Policy</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <PolicyRow label="FIDO2 security keys"       enabled={fido2?.state === 'enabled'}    />
            <PolicyRow label="Microsoft Authenticator"   enabled={authApp?.state === 'enabled'}  />
            <PolicyRow label="Number matching (Authenticator)" enabled={numMatch === 'enabled'}  />
            <PolicyRow label="Additional context (app name)"   enabled={addCtx  === 'enabled'}  />
            <PolicyRow label="SMS (legacy)"              enabled={sms?.state === 'enabled'}   warn />
            <PolicyRow label="Voice call (legacy)"       enabled={voice?.state === 'enabled'} warn />
          </div>
        </div>
      )}

      {/* Method distribution */}
      {Object.keys(methodCounts).length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-4">Registered Method Distribution</h3>
          <div className="space-y-2.5">
            {Object.entries(methodCounts)
              .sort((a, b) => b[1] - a[1])
              .map(([method, count]) => (
                <div key={method}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-muted">{METHOD_LABELS[method] ?? method}</span>
                    <span className="font-mono text-text">{count} ({pct(count, total)})</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-[#1e3a5f] overflow-hidden">
                    <div className="h-full rounded-full bg-blue-400"
                      style={{ width: pct(count, total) }} />
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* User registration table */}
      {registrationDetails.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-[#1e3a5f]">
            <h3 className="text-sm font-semibold text-text">User Registration Detail</h3>
            <button onClick={exportCsv}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs text-muted hover:text-text
                hover:bg-[#1e3a5f]/40 border border-transparent hover:border-[#1e3a5f] transition-colors">
              <Download size={12} /> Export CSV
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e3a5f]">
                  {['User', 'MFA', 'Passwordless', 'Default method', 'Methods'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-[10px] uppercase tracking-wider text-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e3a5f]/50">
                {registrationDetails.slice(0, 50).map(u => (
                  <tr key={u.id} className="hover:bg-[#162032] transition-colors">
                    <td className="px-4 py-2.5 font-mono text-text truncate max-w-[200px]">{u.userPrincipalName}</td>
                    <td className="px-4 py-2.5">
                      {u.isMfaRegistered
                        ? <CheckCircle2 size={13} className="text-green-400" />
                        : <XCircle size={13} className="text-red-400" />}
                    </td>
                    <td className="px-4 py-2.5">
                      {u.isPasswordlessCapable
                        ? <ShieldCheck size={13} className="text-green-400" />
                        : <span className="text-muted">—</span>}
                    </td>
                    <td className="px-4 py-2.5 text-muted">{METHOD_LABELS[u.defaultMfaMethod] ?? u.defaultMfaMethod ?? '—'}</td>
                    <td className="px-4 py-2.5 text-muted">{u.methodsRegistered.map(m => METHOD_LABELS[m] ?? m).join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {registrationDetails.length > 50 && (
              <p className="text-center text-xs text-muted py-3">
                Showing 50 of {registrationDetails.length} users
              </p>
            )}
          </div>
        </div>
      )}

      {data.error && (
        <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-400">
          <strong>Collection error:</strong> {data.error}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, sub, color = 'text-text' }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div>
      <p className={`text-xl font-bold font-mono ${color}`}>{value}</p>
      <p className="text-[10px] text-muted leading-tight mt-0.5">{label}</p>
      {sub && <p className={`text-xs font-mono mt-0.5 ${color}`}>{sub}</p>}
    </div>
  );
}

function PolicyRow({ label, enabled, warn = false }: { label: string; enabled: boolean | undefined; warn?: boolean }) {
  const isGood = warn ? !enabled : enabled;
  return (
    <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#162032] border border-[#1e3a5f]">
      {isGood
        ? <CheckCircle2 size={13} className="text-green-400 flex-shrink-0" />
        : <XCircle size={13} className="text-red-400 flex-shrink-0" />}
      <span className="text-xs text-muted">{label}</span>
      <span className={`ml-auto text-xs font-medium ${isGood ? 'text-green-400' : 'text-red-400'}`}>
        {enabled === undefined ? '—' : enabled ? 'Enabled' : 'Disabled'}
      </span>
    </div>
  );
}
