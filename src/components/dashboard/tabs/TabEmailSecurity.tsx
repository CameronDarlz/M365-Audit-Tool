import { EmailSecurityData, Finding, CategoryScore } from '../../../types/audit';
import { FindingCard } from '../FindingCard';
import { ScoreRing } from '../ScoreRing';
import { CheckCircle2, XCircle, AlertTriangle } from 'lucide-react';
import { cn } from '../../../lib/utils';

interface TabEmailSecurityProps {
  data: EmailSecurityData;
  score: CategoryScore;
  findings: Finding[];
}

export function TabEmailSecurity({ data, score, findings }: TabEmailSecurityProps) {
  const { domain, spfRecord, dmarcRecord, dkim1Record, dkim2Record, mxRecords } = data;

  const spfPresent  = Boolean(spfRecord);
  const spfEnforced = spfRecord?.includes('-all');
  const dmarcPresent   = Boolean(dmarcRecord);
  const dmarcEnforced  = dmarcRecord?.includes('p=reject') || dmarcRecord?.includes('p=quarantine');
  const dkimPresent    = Boolean(dkim1Record || dkim2Record);
  const exchangeMx     = mxRecords.some(r => r.includes('mail.protection.outlook.com'));

  return (
    <div className="p-6 space-y-6">
      {/* Score + domain */}
      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <ScoreRing score={score.score} grade={score.grade} label="Email Security" size={100} strokeWidth={8} />
        <div>
          <p className="text-xs text-muted mb-1">Primary domain</p>
          <p className="text-xl font-mono font-bold text-text">{domain || '—'}</p>
          <p className="text-xs text-muted mt-2">DNS checks run against public DNS (Google DNS-over-HTTPS)</p>
        </div>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-text">Findings ({findings.length})</h3>
          {findings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}

      {/* Summary checks */}
      <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <h3 className="text-sm font-semibold text-text mb-4">Email Authentication Summary</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <DnsCheck label="SPF record present"         pass={spfPresent}   />
          <DnsCheck label="SPF enforced (-all)"        pass={Boolean(spfEnforced)} warn={spfPresent && !spfEnforced} />
          <DnsCheck label="DMARC record present"       pass={dmarcPresent} />
          <DnsCheck label="DMARC enforced (p=quarantine/reject)" pass={Boolean(dmarcEnforced)} warn={dmarcPresent && !dmarcEnforced} />
          <DnsCheck label="DKIM configured"            pass={dkimPresent}  />
          <DnsCheck label="MX → Exchange Online"       pass={exchangeMx}   info={!exchangeMx && mxRecords.length > 0} />
        </div>
      </div>

      {/* Raw record values */}
      <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5 space-y-4">
        <h3 className="text-sm font-semibold text-text">Raw DNS Records</h3>
        <RecordRow label={`SPF (TXT @ ${domain})`}              value={spfRecord}  />
        <RecordRow label={`DMARC (TXT _dmarc.${domain})`}       value={dmarcRecord} />
        <RecordRow label={`DKIM selector1 (TXT selector1._domainkey.${domain})`} value={dkim1Record} truncate />
        <RecordRow label={`DKIM selector2 (TXT selector2._domainkey.${domain})`} value={dkim2Record} truncate />
        {mxRecords.length > 0 && (
          <div>
            <p className="text-[10px] font-medium uppercase tracking-wider text-muted mb-1">MX records</p>
            <div className="space-y-1">
              {mxRecords.map((r, i) => (
                <p key={i} className={cn('text-xs font-mono px-3 py-1.5 rounded bg-[#162032] border border-[#1e3a5f]',
                  r.includes('mail.protection.outlook.com') ? 'text-green-400' : 'text-muted')}>
                  {r}
                </p>
              ))}
            </div>
          </div>
        )}
      </div>

      {data.error && (
        <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-400">
          <strong>DNS error:</strong> {data.error}
        </div>
      )}
    </div>
  );
}

function DnsCheck({ label, pass, warn = false, info = false }: { label: string; pass: boolean; warn?: boolean; info?: boolean }) {
  const Icon = pass ? CheckCircle2 : warn ? AlertTriangle : info ? AlertTriangle : XCircle;
  const color = pass ? 'text-green-400' : warn ? 'text-yellow-400' : info ? 'text-blue-400' : 'text-red-400';
  const bg    = pass ? 'bg-green-400/5 border-green-400/20' : warn ? 'bg-yellow-400/5 border-yellow-400/20' : info ? 'bg-blue-400/5 border-blue-400/20' : 'bg-red-400/5 border-red-400/20';
  const status = pass ? 'Pass' : warn ? 'Warn' : info ? 'Info' : 'Fail';
  return (
    <div className={cn('flex items-center gap-2 px-3 py-2 rounded-lg border', bg)}>
      <Icon size={13} className={cn('flex-shrink-0', color)} />
      <span className="text-xs text-muted">{label}</span>
      <span className={cn('ml-auto text-xs font-medium', color)}>{status}</span>
    </div>
  );
}

function RecordRow({ label, value, truncate = false }: { label: string; value: string | null; truncate?: boolean }) {
  return (
    <div>
      <p className="text-[10px] font-medium uppercase tracking-wider text-muted mb-1">{label}</p>
      {value
        ? <p className={cn('text-xs font-mono px-3 py-2 rounded-lg bg-[#162032] border border-[#1e3a5f] text-text', truncate && 'truncate')}>
            {value}
          </p>
        : <p className="text-xs text-muted/50 px-3 py-2 rounded-lg bg-[#162032] border border-[#1e3a5f]">Not found</p>
      }
    </div>
  );
}
