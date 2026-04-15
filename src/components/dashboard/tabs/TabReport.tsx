import { useRef } from 'react';
import type { ScoredAudit } from '../../../types/audit';
import { remediationSteps } from '../../../engine/remediationSteps';
import { gradeColor, severityColor, effortMinutesLabel, formatDateTime } from '../../../lib/utils';
import { Printer } from 'lucide-react';

interface TabReportProps {
  audit: ScoredAudit;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

const GRADE_LABEL: Record<string, string> = {
  good: 'Good',
  fair: 'Fair',
  poor: 'Poor',
  critical: 'Critical',
};

export function TabReport({ audit }: TabReportProps) {
  const reportRef = useRef<HTMLDivElement>(null);
  const { result, scores, overallScore, overallGrade, findings } = audit;
  const org = result.org.organization;
  const domain = result.emailSecurity.domain || org?.verifiedDomains.find(d => d.isDefault)?.name || '—';
  const auditDate = formatDateTime(result.auditedAt);

  const quickWins = findings.filter(f => f.effort === 'quick-win');
  const medium    = findings.filter(f => f.effort === 'medium');
  const project   = findings.filter(f => f.effort === 'project');

  const severityCounts = SEVERITY_ORDER.reduce<Record<string, number>>((acc, s) => {
    acc[s] = findings.filter(f => f.severity === s).length;
    return acc;
  }, {});

  function handlePrint() {
    window.print();
  }

  return (
    <div className="p-6 space-y-6">
      {/* Print button — hidden when printing */}
      <div className="flex justify-end no-print">
        <button
          onClick={handlePrint}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-500/10 border border-blue-500/20
            text-blue-400 text-sm font-medium hover:bg-blue-500/20 transition-colors"
        >
          <Printer size={14} /> Print / Save as PDF
        </button>
      </div>

      {/* ── REPORT BODY ── */}
      <div ref={reportRef} className="print-report space-y-8">

        {/* Cover */}
        <div className="rounded-2xl border border-[#1e3a5f] bg-[#0f172a] p-8 text-center space-y-4">
          <div className="text-xs font-semibold uppercase tracking-widest text-muted">
            Microsoft 365 Security Audit Report
          </div>
          <h1 className="text-2xl font-bold text-text">
            {org?.displayName ?? domain}
          </h1>
          <p className="text-sm text-muted">{domain}</p>
          <div className="inline-block mx-auto">
            <div
              className="w-24 h-24 rounded-full border-4 flex flex-col items-center justify-center mx-auto"
              style={{ borderColor: gradeColor(overallGrade) }}
            >
              <span className="text-3xl font-bold font-mono" style={{ color: gradeColor(overallGrade) }}>
                {overallScore}
              </span>
              <span className="text-[10px] text-muted uppercase tracking-wider">/ 100</span>
            </div>
          </div>
          <div>
            <span
              className="inline-block px-4 py-1 rounded-full text-sm font-semibold uppercase tracking-wider border"
              style={{ color: gradeColor(overallGrade), borderColor: `${gradeColor(overallGrade)}40`, background: `${gradeColor(overallGrade)}15` }}
            >
              {GRADE_LABEL[overallGrade]} Security Posture
            </span>
          </div>
          <p className="text-xs text-muted">Audited: {auditDate}</p>
        </div>

        {/* Executive Summary */}
        <section className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-6 space-y-4">
          <h2 className="text-base font-bold text-text border-b border-[#1e3a5f] pb-2">Executive Summary</h2>
          <p className="text-sm text-muted leading-relaxed">
            This report summarises the Microsoft 365 security posture of{' '}
            <strong className="text-text">{org?.displayName ?? domain}</strong> as assessed on{' '}
            <strong className="text-text">{auditDate}</strong>. The tenant achieved an overall security score of{' '}
            <strong style={{ color: gradeColor(overallGrade) }}>{overallScore}/100 ({GRADE_LABEL[overallGrade]})</strong>.
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {SEVERITY_ORDER.map(s => (
              <div key={s} className="text-center rounded-lg bg-[#162032] border border-[#1e3a5f] py-3 px-2">
                <p className="text-xl font-bold font-mono" style={{ color: severityColor(s) }}>
                  {severityCounts[s] ?? 0}
                </p>
                <p className="text-[10px] text-muted uppercase tracking-wider mt-0.5 capitalize">{s}</p>
              </div>
            ))}
          </div>
          <p className="text-sm text-muted">
            {findings.length} total findings were identified: {quickWins.length} quick wins, {medium.length} medium effort, and {project.length} project-level remediations.
          </p>
        </section>

        {/* Category Scores */}
        <section className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-6 space-y-4">
          <h2 className="text-base font-bold text-text border-b border-[#1e3a5f] pb-2">Security Category Scores</h2>
          <div className="space-y-3">
            {Object.entries(scores)
              .sort(([, a], [, b]) => a.score - b.score)
              .map(([key, cat]) => (
                <div key={key}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-text font-medium">{cat.label}</span>
                    <div className="flex items-center gap-3">
                      <span className="text-muted text-[10px] uppercase">weight {(cat.weight * 100).toFixed(0)}%</span>
                      <span className="font-mono font-semibold" style={{ color: gradeColor(cat.grade) }}>
                        {cat.score}/100 — {GRADE_LABEL[cat.grade]}
                      </span>
                    </div>
                  </div>
                  <div className="h-2 rounded-full bg-[#162032] overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${cat.score}%`, backgroundColor: gradeColor(cat.grade) }}
                    />
                  </div>
                </div>
              ))}
          </div>
        </section>

        {/* Findings by Severity */}
        {findings.length > 0 && (
          <section className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-6 space-y-4">
            <h2 className="text-base font-bold text-text border-b border-[#1e3a5f] pb-2">Findings</h2>
            {SEVERITY_ORDER.filter(s => severityCounts[s] > 0).map(sev => (
              <div key={sev} className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: severityColor(sev) }}>
                  {sev} ({severityCounts[sev]})
                </h3>
                {findings.filter(f => f.severity === sev).map(f => (
                  <div key={f.id} className="px-4 py-3 rounded-lg bg-[#162032] border border-[#1e3a5f] space-y-1.5">
                    <div className="flex items-start justify-between gap-3">
                      <p className="text-sm font-semibold text-text leading-snug">{f.title}</p>
                      <span
                        className="flex-shrink-0 text-[10px] px-2 py-0.5 rounded-full border uppercase font-semibold tracking-wide"
                        style={{ color: severityColor(f.severity), borderColor: `${severityColor(f.severity)}40`, background: `${severityColor(f.severity)}15` }}
                      >
                        {f.effort === 'quick-win' ? '⚡ Quick Win' : f.effort === 'medium' ? '⚙ Medium' : '📋 Project'}
                      </span>
                    </div>
                    <p className="text-xs text-muted leading-relaxed">{f.description}</p>
                    <p className="text-xs text-text/70 leading-relaxed">
                      <span className="font-semibold text-muted">Recommendation: </span>{f.recommendation}
                    </p>
                    {f.affectedCount !== undefined && f.affectedCount > 0 && (
                      <p className="text-[10px] text-muted/70 font-mono">{f.affectedCount} affected</p>
                    )}
                  </div>
                ))}
              </div>
            ))}
          </section>
        )}

        {/* Remediation Roadmap */}
        {findings.length > 0 && (
          <section className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-6 space-y-6">
            <h2 className="text-base font-bold text-text border-b border-[#1e3a5f] pb-2">Remediation Roadmap</h2>

            {quickWins.length > 0 && (
              <RoadmapSection
                title="⚡ Quick Wins"
                subtitle="Complete these first — single portal change, under 30 mins, no user impact"
                color="text-green-400"
                findings={quickWins}
              />
            )}
            {medium.length > 0 && (
              <RoadmapSection
                title="⚙ Medium Effort"
                subtitle="Schedule these this week — requires planning or user communication"
                color="text-yellow-400"
                findings={medium}
              />
            )}
            {project.length > 0 && (
              <RoadmapSection
                title="📋 Project Work"
                subtitle="Scope and plan these — multi-week, coordination required"
                color="text-orange-400"
                findings={project}
              />
            )}
          </section>
        )}

        {/* Footer */}
        <div className="text-center text-[10px] text-muted/50 py-2">
          Generated by North Stream Systems · M365 Audit Tool · {auditDate}
        </div>
      </div>
    </div>
  );
}

function RoadmapSection({
  title,
  subtitle,
  color,
  findings,
}: {
  title: string;
  subtitle: string;
  color: string;
  findings: ScoredAudit['findings'];
}) {
  return (
    <div className="space-y-3">
      <div>
        <h3 className={`text-sm font-bold ${color}`}>{title}</h3>
        <p className="text-[11px] text-muted mt-0.5">{subtitle}</p>
      </div>
      {findings.map((f, idx) => {
        const guide = remediationSteps[f.id] ?? null;
        return (
          <div key={f.id} className="rounded-lg border border-[#1e3a5f] bg-[#162032] overflow-hidden">
            <div className="flex items-center gap-3 px-4 py-2.5 border-b border-[#1e3a5f]/50">
              <span className="w-5 h-5 flex-shrink-0 rounded-full bg-[#1e3a5f] flex items-center justify-center text-[10px] font-mono text-muted">
                {idx + 1}
              </span>
              <p className="text-sm font-semibold text-text flex-1">{f.title}</p>
              {guide && (
                <span className="text-[10px] text-muted flex-shrink-0">
                  {effortMinutesLabel(guide.estimatedMinutes)}
                </span>
              )}
            </div>
            {guide ? (
              <div className="px-4 py-3 space-y-2">
                {guide.whyItMatters && (
                  <p className="text-xs text-muted leading-relaxed italic">"{guide.whyItMatters}"</p>
                )}
                <ol className="space-y-1.5">
                  {guide.steps.map((step, i) => (
                    <li key={i} className="flex gap-2 text-xs text-text">
                      <span className="flex-shrink-0 w-4 h-4 rounded-full bg-[#1e3a5f] flex items-center justify-center text-[9px] font-mono text-muted mt-0.5">
                        {i + 1}
                      </span>
                      <span className="leading-relaxed">{step}</span>
                    </li>
                  ))}
                </ol>
                {guide.caveats && (
                  <p className="text-[11px] text-yellow-400/80">⚠ {guide.caveats}</p>
                )}
              </div>
            ) : (
              <div className="px-4 py-3">
                <p className="text-xs text-muted">{f.recommendation}</p>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
