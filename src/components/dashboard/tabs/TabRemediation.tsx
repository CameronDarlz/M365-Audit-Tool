import { useState } from 'react';
import type { Finding } from '../../../types/audit';
import { remediationSteps, type RemediationGuide } from '../../../engine/remediationSteps';
import { severityBg, effortMinutesLabel, cn } from '../../../lib/utils';
import { CheckSquare, Square, ExternalLink, ChevronDown, ChevronUp, Zap, Settings, ClipboardList } from 'lucide-react';

interface TabRemediationProps {
  findings: Finding[];
}

const EFFORT_CONFIG = {
  'quick-win': {
    label: '⚡ Quick Wins — complete these first',
    sublabel: 'Single portal change, under 30 mins, no user impact',
    color: 'text-green-400',
    bg: 'bg-green-400/5',
    border: 'border-green-400/20',
    Icon: Zap,
  },
  medium: {
    label: '⚙ Medium Effort — schedule these this week',
    sublabel: 'Requires planning or user communication, 1–4 hours',
    color: 'text-yellow-400',
    bg: 'bg-yellow-400/5',
    border: 'border-yellow-400/20',
    Icon: Settings,
  },
  project: {
    label: '📋 Project Work — scope and plan these',
    sublabel: 'Multi-week, coordination required, potential disruption',
    color: 'text-orange-400',
    bg: 'bg-orange-400/5',
    border: 'border-orange-400/20',
    Icon: ClipboardList,
  },
};

function RemediationCard({
  finding,
  guide,
  done,
  onToggle,
}: {
  finding: Finding;
  guide: RemediationGuide | null;
  done: boolean;
  onToggle: () => void;
}) {
  const [expanded, setExpanded] = useState(true);

  return (
    <div className={cn(
      'rounded-xl border border-[#1e3a5f] bg-[#0f172a] overflow-hidden transition-opacity',
      done && 'opacity-40',
    )}>
      {/* Header */}
      <div className="flex items-start gap-3 p-4">
        <button onClick={onToggle} className="mt-0.5 flex-shrink-0 text-muted hover:text-text transition-colors">
          {done ? <CheckSquare size={16} className="text-green-400" /> : <Square size={16} />}
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className={cn('inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border', severityBg(finding.severity))}>
              {finding.severity}
            </span>
            <span className="text-[10px] text-muted">{finding.category}</span>
            {finding.affectedCount !== undefined && finding.affectedCount > 0 && (
              <span className="text-[10px] font-mono text-muted">
                {finding.affectedCount} affected
              </span>
            )}
          </div>
          <h3 className={cn('text-sm font-semibold leading-snug', done ? 'line-through text-muted' : 'text-text')}>
            {finding.title}
          </h3>
        </div>
        <button onClick={() => setExpanded(e => !e)} className="flex-shrink-0 text-muted mt-0.5 hover:text-text transition-colors">
          {expanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
        </button>
      </div>

      {/* Body */}
      {expanded && !done && (
        <div className="px-4 pb-4 pl-11 space-y-3">
          <div className="h-px bg-[#1e3a5f]" />

          {guide ? (
            <>
              {/* Why it matters */}
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted mb-1">Why this matters</p>
                <p className="text-sm text-muted leading-relaxed">{guide.whyItMatters}</p>
              </div>

              {/* Steps */}
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted mb-2">How to fix</p>
                <ol className="space-y-2">
                  {guide.steps.map((step, i) => (
                    <li key={i} className="flex gap-2.5 text-sm text-text">
                      <span className="flex-shrink-0 w-5 h-5 rounded-full bg-[#1e3a5f] flex items-center justify-center text-[10px] font-mono text-muted mt-0.5">
                        {i + 1}
                      </span>
                      <span className="leading-relaxed">{step}</span>
                    </li>
                  ))}
                </ol>
              </div>

              {/* Caveats */}
              {guide.caveats && (
                <div className="rounded-lg bg-yellow-400/5 border border-yellow-400/20 px-3 py-2">
                  <p className="text-xs text-yellow-400">
                    <span className="font-semibold">Note: </span>{guide.caveats}
                  </p>
                </div>
              )}

              {/* Footer */}
              <div className="flex items-center justify-between pt-1">
                {guide.docsUrl ? (
                  <a href={guide.docsUrl} target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors">
                    Microsoft documentation <ExternalLink size={11} />
                  </a>
                ) : <span />}
                <span className="text-xs text-muted">
                  Estimated: {effortMinutesLabel(guide.estimatedMinutes)}
                </span>
              </div>
            </>
          ) : (
            /* Fallback for findings with no guide entry */
            <div className="space-y-2">
              <p className="text-sm text-muted">{finding.description}</p>
              <div className="rounded-lg bg-[#162032] border border-[#1e3a5f] p-3">
                <p className="text-xs text-text">{finding.recommendation}</p>
              </div>
              {finding.learnMoreUrl && (
                <a href={finding.learnMoreUrl} target="_blank" rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors">
                  Microsoft documentation <ExternalLink size={11} />
                </a>
              )}
              <p className="text-xs text-muted/50 italic">Detailed fix guide coming soon.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function EffortSection({
  effort,
  findings,
  doneSet,
  onToggle,
}: {
  effort: 'quick-win' | 'medium' | 'project';
  findings: Finding[];
  doneSet: Set<string>;
  onToggle: (id: string) => void;
}) {
  const cfg = EFFORT_CONFIG[effort];
  if (findings.length === 0) return null;

  const doneCount = findings.filter(f => doneSet.has(f.id)).length;
  const totalMins = findings.reduce((acc, f) => {
    const guide = remediationSteps[f.id];
    return acc + (guide?.estimatedMinutes ?? 0);
  }, 0);

  function markAllDone() {
    findings.forEach(f => { if (!doneSet.has(f.id)) onToggle(f.id); });
  }

  return (
    <div className="space-y-3">
      {/* Section header */}
      <div className={cn('rounded-xl border p-4', cfg.bg, cfg.border)}>
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className={cn('text-sm font-bold', cfg.color)}>{cfg.label}</h3>
            <p className="text-xs text-muted mt-0.5">{cfg.sublabel}</p>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            <div className="text-right">
              <p className={cn('text-xs font-mono font-semibold', cfg.color)}>
                {findings.length} finding{findings.length !== 1 ? 's' : ''}
              </p>
              {totalMins > 0 && (
                <p className="text-[10px] text-muted">{effortMinutesLabel(totalMins)} total</p>
              )}
            </div>
            <button
              onClick={markAllDone}
              className={cn(
                'px-2.5 py-1 rounded-md text-xs font-medium border transition-colors',
                cfg.color, cfg.border, cfg.bg,
                'hover:opacity-80',
              )}
            >
              Mark all done
            </button>
          </div>
        </div>
        {doneCount > 0 && (
          <div className="mt-2">
            <div className="h-1 rounded-full bg-[#1e3a5f] overflow-hidden">
              <div className="h-full rounded-full bg-green-400 transition-all duration-500"
                style={{ width: `${(doneCount / findings.length) * 100}%` }} />
            </div>
          </div>
        )}
      </div>

      {/* Cards */}
      {findings.map(f => (
        <RemediationCard
          key={f.id}
          finding={f}
          guide={remediationSteps[f.id] ?? null}
          done={doneSet.has(f.id)}
          onToggle={() => onToggle(f.id)}
        />
      ))}
    </div>
  );
}

export function TabRemediation({ findings }: TabRemediationProps) {
  const [doneSet, setDoneSet] = useState<Set<string>>(new Set());

  function toggleDone(id: string) {
    setDoneSet(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const quickWins = findings.filter(f => f.effort === 'quick-win');
  const medium    = findings.filter(f => f.effort === 'medium');
  const project   = findings.filter(f => f.effort === 'project');

  const totalDone = doneSet.size;
  const totalFindings = findings.length;
  const overallProgress = totalFindings > 0 ? Math.round((totalDone / totalFindings) * 100) : 0;

  return (
    <div className="p-6 space-y-8">
      {/* Progress tracker */}
      <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-text">Remediation Progress</h3>
          <span className="text-xs font-mono text-muted">
            {totalDone} of {totalFindings} findings resolved
          </span>
        </div>
        <div className="h-2 rounded-full bg-[#162032] overflow-hidden mb-3">
          <div className="h-full rounded-full bg-green-400 transition-all duration-500"
            style={{ width: `${overallProgress}%` }} />
        </div>
        <div className="flex flex-wrap gap-4 text-xs">
          <span className="text-green-400">
            Quick wins: {quickWins.filter(f => doneSet.has(f.id)).length}/{quickWins.length}
            {quickWins.filter(f => doneSet.has(f.id)).length === quickWins.length && quickWins.length > 0 && ' ✓'}
          </span>
          <span className="text-yellow-400">
            Medium: {medium.filter(f => doneSet.has(f.id)).length}/{medium.length}
            {medium.filter(f => doneSet.has(f.id)).length === medium.length && medium.length > 0 && ' ✓'}
          </span>
          <span className="text-orange-400">
            Project: {project.filter(f => doneSet.has(f.id)).length}/{project.length}
            {project.filter(f => doneSet.has(f.id)).length === project.length && project.length > 0 && ' ✓'}
          </span>
        </div>
        <p className="text-[10px] text-muted/50 mt-2">Progress resets on re-audit</p>
      </div>

      {/* Sections */}
      <EffortSection effort="quick-win" findings={quickWins} doneSet={doneSet} onToggle={toggleDone} />
      <EffortSection effort="medium"    findings={medium}    doneSet={doneSet} onToggle={toggleDone} />
      <EffortSection effort="project"   findings={project}   doneSet={doneSet} onToggle={toggleDone} />

      {findings.length === 0 && (
        <div className="text-center py-16 text-muted text-sm">
          No findings to remediate — excellent posture!
        </div>
      )}
    </div>
  );
}
