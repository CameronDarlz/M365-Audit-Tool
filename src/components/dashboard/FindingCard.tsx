import { useState } from 'react';
import { ChevronDown, ChevronUp, ExternalLink } from 'lucide-react';
import { Finding } from '../../types/audit';
import { cn, severityBg, severityColor, effortLabel } from '../../lib/utils';

interface FindingCardProps {
  finding: Finding;
  compact?: boolean;
}

const EFFORT_COLORS: Record<string, string> = {
  'quick-win': 'text-green-400 bg-green-400/10 border-green-400/20',
  'medium':    'text-yellow-400 bg-yellow-400/10 border-yellow-400/20',
  'project':   'text-orange-400 bg-orange-400/10 border-orange-400/20',
};

export function FindingCard({ finding, compact = false }: FindingCardProps) {
  const [expanded, setExpanded] = useState(!compact);
  const hasItems = (finding.affectedItems?.length ?? 0) > 0;
  const [showAllItems, setShowAllItems] = useState(false);

  const severityBorderColor = severityColor(finding.severity);

  return (
    <div
      className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] overflow-hidden fade-in"
      style={{ borderLeftWidth: 3, borderLeftColor: severityBorderColor }}
    >
      {/* Header */}
      <div
        className={cn('flex items-start gap-3 p-4', compact && 'cursor-pointer hover:bg-[#162032]')}
        onClick={compact ? () => setExpanded(e => !e) : undefined}
      >
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            {/* Severity badge */}
            <span className={cn(
              'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border',
              severityBg(finding.severity),
            )}>
              {finding.severity}
            </span>

            {/* Effort badge */}
            <span className={cn(
              'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border',
              EFFORT_COLORS[finding.effort],
            )}>
              {effortLabel(finding.effort)}
            </span>

            {/* Category */}
            <span className="text-[10px] text-muted">{finding.category}</span>
          </div>

          <h3 className="text-sm font-semibold text-text leading-snug">{finding.title}</h3>

          {finding.affectedCount !== undefined && finding.affectedCount > 0 && (
            <span className="inline-block mt-1 text-[11px] font-mono text-muted">
              {finding.affectedCount} affected
            </span>
          )}
        </div>

        {compact && (
          <button className="flex-shrink-0 text-muted mt-0.5">
            {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
        )}
      </div>

      {/* Body */}
      {expanded && (
        <div className="px-4 pb-4 space-y-3">
          <div className="h-px bg-[#1e3a5f]" />

          <p className="text-sm text-muted leading-relaxed">{finding.description}</p>

          <div className="rounded-lg bg-[#162032] border border-[#1e3a5f] p-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-blue-400 mb-1">
              Recommendation
            </p>
            <p className="text-sm text-text leading-relaxed">{finding.recommendation}</p>
          </div>

          {/* Affected items */}
          {hasItems && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-muted mb-1.5">
                Affected items
              </p>
              <div className="flex flex-wrap gap-1.5">
                {(showAllItems ? finding.affectedItems! : finding.affectedItems!.slice(0, 5)).map((item, i) => (
                  <span key={i} className="px-2 py-0.5 rounded-md bg-[#162032] border border-[#1e3a5f] text-xs font-mono text-muted">
                    {item}
                  </span>
                ))}
                {!showAllItems && finding.affectedItems!.length > 5 && (
                  <button
                    onClick={() => setShowAllItems(true)}
                    className="px-2 py-0.5 rounded-md text-xs text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    +{finding.affectedItems!.length - 5} more
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Docs link */}
          {finding.learnMoreUrl && (
            <a
              href={finding.learnMoreUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              Microsoft documentation
              <ExternalLink size={11} />
            </a>
          )}
        </div>
      )}
    </div>
  );
}
