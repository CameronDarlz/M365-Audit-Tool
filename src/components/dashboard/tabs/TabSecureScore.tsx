import type { SecureScoreData, Finding } from '../../../types/audit';
import { FindingCard } from '../FindingCard';
import { ScoreRing } from '../ScoreRing';
import { scoreToGrade } from '../../../lib/utils';
import { formatDate, pct } from '../../../lib/utils';
import { ExternalLink } from 'lucide-react';

interface TabSecureScoreProps {
  data: SecureScoreData;
  findings: Finding[];
}

const CATEGORY_COLORS: Record<string, string> = {
  Identity: '#38bdf8',
  Data: '#34d399',
  Device: '#fbbf24',
  Apps: '#fb923c',
  Infrastructure: '#a78bfa',
};

export function TabSecureScore({ data, findings }: TabSecureScoreProps) {
  const latest = data.secureScores[0];

  if (!latest) {
    return (
      <div className="p-6">
        {data.error ? (
          <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-400">
            <strong>Collection error:</strong> {data.error}
          </div>
        ) : (
          <p className="text-muted text-sm">No Secure Score data available.</p>
        )}
      </div>
    );
  }

  const scorePercent = Math.round((latest.currentScore / latest.maxScore) * 100);
  const grade = scoreToGrade(scorePercent);

  const byCategory = latest.controlScores.reduce<Record<string, { total: number; count: number }>>((acc, c) => {
    const cat = c.controlCategory || 'Other';
    if (!acc[cat]) acc[cat] = { total: 0, count: 0 };
    acc[cat].total += c.score;
    acc[cat].count += 1;
    return acc;
  }, {});

  const topControls = [...latest.controlScores]
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  return (
    <div className="p-6 space-y-6">
      {/* Main score */}
      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-6 rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
        <ScoreRing score={scorePercent} grade={grade} label="Secure Score" size={100} strokeWidth={8} />
        <div className="space-y-2">
          <div>
            <p className="text-3xl font-bold font-mono text-text">
              {Math.round(latest.currentScore)}{' '}
              <span className="text-base text-muted">/ {Math.round(latest.maxScore)}</span>
            </p>
            <p className="text-xs text-muted mt-1">{scorePercent}% of maximum score</p>
          </div>
          <div className="flex flex-wrap gap-3 text-xs text-muted pt-1">
            <span>Active users: <span className="text-text font-mono">{latest.activeUserCount}</span></span>
            <span>Licensed: <span className="text-text font-mono">{latest.licensedUserCount}</span></span>
            <span>As of: <span className="text-text">{formatDate(latest.createdDateTime)}</span></span>
          </div>
        </div>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-text">Findings ({findings.length})</h3>
          {findings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}

      {/* Category breakdown */}
      {Object.keys(byCategory).length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-4">Score by Category</h3>
          <div className="space-y-3">
            {Object.entries(byCategory).map(([cat, { total }]) => {
              const color = CATEGORY_COLORS[cat] ?? '#94a3b8';
              const catPct = pct(total, latest.maxScore);
              return (
                <div key={cat}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-muted">{cat}</span>
                    <span className="font-mono" style={{ color }}>{Math.round(total)} pts ({catPct})</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-[#1e3a5f] overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width: catPct, backgroundColor: color }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Top controls */}
      {topControls.length > 0 && (
        <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] p-5">
          <h3 className="text-sm font-semibold text-text mb-3">Top Scoring Controls</h3>
          <div className="space-y-2">
            {topControls.map(c => (
              <div key={c.controlName} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-[#162032] border border-[#1e3a5f]">
                <span className="text-sm text-text flex-1 truncate">{c.controlName}</span>
                <span className="text-xs font-mono text-blue-400">{Math.round(c.score)} pts</span>
                <span className="text-[10px] text-muted">{c.controlCategory}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="text-center">
        <a href="https://security.microsoft.com/securescore" target="_blank" rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors">
          Open Secure Score in Microsoft Defender <ExternalLink size={11} />
        </a>
      </div>

      {data.error && (
        <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-400">
          <strong>Collection error:</strong> {data.error}
        </div>
      )}
    </div>
  );
}
