import { CollectorState } from '../types/audit';
import { CheckCircle2, XCircle, Loader2, Circle } from 'lucide-react';
import { cn } from '../lib/utils';

interface LoadingPageProps {
  states: CollectorState[];
}

function StatusIcon({ status }: { status: CollectorState['status'] }) {
  switch (status) {
    case 'complete': return <CheckCircle2 size={14} className="text-green-400 flex-shrink-0" />;
    case 'failed':   return <XCircle size={14} className="text-red-400 flex-shrink-0" />;
    case 'running':  return <Loader2 size={14} className="text-blue-400 animate-spin flex-shrink-0" />;
    default:         return <Circle size={14} className="text-muted/30 flex-shrink-0" />;
  }
}

export function LoadingPage({ states }: LoadingPageProps) {
  const done = states.filter(s => s.status === 'complete' || s.status === 'failed').length;
  const total = states.length;
  const progress = total > 0 ? Math.round((done / total) * 100) : 0;
  const running = states.find(s => s.status === 'running');

  return (
    <div className="min-h-screen bg-[#080d18] flex items-center justify-center p-6">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="relative inline-flex mb-4">
            <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
              style={{ background: 'linear-gradient(135deg, #38bdf8, #0284c7)' }}>
              <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
                <text x="16" y="22" textAnchor="middle" fontFamily="DM Sans, sans-serif"
                  fontWeight="700" fontSize="16" fill="white" letterSpacing="-0.5">NS</text>
              </svg>
            </div>
            <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-blue-400 animate-pulse" />
          </div>
          <h2 className="text-xl font-bold text-text mb-1">Running Audit</h2>
          <p className="text-sm text-muted">
            {running ? `Checking ${running.label}…` : 'Collecting tenant data…'}
          </p>
        </div>

        {/* Progress bar */}
        <div className="mb-6">
          <div className="flex justify-between text-xs text-muted mb-2">
            <span>{done} of {total} checks complete</span>
            <span>{progress}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-[#1e3a5f] overflow-hidden">
            <div
              className="h-full rounded-full bg-blue-400 transition-all duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Collector list */}
        {states.length > 0 && (
          <div className="rounded-xl border border-[#1e3a5f] bg-[#0f172a] divide-y divide-[#1e3a5f]/50">
            {states.map(state => (
              <div key={state.id}
                className={cn(
                  'flex items-center gap-3 px-4 py-2.5 text-sm transition-colors',
                  state.status === 'running' && 'bg-blue-400/5',
                )}>
                <StatusIcon status={state.status} />
                <span className={cn(
                  'flex-1',
                  state.status === 'running' ? 'text-text' :
                  state.status === 'complete' ? 'text-muted' :
                  state.status === 'failed' ? 'text-red-400/70' : 'text-muted/40',
                )}>
                  {state.label}
                </span>
                {state.status === 'failed' && state.error && (
                  <span className="text-xs text-red-400/60 truncate max-w-[140px]" title={state.error}>
                    {state.error.includes('403') || state.error.includes('Forbidden')
                      ? 'Permission denied'
                      : 'Failed'}
                  </span>
                )}
              </div>
            ))}
          </div>
        )}

        <p className="text-center text-xs text-muted/50 mt-6">
          No data leaves your browser — all checks run client-side via Microsoft Graph
        </p>
      </div>
    </div>
  );
}
