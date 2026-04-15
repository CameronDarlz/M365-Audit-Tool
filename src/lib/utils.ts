import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { Severity, CategoryScore } from '../types/audit';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityColor(severity: Severity): string {
  switch (severity) {
    case 'critical': return '#f87171';
    case 'high':     return '#fb923c';
    case 'medium':   return '#fbbf24';
    case 'low':      return '#38bdf8';
    case 'info':     return '#94a3b8';
  }
}

export function severityBg(severity: Severity): string {
  switch (severity) {
    case 'critical': return 'bg-red-400/10 text-red-400 border-red-400/30';
    case 'high':     return 'bg-orange-400/10 text-orange-400 border-orange-400/30';
    case 'medium':   return 'bg-yellow-400/10 text-yellow-400 border-yellow-400/30';
    case 'low':      return 'bg-blue-400/10 text-blue-400 border-blue-400/30';
    case 'info':     return 'bg-muted/10 text-muted border-muted/30';
  }
}

export function gradeColor(grade: CategoryScore['grade']): string {
  switch (grade) {
    case 'good':     return '#34d399';
    case 'fair':     return '#fbbf24';
    case 'poor':     return '#fb923c';
    case 'critical': return '#f87171';
  }
}

export function scoreToGrade(score: number): CategoryScore['grade'] {
  if (score >= 80) return 'good';
  if (score >= 60) return 'fair';
  if (score >= 40) return 'poor';
  return 'critical';
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
  });
}

export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export function daysSince(iso: string | null | undefined): number | null {
  if (!iso) return null;
  return Math.floor((Date.now() - new Date(iso).getTime()) / (1000 * 60 * 60 * 24));
}

export function daysUntil(iso: string | null | undefined): number | null {
  if (!iso) return null;
  return Math.floor((new Date(iso).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
}

export function pct(n: number, total: number, decimals = 0): string {
  if (total === 0) return '0%';
  return `${(n / total * 100).toFixed(decimals)}%`;
}

export function effortLabel(effort: 'quick-win' | 'medium' | 'project'): string {
  switch (effort) {
    case 'quick-win': return 'Quick Win';
    case 'medium':    return 'Medium';
    case 'project':   return 'Project';
  }
}

export function effortMinutesLabel(minutes: number): string {
  if (minutes < 60) return `~${minutes} min`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return m > 0 ? `~${h}h ${m}m` : `~${h}h`;
}

export function downloadCsv(filename: string, rows: Record<string, unknown>[]): void {
  if (!rows.length) return;
  const headers = Object.keys(rows[0]);
  const lines = [
    headers.join(','),
    ...rows.map(r =>
      headers.map(h => {
        const v = String(r[h] ?? '');
        return v.includes(',') || v.includes('"') || v.includes('\n')
          ? `"${v.replace(/"/g, '""')}"` : v;
      }).join(','),
    ),
  ];
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}
