import { clsx, type ClassValue } from 'clsx';
import { formatDistanceToNow, format } from 'date-fns';
import type { ScoreCategory } from './types';

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function getScoreCategory(score: number): ScoreCategory {
  if (score >= 76) return 'critical';
  if (score >= 51) return 'high';
  if (score >= 26) return 'medium';
  return 'low';
}

export function getScoreColor(score: number): string {
  if (score >= 76) return '#ef4444';
  if (score >= 51) return '#f59e0b';
  if (score >= 26) return '#eab308';
  return '#10b981';
}

export function getScoreBgClass(score: number): string {
  if (score >= 76) return 'bg-red-500/20 text-red-400 border-red-500/30';
  if (score >= 51) return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
  if (score >= 26) return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
  return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
}

export function getIOCTypeIcon(type: string): string {
  const map: Record<string, string> = {
    ip: 'Globe',
    domain: 'Link',
    hash: 'Hash',
    url: 'ExternalLink',
    email: 'Mail',
    cve: 'ShieldAlert',
  };
  return map[type] || 'FileQuestion';
}

export function formatTimestamp(ts: string | null | undefined): string {
  if (!ts) return 'N/A';
  try {
    return formatDistanceToNow(new Date(ts), { addSuffix: true });
  } catch {
    return 'N/A';
  }
}

export function formatDate(ts: string | null | undefined): string {
  if (!ts) return 'N/A';
  try {
    return format(new Date(ts), 'yyyy-MM-dd HH:mm');
  } catch {
    return 'N/A';
  }
}

export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + '...';
}

export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

export function getHealthColor(health: string): string {
  switch (health) {
    case 'healthy': return '#10b981';
    case 'degraded': return '#f59e0b';
    case 'offline': return '#ef4444';
    case 'disabled': return '#64748b';
    default: return '#64748b';
  }
}
