import { clsx, type ClassValue } from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import { formatInTimeZone } from 'date-fns-tz';
import type { ScoreCategory } from './types';

/** Resolved at runtime from the browser/OS — e.g. 'Asia/Kolkata', 'America/New_York'. */
const USER_TZ: string =
  typeof Intl !== 'undefined'
    ? Intl.DateTimeFormat().resolvedOptions().timeZone
    : 'UTC';

/**
 * Parse a datetime string safely.
 * Strings WITHOUT a timezone designator (no Z, no +HH:MM) come from the
 * backend as naive UTC values. We append 'Z' so the browser treats them
 * as UTC instead of local time, which would shift the displayed time.
 */
function parseTs(ts: string): Date {
  // Already has timezone info — parse as-is
  if (/[Zz]$/.test(ts) || /[+\-]\d{2}:\d{2}$/.test(ts)) {
    return new Date(ts);
  }
  // Naive datetime — assume UTC
  return new Date(ts + 'Z');
}

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
    return formatDistanceToNow(parseTs(ts), { addSuffix: true });
  } catch {
    return 'N/A';
  }
}

export function formatDate(ts: string | null | undefined): string {
  if (!ts) return 'N/A';
  try {
    return formatInTimeZone(parseTs(ts), USER_TZ, 'yyyy-MM-dd HH:mm');
  } catch {
    return 'N/A';
  }
}

export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + '...';
}

export function formatNumber(n: number | null | undefined): string {
  if (n == null || isNaN(n)) return '0';
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
