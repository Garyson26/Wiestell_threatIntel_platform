'use client';

import { useRouter } from 'next/navigation';
import { cn, formatTimestamp, truncate } from '@/lib/utils';
import ScoreBadge from '@/components/ioc/ScoreBadge';
import type { TopThreat } from '@/lib/types';

interface TopThreatsProps {
  threats: TopThreat[];
  loading: boolean;
}

export default function TopThreats({ threats, loading }: TopThreatsProps) {
  const router = useRouter();

  return (
    <div className="sentinel-card overflow-hidden">
      <div className="px-5 py-3 border-b border-sentinel-border">
        <h3 className="text-xs font-mono font-semibold uppercase tracking-widest text-sentinel-text-muted">
          TOP THREATS
        </h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-sentinel-border">
              <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">IOC</th>
              <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Type</th>
              <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Score</th>
              <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted hidden md:table-cell">Last Seen</th>
              <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted hidden lg:table-cell">Tags</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} className="border-b border-sentinel-border/50 animate-pulse">
                  <td className="px-4 py-3"><div className="h-3 w-40 bg-sentinel-bg-tertiary rounded" /></td>
                  <td className="px-4 py-3"><div className="h-3 w-12 bg-sentinel-bg-tertiary rounded" /></td>
                  <td className="px-4 py-3"><div className="h-3 w-8 bg-sentinel-bg-tertiary rounded" /></td>
                  <td className="px-4 py-3 hidden md:table-cell"><div className="h-3 w-16 bg-sentinel-bg-tertiary rounded" /></td>
                  <td className="px-4 py-3 hidden lg:table-cell"><div className="h-3 w-24 bg-sentinel-bg-tertiary rounded" /></td>
                </tr>
              ))
            ) : threats.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-sentinel-text-muted text-xs font-mono">
                  No high-scored threats detected yet
                </td>
              </tr>
            ) : (
              threats.map((threat, i) => (
                <tr
                  key={threat.id}
                  className="border-b border-sentinel-border/50 cursor-pointer hover:bg-sentinel-bg-hover transition-colors animate-fade-in"
                  style={{ animationDelay: `${i * 30}ms` }}
                  onClick={() => router.push(`/ioc/${threat.id}`)}
                >
                  <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">
                    {truncate(threat.value, 45)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted uppercase">
                    {threat.type}
                  </td>
                  <td className="px-4 py-2.5">
                    <ScoreBadge score={threat.threat_score} size="sm" showBar />
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted hidden md:table-cell">
                    {formatTimestamp(threat.last_seen)}
                  </td>
                  <td className="px-4 py-2.5 hidden lg:table-cell">
                    <div className="flex gap-1 flex-wrap">
                      {(threat.tags || []).slice(0, 3).map((tag) => (
                        <span key={tag} className="px-1.5 py-0.5 text-[9px] font-mono rounded bg-sentinel-bg-tertiary text-sentinel-text-muted border border-sentinel-border">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
