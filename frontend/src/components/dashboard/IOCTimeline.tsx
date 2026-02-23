'use client';

import { Globe, Link, Hash, ExternalLink, Mail, ShieldAlert } from 'lucide-react';
import { cn, formatTimestamp, truncate } from '@/lib/utils';
import ScoreBadge from '@/components/ioc/ScoreBadge';
import type { TimelineEntry } from '@/lib/types';

interface IOCTimelineProps {
  entries: TimelineEntry[];
  loading: boolean;
}

const typeIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  ip: Globe,
  domain: Link,
  hash: Hash,
  url: ExternalLink,
  email: Mail,
  cve: ShieldAlert,
};

export default function IOCTimeline({ entries, loading }: IOCTimelineProps) {
  return (
    <div className="sentinel-card flex flex-col h-full">
      <div className="px-5 py-3 border-b border-sentinel-border flex items-center justify-between">
        <h3 className="text-xs font-mono font-semibold uppercase tracking-widest text-sentinel-text-muted">
          LIVE IOC FEED
        </h3>
        <span className="flex items-center gap-1.5 text-[10px] font-mono text-sentinel-text-muted">
          <span className="status-dot w-1.5 h-1.5 rounded-full bg-emerald-400" />
          LIVE
        </span>
      </div>
      <div className="flex-1 overflow-auto px-2 py-2 space-y-1 max-h-[500px]">
        {loading ? (
          Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 px-3 py-2 animate-pulse">
              <div className="w-5 h-5 bg-sentinel-bg-tertiary rounded" />
              <div className="flex-1 h-3 bg-sentinel-bg-tertiary rounded" />
              <div className="w-8 h-3 bg-sentinel-bg-tertiary rounded" />
            </div>
          ))
        ) : entries.length === 0 ? (
          <div className="text-center py-8 text-sentinel-text-muted text-xs font-mono">
            No IOCs ingested yet. Enable feeds to start.
          </div>
        ) : (
          entries.map((entry, i) => {
            const Icon = typeIcons[entry.type] || Globe;
            return (
              <div
                key={entry.id}
                className="flex items-center gap-3 px-3 py-2 rounded hover:bg-sentinel-bg-hover transition-colors animate-fade-in group"
                style={{ animationDelay: `${Math.min(i * 20, 400)}ms` }}
              >
                <Icon className="w-4 h-4 text-sentinel-text-muted flex-shrink-0 group-hover:text-sentinel-accent transition-colors" />
                <span className="font-mono text-xs text-sentinel-text-primary truncate flex-1">
                  {truncate(entry.value, 40)}
                </span>
                <span className="text-[10px] font-mono text-sentinel-text-muted uppercase flex-shrink-0">
                  {entry.type}
                </span>
                <ScoreBadge score={entry.threat_score} size="sm" />
                <span className="text-[10px] font-mono text-sentinel-text-muted flex-shrink-0 hidden lg:block">
                  {formatTimestamp(entry.created_at)}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
