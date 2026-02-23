'use client';

import { Rss, RefreshCw } from 'lucide-react';
import { cn, formatTimestamp, formatNumber } from '@/lib/utils';
import StatusDot from '@/components/shared/StatusDot';
import type { FeedHealth as FeedHealthType } from '@/lib/types';

interface FeedHealthProps {
  feeds: FeedHealthType[];
  loading: boolean;
}

export default function FeedHealth({ feeds, loading }: FeedHealthProps) {
  return (
    <div className="sentinel-card">
      <div className="px-5 py-3 border-b border-sentinel-border flex items-center justify-between">
        <h3 className="text-xs font-mono font-semibold uppercase tracking-widest text-sentinel-text-muted">
          FEED HEALTH
        </h3>
        <span className="text-[10px] font-mono text-sentinel-text-muted">
          {feeds.filter(f => f.health === 'healthy').length}/{feeds.length} active
        </span>
      </div>
      <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
        {loading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="p-3 rounded bg-sentinel-bg-primary border border-sentinel-border animate-pulse">
              <div className="h-3 w-28 bg-sentinel-bg-tertiary rounded mb-2" />
              <div className="h-2 w-20 bg-sentinel-bg-tertiary rounded" />
            </div>
          ))
        ) : feeds.length === 0 ? (
          <div className="col-span-2 text-center py-6 text-sentinel-text-muted text-xs font-mono">
            No feeds configured. Add feeds to start ingesting IOCs.
          </div>
        ) : (
          feeds.map((feed, i) => (
            <div
              key={feed.id}
              className="p-3 rounded bg-sentinel-bg-primary border border-sentinel-border hover:border-sentinel-border-hover transition-colors animate-fade-in"
              style={{ animationDelay: `${i * 40}ms` }}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <StatusDot status={feed.health} size="md" />
                  <span className="text-xs font-mono font-medium text-sentinel-text-primary">
                    {feed.name}
                  </span>
                </div>
                <Rss className="w-3 h-3 text-sentinel-text-muted" />
              </div>
              <div className="flex items-center justify-between text-[10px] font-mono text-sentinel-text-muted">
                <span>{formatNumber(feed.ioc_count)} IOCs</span>
                <span>{feed.last_sync_at ? formatTimestamp(feed.last_sync_at) : 'Never synced'}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
