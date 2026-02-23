'use client';

import { TrendingUp, TrendingDown, Shield, Rss, AlertTriangle, Activity } from 'lucide-react';
import { cn, formatNumber } from '@/lib/utils';
import type { DashboardStats } from '@/lib/types';

interface StatsCardsProps {
  stats: DashboardStats | null;
  loading: boolean;
}

export default function StatsCards({ stats, loading }: StatsCardsProps) {
  const cards = [
    {
      label: 'TOTAL IOCs',
      value: stats?.total_iocs ?? 0,
      delta: stats?.delta_pct ?? 0,
      deltaLabel: `+${formatNumber(stats?.new_24h ?? 0)} today`,
      icon: Shield,
      color: '#00e5ff',
    },
    {
      label: 'ACTIVE FEEDS',
      value: stats?.active_feeds ?? 0,
      delta: 0,
      deltaLabel: `${stats?.total_feeds ?? 0} total`,
      icon: Rss,
      color: '#10b981',
    },
    {
      label: 'CRITICAL THREATS',
      value: stats?.critical_threats ?? 0,
      delta: 0,
      deltaLabel: 'score >= 76',
      icon: AlertTriangle,
      color: '#ef4444',
    },
    {
      label: 'AVG THREAT SCORE',
      value: stats?.avg_threat_score ?? 0,
      delta: 0,
      deltaLabel: 'across all IOCs',
      icon: Activity,
      color: '#f59e0b',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, i) => {
        const Icon = card.icon;
        return (
          <div
            key={card.label}
            className={cn(
              'sentinel-card p-5 animate-fade-in',
              loading && 'animate-pulse'
            )}
            style={{ animationDelay: `${i * 50}ms` }}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-mono font-semibold uppercase tracking-widest text-sentinel-text-muted">
                {card.label}
              </span>
              {card.delta > 0 && (
                <span className="flex items-center gap-0.5 text-[10px] font-mono text-emerald-400">
                  <TrendingUp className="w-3 h-3" />
                  {card.delta}%
                </span>
              )}
              {card.delta < 0 && (
                <span className="flex items-center gap-0.5 text-[10px] font-mono text-red-400">
                  <TrendingDown className="w-3 h-3" />
                  {Math.abs(card.delta)}%
                </span>
              )}
            </div>
            <div className="flex items-end justify-between">
              <div>
                <p className="text-2xl font-mono font-bold" style={{ color: card.color }}>
                  {formatNumber(typeof card.value === 'number' ? Math.round(card.value) : card.value)}
                </p>
                <p className="text-[10px] font-mono text-sentinel-text-muted mt-1">{card.deltaLabel}</p>
              </div>
              <Icon className="w-8 h-8 opacity-20" style={{ color: card.color }} />
            </div>
            {/* Mini sparkline placeholder */}
            {stats?.trends && (
              <div className="flex items-end gap-[2px] mt-3 h-6">
                {stats.trends.map((t, j) => {
                  const max = Math.max(...stats.trends.map(p => p.count), 1);
                  const h = Math.max(2, (t.count / max) * 24);
                  return (
                    <div
                      key={j}
                      className="flex-1 rounded-sm transition-all"
                      style={{
                        height: `${h}px`,
                        backgroundColor: card.color,
                        opacity: 0.4 + (j / stats.trends.length) * 0.6,
                      }}
                    />
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
