'use client';

import { useDashboardData } from '@/hooks/useDashboardData';
import StatsCards from '@/components/dashboard/StatsCards';
import ThreatGauge from '@/components/dashboard/ThreatGauge';
import IOCTimeline from '@/components/dashboard/IOCTimeline';
import TopThreats from '@/components/dashboard/TopThreats';
import FeedHealth from '@/components/dashboard/FeedHealth';
import GeoThreatMap from '@/components/dashboard/GeoThreatMap';
import { RefreshCw } from 'lucide-react';

export default function DashboardPage() {
  const {
    stats, timeline, topThreats, feedHealth, geoData,
    statsLoading, timelineLoading, topThreatsLoading, feedHealthLoading, geoLoading,
    error, refresh,
  } = useDashboardData();

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-display font-bold text-sentinel-text-primary">
            Threat Overview
          </h1>
          <p className="text-xs font-mono text-sentinel-text-muted mt-0.5">
            Real-time threat intelligence dashboard
          </p>
        </div>
        <button
          onClick={refresh}
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-mono rounded border border-sentinel-border text-sentinel-text-secondary hover:text-sentinel-accent hover:border-sentinel-accent/30 transition-colors"
        >
          <RefreshCw className="w-3 h-3" />
          REFRESH
        </button>
      </div>

      {error && (
        <div className="sentinel-card p-4 border-sentinel-warning/30">
          <p className="text-xs font-mono text-sentinel-warning">
            Backend not reachable. Showing cached data. Start services with: docker-compose up
          </p>
        </div>
      )}

      {/* Stats Cards Row */}
      <StatsCards stats={stats} loading={statsLoading} />

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Gauge + Geo */}
        <div className="space-y-6">
          <ThreatGauge score={stats?.avg_threat_score ?? 0} loading={statsLoading} />
          <GeoThreatMap data={geoData} loading={geoLoading} />
        </div>

        {/* Center Column: Timeline */}
        <div className="lg:col-span-1">
          <IOCTimeline entries={timeline} loading={timelineLoading} />
        </div>

        {/* Right Column: Feed Health */}
        <div>
          <FeedHealth feeds={feedHealth} loading={feedHealthLoading} />
        </div>
      </div>

      {/* Top Threats Table */}
      <TopThreats threats={topThreats} loading={topThreatsLoading} />
    </div>
  );
}
