'use client';

import { useState, useEffect, useCallback } from 'react';
import {
  getDashboardStats,
  getDashboardTimeline,
  getTopThreats,
  getFeedHealth,
  getDashboardGeo,
} from '@/lib/api';
import type {
  DashboardStats,
  TimelineEntry,
  TopThreat,
  FeedHealth,
  GeoData,
} from '@/lib/types';

interface DashboardData {
  stats: DashboardStats | null;
  timeline: TimelineEntry[];
  topThreats: TopThreat[];
  feedHealth: FeedHealth[];
  geoData: GeoData[];
  loading: boolean;
  statsLoading: boolean;
  timelineLoading: boolean;
  topThreatsLoading: boolean;
  feedHealthLoading: boolean;
  geoLoading: boolean;
  error: string | null;
  refresh: () => void;
}

export function useDashboardData(): DashboardData {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [topThreats, setTopThreats] = useState<TopThreat[]>([]);
  const [feedHealth, setFeedHealth] = useState<FeedHealth[]>([]);
  const [geoData, setGeoData] = useState<GeoData[]>([]);
  const [statsLoading, setStatsLoading] = useState(true);
  const [timelineLoading, setTimelineLoading] = useState(true);
  const [topThreatsLoading, setTopThreatsLoading] = useState(true);
  const [feedHealthLoading, setFeedHealthLoading] = useState(true);
  const [geoLoading, setGeoLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setError(null);
    setStatsLoading(true);
    setTimelineLoading(true);
    setTopThreatsLoading(true);
    setFeedHealthLoading(true);
    setGeoLoading(true);

    // Fire all requests independently — each updates its own state on arrival
    getDashboardStats()
      .then(s => setStats(s))
      .catch(() => setError('Failed to load stats'))
      .finally(() => setStatsLoading(false));

    getDashboardTimeline(50)
      .then(t => setTimeline(t))
      .catch(() => {})
      .finally(() => setTimelineLoading(false));

    getTopThreats(20)
      .then(th => setTopThreats(th))
      .catch(() => {})
      .finally(() => setTopThreatsLoading(false));

    getFeedHealth()
      .then(fh => setFeedHealth(fh))
      .catch(() => {})
      .finally(() => setFeedHealthLoading(false));

    getDashboardGeo()
      .then(g => setGeoData(g))
      .catch(() => {})
      .finally(() => setGeoLoading(false));
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 60000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const loading = statsLoading || timelineLoading || topThreatsLoading || feedHealthLoading || geoLoading;

  return {
    stats, timeline, topThreats, feedHealth, geoData,
    loading, statsLoading, timelineLoading, topThreatsLoading, feedHealthLoading, geoLoading,
    error, refresh: fetchData,
  };
}
