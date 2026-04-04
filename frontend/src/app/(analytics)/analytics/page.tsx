'use client';

import { useEffect, useState } from 'react';
import { Activity, Shield, Search, Upload, Database, Clock, Eye, FileUp, ExternalLink, Globe, Link, Hash, Mail, ShieldAlert } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { useRouter } from 'next/navigation';
import { getUserStats, getRecentIOCs, getActivityTrend } from '@/lib/userActivity';
import type { UserStats, UserActivity } from '@/lib/userActivity';
import { formatTimestamp, cn } from '@/lib/utils';
import ScoreBadge from '@/components/ioc/ScoreBadge';

function getExternalLinks(type: string, value: string) {
  const encoded = encodeURIComponent(value);
  const vtBase = 'https://www.virustotal.com/gui';
  const vtUrl =
    type === 'ip'     ? `${vtBase}/ip-address/${value}` :
    type === 'domain' ? `${vtBase}/domain/${value}` :
    type === 'hash'   ? `${vtBase}/file/${value}` :
                        `${vtBase}/search/${encoded}`;

  const links = [{ label: 'VirusTotal', url: vtUrl, description: 'Multi-engine threat scan' }];

  if (type === 'ip') {
    links.push(
      { label: 'Shodan',    url: `https://www.shodan.io/host/${value}`,              description: 'Device & service scan' },
      { label: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${value}`,         description: 'Community abuse reports' },
    );
  } else if (type === 'domain') {
    links.push(
      { label: 'Shodan',     url: `https://www.shodan.io/search?query=hostname:${encoded}`, description: 'Hostname infrastructure' },
      { label: 'URLScan.io', url: `https://urlscan.io/search/#domain:${value}`,              description: 'Domain scan history' },
    );
  } else if (type === 'hash') {
    links.push({ label: 'MalwareBazaar', url: `https://bazaar.abuse.ch/sample/${value}/`, description: 'Malware sample repo' });
  } else if (type === 'url') {
    links.push(
      { label: 'URLScan.io', url: `https://urlscan.io/search/#page.url:${encoded}`,          description: 'URL scan history' },
      { label: 'URLhaus',    url: `https://urlhaus.abuse.ch/browse.php?search=${encoded}`,   description: 'Malware URL tracker' },
    );
  } else if (type === 'cve') {
    links.push({ label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${value}`, description: 'NIST Vulnerability DB' });
  }
  return links;
}

const typeIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  ip: Globe, domain: Link, hash: Hash, url: ExternalLink, email: Mail, cve: ShieldAlert,
};

export default function AnalyticsDashboard() {
  const { user } = useAuth();
  const router = useRouter();
  const [stats, setStats] = useState<UserStats | null>(null);
  const [recentIOCs, setRecentIOCs] = useState<UserActivity[]>([]);
  const [activityTrend, setActivityTrend] = useState<Array<{ date: string; count: number }>>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'external-sources'>('overview');

  useEffect(() => {
    if (user?.id) {
      const userStats = getUserStats(user.id);
      setStats(userStats);
      setRecentIOCs(getRecentIOCs(user.id, 20));
      setActivityTrend(getActivityTrend(user.id, 7));
    }
  }, [user]);

  // IOCs that have a value + type (usable for external lookups)
  const lookupIOCs = recentIOCs.filter(a => a.iocValue && a.iocType);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-sentinel-text-primary mb-2">
            Analytics Dashboard
          </h1>
          <p className="text-sentinel-text-secondary">
            Welcome back, <span className="text-sentinel-accent">{user?.username}</span> ({user?.role})
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-sentinel-border">
        {(['overview', 'external-sources'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              'px-4 py-2 text-xs font-mono uppercase tracking-wider transition-colors border-b-2 -mb-px flex items-center gap-1.5',
              activeTab === tab
                ? 'text-sentinel-accent border-sentinel-accent'
                : 'text-sentinel-text-muted border-transparent hover:text-sentinel-text-secondary'
            )}
          >
            {tab === 'external-sources' && <ExternalLink className="w-3 h-3" />}
            {tab === 'overview' ? 'Overview' : 'External Sources'}
          </button>
        ))}
      </div>

      {/* === External Sources Tab === */}
      {activeTab === 'external-sources' && (
        <div className="space-y-4">
          {lookupIOCs.length === 0 ? (
            <div className="sentinel-card p-10 text-center">
              <Database className="w-12 h-12 text-sentinel-text-muted mx-auto mb-3 opacity-40" />
              <p className="text-sm font-mono text-sentinel-text-muted">No IOC activity yet</p>
              <p className="text-xs font-mono text-sentinel-text-muted mt-1">
                Search or submit IOCs to see external lookup links here
              </p>
            </div>
          ) : (
            lookupIOCs.map((activity, idx) => {
              const Icon = typeIcons[activity.iocType!] || Globe;
              const links = getExternalLinks(activity.iocType!, activity.iocValue!);
              return (
                <div
                  key={activity.id}
                  className="sentinel-card overflow-hidden animate-fade-in"
                  style={{ animationDelay: `${idx * 40}ms` }}
                >
                  {/* IOC identity row */}
                  <div className="px-5 py-3 border-b border-sentinel-border flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <Icon className="w-4 h-4 text-sentinel-text-muted flex-shrink-0" />
                      <span className="font-mono text-xs text-sentinel-text-primary truncate">
                        {activity.iocValue}
                      </span>
                      <span className="px-1.5 py-0.5 text-[9px] font-mono uppercase rounded bg-sentinel-bg-primary border border-sentinel-border text-sentinel-text-muted flex-shrink-0">
                        {activity.iocType}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {activity.threatScore !== undefined && (
                        <ScoreBadge score={activity.threatScore} size="sm" />
                      )}
                      {activity.iocId && (
                        <button
                          onClick={() => router.push(`/ioc-detail/${activity.iocId}`)}
                          className="px-2 py-1 rounded text-[10px] font-mono border border-sentinel-border text-sentinel-text-muted hover:text-sentinel-accent hover:border-sentinel-accent/30 transition-colors"
                        >
                          Detail
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Platform links */}
                  <div className="p-3 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                    {links.map((link) => (
                      <a
                        key={link.label}
                        href={link.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center justify-between gap-2 px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border hover:border-sentinel-accent/40 hover:bg-sentinel-bg-hover transition-colors group"
                      >
                        <div className="min-w-0">
                          <p className="text-[11px] font-mono font-semibold text-sentinel-text-primary group-hover:text-sentinel-accent transition-colors">
                            {link.label}
                          </p>
                          <p className="text-[9px] font-mono text-sentinel-text-muted truncate mt-0.5">
                            {link.description}
                          </p>
                        </div>
                        <ExternalLink className="w-3 h-3 text-sentinel-text-muted group-hover:text-sentinel-accent transition-colors flex-shrink-0" />
                      </a>
                    ))}
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* === Overview Tab === */}
      {activeTab === 'overview' && <>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button
          onClick={() => router.push('/ioc-search')}
          className="sentinel-card p-6 hover:border-sentinel-accent/30 transition-all text-left group"
        >
          <Search className="w-8 h-8 text-sentinel-accent mb-3 group-hover:scale-110 transition-transform" />
          <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-1">
            Search IOCs
          </h3>
          <p className="text-xs text-sentinel-text-muted">
            Search and analyze threat indicators
          </p>
        </button>

        <button
          onClick={() => router.push('/submit')}
          className="sentinel-card p-6 hover:border-sentinel-accent/30 transition-all text-left group"
        >
          <Upload className="w-8 h-8 text-sentinel-accent mb-3 group-hover:scale-110 transition-transform" />
          <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-1">
            Submit IOCs
          </h3>
          <p className="text-xs text-sentinel-text-muted">
            Upload files or enter IOCs manually
          </p>
        </button>

        <button
          onClick={() => router.push('/history')}
          className="sentinel-card p-6 hover:border-sentinel-accent/30 transition-all text-left group"
        >
          <Clock className="w-8 h-8 text-sentinel-accent mb-3 group-hover:scale-110 transition-transform" />
          <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-1">
            View History
          </h3>
          <p className="text-xs text-sentinel-text-muted">
            Track your IOC analysis history
          </p>
        </button>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="sentinel-card p-6">
          <div className="flex items-center justify-between mb-3">
            <Search className="w-8 h-8 text-sentinel-accent" />
          </div>
          <h3 className="text-sm font-mono text-sentinel-text-muted mb-1">
            Your Searches
          </h3>
          <p className="text-3xl font-bold text-sentinel-text-primary">
            {stats?.totalSearches || 0}
          </p>
          <p className="text-xs text-sentinel-text-secondary mt-2">
            Total IOC searches performed
          </p>
        </div>

        <div className="sentinel-card p-6">
          <div className="flex items-center justify-between mb-3">
            <FileUp className="w-8 h-8 text-sentinel-accent" />
          </div>
          <h3 className="text-sm font-mono text-sentinel-text-muted mb-1">
            IOCs Submitted
          </h3>
          <p className="text-3xl font-bold text-sentinel-text-primary">
            {stats?.totalSubmissions || 0}
          </p>
          <p className="text-xs text-sentinel-text-secondary mt-2">
            IOCs analyzed by you
          </p>
        </div>

        <div className="sentinel-card p-6">
          <div className="flex items-center justify-between mb-3">
            <Eye className="w-8 h-8 text-sentinel-accent" />
          </div>
          <h3 className="text-sm font-mono text-sentinel-text-muted mb-1">
            IOCs Viewed
          </h3>
          <p className="text-3xl font-bold text-sentinel-text-primary">
            {stats?.totalViews || 0}
          </p>
          <p className="text-xs text-sentinel-text-secondary mt-2">
            Detailed views accessed
          </p>
        </div>

        <div className="sentinel-card p-6">
          <div className="flex items-center justify-between mb-3">
            <Shield className="w-8 h-8 text-sentinel-accent" />
          </div>
          <h3 className="text-sm font-mono text-sentinel-text-muted mb-1">
            Critical IOCs
          </h3>
          <p className="text-3xl font-bold text-sentinel-text-primary">
            {stats?.criticalIOCs || 0}
          </p>
          <p className="text-xs text-sentinel-danger mt-2">
            High threat indicators
          </p>
        </div>
      </div>

      {/* Activity Trend */}
      <div className="sentinel-card p-6">
        <h2 className="text-lg font-display font-semibold text-sentinel-text-primary mb-4 flex items-center gap-2">
          <Activity className="w-5 h-5" />
          Your Activity (Last 7 Days)
        </h2>
        <div className="flex items-end justify-between gap-2 h-32">
          {activityTrend.map((day, idx) => {
            const maxCount = Math.max(...activityTrend.map(d => d.count), 1);
            const height = (day.count / maxCount) * 100;
            return (
              <div key={idx} className="flex-1 flex flex-col items-center gap-2">
                <div className="flex-1 w-full flex items-end">
                  <div
                    className="w-full bg-sentinel-accent/20 hover:bg-sentinel-accent/30 transition-colors rounded-t relative group"
                    style={{ height: `${height}%`, minHeight: day.count > 0 ? '4px' : '0' }}
                  >
                    <div className="absolute -top-8 left-1/2 transform -translate-x-1/2 bg-sentinel-bg-primary border border-sentinel-border px-2 py-1 rounded text-xs font-mono opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                      {day.count} activities
                    </div>
                  </div>
                </div>
                <span className="text-[9px] font-mono text-sentinel-text-muted">
                  {new Date(day.date).toLocaleDateString('en-US', { weekday: 'short' })}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent IOCs */}
      <div className="sentinel-card overflow-hidden">
        <div className="px-5 py-3 border-b border-sentinel-border flex items-center justify-between">
          <h3 className="text-sm font-display font-semibold text-sentinel-text-primary flex items-center gap-2">
            <Clock className="w-4 h-4" />
            Your Recent IOC Activity
          </h3>
          <span className="text-xs font-mono text-sentinel-text-muted">
            Last 10 items
          </span>
        </div>
        
        {recentIOCs.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-sentinel-border">
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Action</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">IOC Value</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Type</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Threat Score</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Time</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Actions</th>
                </tr>
              </thead>
              <tbody>
                {recentIOCs.map((activity, idx) => (
                  <tr
                    key={activity.id}
                    onClick={() => activity.iocId && router.push(`/ioc-detail/${activity.iocId}`)}
                    className={`border-b border-sentinel-border/50 hover:bg-sentinel-bg-hover transition-colors ${activity.iocId ? 'cursor-pointer' : ''}`}
                  >
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 text-[9px] font-mono rounded uppercase ${
                        activity.type === 'submit'
                          ? 'bg-sentinel-success/10 text-sentinel-success border border-sentinel-success/20'
                          : 'bg-sentinel-accent/10 text-sentinel-accent border border-sentinel-accent/20'
                      }`}>
                        {activity.type}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary max-w-xs truncate">
                      {activity.iocValue || '-'}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted uppercase">
                      {activity.iocType || '-'}
                    </td>
                    <td className="px-4 py-2.5">
                      {activity.threatScore !== undefined ? (
                        <ScoreBadge score={activity.threatScore} size="sm" />
                      ) : (
                        <span className="text-xs text-sentinel-text-muted">-</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted">
                      {formatTimestamp(activity.timestamp)}
                    </td>
                    <td className="px-4 py-2.5">
                      {activity.iocId && (
                        <button
                          onClick={() => router.push(`/ioc-detail/${activity.iocId}`)}
                          className="px-2 py-1 rounded text-[10px] font-mono border border-sentinel-border text-sentinel-text-muted hover:text-sentinel-accent hover:border-sentinel-accent/30 transition-colors"
                        >
                          View
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center">
            <Database className="w-12 h-12 text-sentinel-text-muted mx-auto mb-3 opacity-50" />
            <p className="text-sm font-mono text-sentinel-text-muted">No activity yet</p>
            <p className="text-xs font-mono text-sentinel-text-muted mt-1">
              Start by searching or submitting IOCs to see your activity here
            </p>
          </div>
        )}
      </div>
      </>}
    </div>
  );
}
