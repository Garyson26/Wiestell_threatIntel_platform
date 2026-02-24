'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Rss, RefreshCw, ExternalLink, Power, PowerOff, Plus, X,
  Database, Globe, FileText, Code, Activity, Clock, AlertTriangle,
  CheckCircle2, XCircle, MinusCircle, ChevronDown, ChevronUp,
  Trash2, Settings2, Zap, BarChart3, Filter, Search
} from 'lucide-react';
import { getFeeds, triggerFeedSync, updateFeed, createFeed, deleteFeed, getFeedLogs } from '@/lib/api';
import { cn, formatTimestamp, formatNumber, formatDate } from '@/lib/utils';
import type { FeedSource } from '@/lib/types';

type FilterType = 'all' | 'api' | 'csv' | 'stix' | 'custom';
type FilterStatus = 'all' | 'active' | 'inactive' | 'healthy' | 'failed' | 'never';
type SortBy = 'name' | 'ioc_count' | 'last_sync';

export default function FeedsPage() {
  const [feeds, setFeeds] = useState<FeedSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState<string | null>(null);
  const [syncingAll, setSyncingAll] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Filters
  const [filterType, setFilterType] = useState<FilterType>('all');
  const [filterStatus, setFilterStatus] = useState<FilterStatus>('all');
  const [sortBy, setSortBy] = useState<SortBy>('name');

  // Add feed form
  const [addForm, setAddForm] = useState({
    name: '', slug: '', description: '', feed_type: 'api',
    url: '', api_key_env: '', sync_frequency: 3600,
  });
  const [addError, setAddError] = useState('');
  const [adding, setAdding] = useState(false);

  useEffect(() => { loadFeeds(); }, []);

  async function loadFeeds() {
    setLoading(true);
    try {
      const data = await getFeeds();
      setFeeds(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }

  async function handleSync(feedId: string) {
    setSyncing(feedId);
    try {
      await triggerFeedSync(feedId);
      await loadFeeds();
    } catch {
      // ignore
    } finally {
      setSyncing(null);
    }
  }

  async function handleSyncAll() {
    setSyncingAll(true);
    const enabled = feeds.filter(f => f.is_enabled);
    for (const feed of enabled) {
      try { await triggerFeedSync(feed.id); } catch { /* skip */ }
    }
    await loadFeeds();
    setSyncingAll(false);
  }

  async function handleToggle(feed: FeedSource) {
    try {
      await updateFeed(feed.id, { is_enabled: !feed.is_enabled });
      await loadFeeds();
    } catch {
      // ignore
    }
  }

  async function handleDelete(feedId: string) {
    setDeleting(feedId);
    try {
      await deleteFeed(feedId);
      if (expanded === feedId) setExpanded(null);
      await loadFeeds();
    } catch {
      // ignore
    } finally {
      setDeleting(null);
    }
  }

  async function handleAddFeed(e: React.FormEvent) {
    e.preventDefault();
    setAddError('');
    if (!addForm.name.trim() || !addForm.slug.trim() || !addForm.feed_type) {
      setAddError('Name, slug, and type are required.');
      return;
    }
    setAdding(true);
    try {
      await createFeed({
        name: addForm.name,
        slug: addForm.slug,
        description: addForm.description || undefined,
        feed_type: addForm.feed_type,
        url: addForm.url || undefined,
        api_key_env: addForm.api_key_env || undefined,
        sync_frequency: addForm.sync_frequency,
      });
      setShowAddModal(false);
      setAddForm({ name: '', slug: '', description: '', feed_type: 'api', url: '', api_key_env: '', sync_frequency: 3600 });
      await loadFeeds();
    } catch (err) {
      setAddError(err instanceof Error ? err.message : 'Failed to add feed.');
    } finally {
      setAdding(false);
    }
  }

  // Stats
  const stats = useMemo(() => {
    const totalIOCs = feeds.reduce((s, f) => s + f.ioc_count, 0);
    const active = feeds.filter(f => f.is_enabled).length;
    const healthy = feeds.filter(f => f.last_sync_status === 'success').length;
    const failed = feeds.filter(f => f.last_sync_status === 'failed').length;
    const maxIOC = Math.max(...feeds.map(f => f.ioc_count), 1);
    return { totalIOCs, active, healthy, failed, total: feeds.length, maxIOC };
  }, [feeds]);

  // Filtered & sorted
  const filteredFeeds = useMemo(() => {
    let result = [...feeds];

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(f =>
        f.name.toLowerCase().includes(q) ||
        f.slug.toLowerCase().includes(q) ||
        (f.description || '').toLowerCase().includes(q)
      );
    }

    if (filterType !== 'all') {
      result = result.filter(f => f.feed_type === filterType);
    }

    if (filterStatus === 'active') result = result.filter(f => f.is_enabled);
    else if (filterStatus === 'inactive') result = result.filter(f => !f.is_enabled);
    else if (filterStatus === 'healthy') result = result.filter(f => f.last_sync_status === 'success');
    else if (filterStatus === 'failed') result = result.filter(f => f.last_sync_status === 'failed');
    else if (filterStatus === 'never') result = result.filter(f => !f.last_sync_at);

    if (sortBy === 'name') result.sort((a, b) => a.name.localeCompare(b.name));
    else if (sortBy === 'ioc_count') result.sort((a, b) => b.ioc_count - a.ioc_count);
    else if (sortBy === 'last_sync') result.sort((a, b) => {
      if (!a.last_sync_at && !b.last_sync_at) return 0;
      if (!a.last_sync_at) return 1;
      if (!b.last_sync_at) return -1;
      return new Date(b.last_sync_at).getTime() - new Date(a.last_sync_at).getTime();
    });

    return result;
  }, [feeds, searchQuery, filterType, filterStatus, sortBy]);

  const feedTypeIcon = (type: string) => {
    switch (type) {
      case 'api': return <Globe className="w-3.5 h-3.5" />;
      case 'csv': return <FileText className="w-3.5 h-3.5" />;
      case 'stix': return <Code className="w-3.5 h-3.5" />;
      default: return <Database className="w-3.5 h-3.5" />;
    }
  };

  const feedTypeColor = (type: string) => {
    switch (type) {
      case 'api': return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
      case 'csv': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
      case 'stix': return 'text-purple-400 bg-purple-500/10 border-purple-500/20';
      default: return 'text-sentinel-text-muted bg-sentinel-bg-tertiary border-sentinel-border';
    }
  };

  const syncStatusInfo = (feed: FeedSource) => {
    if (!feed.last_sync_at) return { label: 'NEVER SYNCED', icon: <MinusCircle className="w-3 h-3" />, color: 'text-slate-500' };
    if (feed.last_sync_status === 'success') return { label: 'HEALTHY', icon: <CheckCircle2 className="w-3 h-3" />, color: 'text-emerald-400' };
    if (feed.last_sync_status === 'failed') return { label: 'FAILED', icon: <XCircle className="w-3 h-3" />, color: 'text-red-400' };
    return { label: 'PARTIAL', icon: <AlertTriangle className="w-3 h-3" />, color: 'text-amber-400' };
  };

  const iocBarWidth = (count: number) => Math.max(2, (count / stats.maxIOC) * 100);

  const iocBarColor = (count: number) => {
    if (count > 10000) return 'bg-sentinel-accent';
    if (count > 1000) return 'bg-blue-500';
    if (count > 0) return 'bg-emerald-500';
    return 'bg-slate-600';
  };

  const formatFrequency = (seconds: number) => {
    if (seconds >= 86400) return `${Math.round(seconds / 86400)}d`;
    if (seconds >= 3600) return `${Math.round(seconds / 3600)}h`;
    return `${Math.round(seconds / 60)}m`;
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-display font-bold text-sentinel-text-primary">Threat Feeds</h1>
          <p className="text-xs font-mono text-sentinel-text-muted mt-0.5">
            Manage and monitor threat intelligence feed sources
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleSyncAll}
            disabled={syncingAll}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-mono rounded border border-sentinel-accent/30 bg-sentinel-accent/5 text-sentinel-accent hover:bg-sentinel-accent/15 disabled:opacity-30 transition-colors"
          >
            <Zap className={cn('w-3 h-3', syncingAll && 'animate-pulse')} />
            {syncingAll ? 'SYNCING ALL...' : 'SYNC ALL'}
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-mono rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent hover:bg-sentinel-accent/20 transition-colors"
          >
            <Plus className="w-3 h-3" />
            ADD FEED
          </button>
          <button
            onClick={loadFeeds}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-mono rounded border border-sentinel-border text-sentinel-text-secondary hover:text-sentinel-accent hover:border-sentinel-accent/30 transition-colors"
          >
            <RefreshCw className="w-3 h-3" />
            REFRESH
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      {!loading && feeds.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Total Feeds', value: stats.total, icon: <Rss className="w-4 h-4" />, accent: 'text-sentinel-accent' },
            { label: 'Active Feeds', value: stats.active, icon: <Activity className="w-4 h-4" />, accent: 'text-emerald-400' },
            { label: 'Total IOCs Ingested', value: formatNumber(stats.totalIOCs), icon: <Database className="w-4 h-4" />, accent: 'text-blue-400' },
            { label: 'Healthy Syncs', value: `${stats.healthy}/${stats.total}`, icon: <CheckCircle2 className="w-4 h-4" />, accent: stats.failed > 0 ? 'text-amber-400' : 'text-emerald-400' },
          ].map((s, i) => (
            <div key={i} className="sentinel-card p-4 animate-fade-in" style={{ animationDelay: `${i * 50}ms` }}>
              <div className="flex items-center justify-between mb-2">
                <span className={cn('opacity-60', s.accent)}>{s.icon}</span>
                <span className="text-[9px] font-mono text-sentinel-text-muted uppercase tracking-wider">{s.label}</span>
              </div>
              <p className={cn('text-xl font-display font-bold', s.accent)}>{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Filters Row */}
      {!loading && feeds.length > 0 && (
        <div className="sentinel-card p-3 animate-fade-in">
          <div className="flex flex-wrap items-center gap-3">
            {/* Search */}
            <div className="flex items-center gap-2 px-2.5 py-1.5 rounded bg-sentinel-bg-primary border border-sentinel-border focus-within:border-sentinel-accent/40 transition-colors flex-1 min-w-[180px] max-w-xs">
              <Search className="w-3.5 h-3.5 text-sentinel-text-muted flex-shrink-0" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search feeds..."
                className="bg-transparent text-xs font-mono text-sentinel-text-primary placeholder:text-sentinel-text-muted w-full outline-none"
              />
            </div>

            <div className="h-5 w-px bg-sentinel-border" />

            {/* Type Filter */}
            <div className="flex items-center gap-1">
              <Filter className="w-3 h-3 text-sentinel-text-muted mr-1" />
              {(['all', 'api', 'csv', 'stix', 'custom'] as FilterType[]).map(t => (
                <button
                  key={t}
                  onClick={() => setFilterType(t)}
                  className={cn(
                    'px-2 py-1 text-[10px] font-mono uppercase rounded transition-colors',
                    filterType === t
                      ? 'bg-sentinel-accent/15 text-sentinel-accent border border-sentinel-accent/30'
                      : 'text-sentinel-text-muted hover:text-sentinel-text-secondary border border-transparent'
                  )}
                >
                  {t}
                </button>
              ))}
            </div>

            <div className="h-5 w-px bg-sentinel-border" />

            {/* Status Filter */}
            <div className="flex items-center gap-1">
              {([
                { key: 'all', label: 'All' },
                { key: 'active', label: 'Active' },
                { key: 'inactive', label: 'Disabled' },
                { key: 'healthy', label: 'Healthy' },
                { key: 'failed', label: 'Failed' },
                { key: 'never', label: 'Never Synced' },
              ] as { key: FilterStatus; label: string }[]).map(s => (
                <button
                  key={s.key}
                  onClick={() => setFilterStatus(s.key)}
                  className={cn(
                    'px-2 py-1 text-[10px] font-mono rounded transition-colors',
                    filterStatus === s.key
                      ? 'bg-sentinel-accent/15 text-sentinel-accent border border-sentinel-accent/30'
                      : 'text-sentinel-text-muted hover:text-sentinel-text-secondary border border-transparent'
                  )}
                >
                  {s.label}
                </button>
              ))}
            </div>

            <div className="flex-1" />

            {/* Sort */}
            <div className="flex items-center gap-1">
              <BarChart3 className="w-3 h-3 text-sentinel-text-muted mr-1" />
              {([
                { key: 'name', label: 'Name' },
                { key: 'ioc_count', label: 'IOCs' },
                { key: 'last_sync', label: 'Last Sync' },
              ] as { key: SortBy; label: string }[]).map(s => (
                <button
                  key={s.key}
                  onClick={() => setSortBy(s.key)}
                  className={cn(
                    'px-2 py-1 text-[10px] font-mono rounded transition-colors',
                    sortBy === s.key
                      ? 'bg-sentinel-accent/15 text-sentinel-accent border border-sentinel-accent/30'
                      : 'text-sentinel-text-muted hover:text-sentinel-text-secondary border border-transparent'
                  )}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Feed List */}
      {loading ? (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="sentinel-card p-5 animate-pulse">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-lg bg-sentinel-bg-tertiary" />
                <div className="flex-1 space-y-2">
                  <div className="h-4 w-40 bg-sentinel-bg-tertiary rounded" />
                  <div className="h-3 w-64 bg-sentinel-bg-tertiary rounded" />
                </div>
                <div className="h-3 w-20 bg-sentinel-bg-tertiary rounded" />
              </div>
            </div>
          ))}
        </div>
      ) : feeds.length === 0 ? (
        <div className="sentinel-card p-12 text-center">
          <Rss className="w-10 h-10 text-sentinel-text-muted mx-auto mb-3" />
          <p className="text-sentinel-text-muted text-sm font-mono">No feeds configured</p>
          <p className="text-sentinel-text-muted text-xs font-mono mt-1">
            Click &quot;ADD FEED&quot; to add a threat intelligence source
          </p>
        </div>
      ) : filteredFeeds.length === 0 ? (
        <div className="sentinel-card p-8 text-center">
          <Filter className="w-8 h-8 text-sentinel-text-muted mx-auto mb-2" />
          <p className="text-sentinel-text-muted text-xs font-mono">No feeds match your filters</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filteredFeeds.map((feed, i) => {
            const status = syncStatusInfo(feed);
            const isExpanded = expanded === feed.id;

            return (
              <div
                key={feed.id}
                className={cn(
                  'sentinel-card overflow-hidden animate-fade-in transition-all duration-200',
                  !feed.is_enabled && 'opacity-60',
                  isExpanded && 'ring-1 ring-sentinel-accent/20'
                )}
                style={{ animationDelay: `${i * 30}ms` }}
              >
                {/* Main Row */}
                <div className="p-4">
                  <div className="flex items-center gap-4">
                    {/* Feed Icon */}
                    <div className={cn(
                      'w-10 h-10 rounded-lg border flex items-center justify-center flex-shrink-0',
                      feedTypeColor(feed.feed_type)
                    )}>
                      {feedTypeIcon(feed.feed_type)}
                    </div>

                    {/* Name & Description */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <h3 className="text-sm font-mono font-semibold text-sentinel-text-primary truncate">{feed.name}</h3>
                        <span className={cn(
                          'text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border flex-shrink-0',
                          feedTypeColor(feed.feed_type)
                        )}>
                          {feed.feed_type}
                        </span>
                      </div>
                      <p className="text-[10px] font-mono text-sentinel-text-muted truncate">
                        {feed.description || 'No description'}
                      </p>
                    </div>

                    {/* IOC Bar */}
                    <div className="w-32 flex-shrink-0 hidden md:block">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[9px] font-mono text-sentinel-text-muted">IOCs</span>
                        <span className="text-[11px] font-mono font-semibold text-sentinel-text-primary">
                          {formatNumber(feed.ioc_count)}
                        </span>
                      </div>
                      <div className="h-1.5 rounded-full bg-sentinel-bg-primary overflow-hidden">
                        <div
                          className={cn('h-full rounded-full transition-all duration-500', iocBarColor(feed.ioc_count))}
                          style={{ width: `${iocBarWidth(feed.ioc_count)}%` }}
                        />
                      </div>
                    </div>

                    {/* Sync Status */}
                    <div className="flex items-center gap-1.5 flex-shrink-0 w-28">
                      <span className={status.color}>{status.icon}</span>
                      <div>
                        <span className={cn('text-[9px] font-mono font-semibold uppercase block', status.color)}>
                          {status.label}
                        </span>
                        <span className="text-[9px] font-mono text-sentinel-text-muted">
                          {feed.last_sync_at ? formatTimestamp(feed.last_sync_at) : '—'}
                        </span>
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <button
                        onClick={() => handleToggle(feed)}
                        className={cn(
                          'p-1.5 rounded transition-colors',
                          feed.is_enabled
                            ? 'text-emerald-400 hover:bg-emerald-400/10'
                            : 'text-sentinel-text-muted hover:bg-sentinel-bg-hover'
                        )}
                        title={feed.is_enabled ? 'Disable feed' : 'Enable feed'}
                      >
                        {feed.is_enabled ? <Power className="w-3.5 h-3.5" /> : <PowerOff className="w-3.5 h-3.5" />}
                      </button>
                      <button
                        onClick={() => handleSync(feed.id)}
                        disabled={syncing === feed.id || !feed.is_enabled}
                        className="p-1.5 rounded text-sentinel-text-muted hover:text-sentinel-accent hover:bg-sentinel-accent/10 disabled:opacity-30 transition-colors"
                        title="Sync now"
                      >
                        <RefreshCw className={cn('w-3.5 h-3.5', syncing === feed.id && 'animate-spin')} />
                      </button>
                      <button
                        onClick={() => setExpanded(isExpanded ? null : feed.id)}
                        className="p-1.5 rounded text-sentinel-text-muted hover:text-sentinel-text-primary hover:bg-sentinel-bg-hover transition-colors"
                        title="Details"
                      >
                        {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>

                {/* Expanded Detail Panel */}
                {isExpanded && (
                  <FeedDetailPanel
                    feed={feed}
                    onDelete={() => handleDelete(feed.id)}
                    deleting={deleting === feed.id}
                  />
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Add Feed Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="sentinel-card w-full max-w-lg p-6 animate-fade-in max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-sm font-display font-bold text-sentinel-text-primary">Add Feed Source</h2>
              <button onClick={() => setShowAddModal(false)} className="p-1 rounded hover:bg-sentinel-bg-hover transition-colors">
                <X className="w-4 h-4 text-sentinel-text-muted" />
              </button>
            </div>

            {addError && (
              <div className="mb-4 p-2.5 rounded bg-red-500/5 border border-red-500/20">
                <p className="text-xs font-mono text-red-400">{addError}</p>
              </div>
            )}

            <form onSubmit={handleAddFeed} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Name *</label>
                  <input
                    type="text"
                    value={addForm.name}
                    onChange={(e) => setAddForm({ ...addForm, name: e.target.value })}
                    placeholder="e.g., My Custom Feed"
                    className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Slug *</label>
                  <input
                    type="text"
                    value={addForm.slug}
                    onChange={(e) => setAddForm({ ...addForm, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '-') })}
                    placeholder="e.g., my-custom-feed"
                    className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Description</label>
                <input
                  type="text"
                  value={addForm.description}
                  onChange={(e) => setAddForm({ ...addForm, description: e.target.value })}
                  placeholder="Brief description of the feed source"
                  className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Feed Type *</label>
                  <div className="grid grid-cols-4 gap-1">
                    {['api', 'csv', 'stix', 'custom'].map(t => (
                      <button
                        key={t}
                        type="button"
                        onClick={() => setAddForm({ ...addForm, feed_type: t })}
                        className={cn(
                          'py-1.5 rounded text-[10px] font-mono uppercase border transition-colors',
                          addForm.feed_type === t
                            ? feedTypeColor(t) + ' font-semibold'
                            : 'border-sentinel-border text-sentinel-text-muted hover:text-sentinel-text-secondary'
                        )}
                      >
                        {t}
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Sync Frequency</label>
                  <select
                    value={addForm.sync_frequency}
                    onChange={(e) => setAddForm({ ...addForm, sync_frequency: Number(e.target.value) })}
                    className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                  >
                    <option value={900}>15 minutes</option>
                    <option value={1800}>30 minutes</option>
                    <option value={3600}>1 hour</option>
                    <option value={21600}>6 hours</option>
                    <option value={43200}>12 hours</option>
                    <option value={86400}>24 hours</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Feed URL</label>
                <input
                  type="text"
                  value={addForm.url}
                  onChange={(e) => setAddForm({ ...addForm, url: e.target.value })}
                  placeholder="https://..."
                  className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                />
              </div>

              <div>
                <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">API Key Env Variable</label>
                <input
                  type="text"
                  value={addForm.api_key_env}
                  onChange={(e) => setAddForm({ ...addForm, api_key_env: e.target.value })}
                  placeholder="e.g., MY_FEED_API_KEY"
                  className="w-full px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                />
              </div>

              <div className="flex gap-2 pt-2">
                <button
                  type="submit"
                  disabled={adding}
                  className="px-4 py-2 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-xs font-mono font-semibold hover:bg-sentinel-accent/20 disabled:opacity-30 transition-colors"
                >
                  {adding ? 'ADDING...' : 'ADD FEED'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded border border-sentinel-border text-xs font-mono text-sentinel-text-secondary hover:text-sentinel-text-primary transition-colors"
                >
                  CANCEL
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------- Expanded Detail Panel ---------- */

function FeedDetailPanel({ feed, onDelete, deleting }: { feed: FeedSource; onDelete: () => void; deleting: boolean }) {
  const [logs, setLogs] = useState<{ timestamp: string | null; status: string; iocs_ingested: number }[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(true);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    setLoadingLogs(true);
    getFeedLogs(feed.id).then(data => {
      setLogs(data.logs);
    }).catch(() => {}).finally(() => setLoadingLogs(false));
  }, [feed.id]);

  return (
    <div className="border-t border-sentinel-border bg-sentinel-bg-primary/50 animate-fade-in">
      <div className="p-5 grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Configuration */}
        <div>
          <h4 className="text-[10px] font-mono font-semibold text-sentinel-text-muted uppercase tracking-wider mb-3 flex items-center gap-1.5">
            <Settings2 className="w-3 h-3" />
            Configuration
          </h4>
          <div className="space-y-2">
            {[
              { label: 'Slug', value: feed.slug },
              { label: 'Type', value: feed.feed_type.toUpperCase() },
              { label: 'Frequency', value: formatFreqDetail(feed.sync_frequency) },
              { label: 'Created', value: formatDate(feed.created_at) },
              { label: 'API Key Env', value: feed.api_key_env || '—' },
              { label: 'Status', value: feed.is_enabled ? 'Enabled' : 'Disabled' },
            ].map(row => (
              <div key={row.label} className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-sentinel-text-muted">{row.label}</span>
                <span className="text-[10px] font-mono text-sentinel-text-secondary">{row.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Feed URL */}
        <div>
          <h4 className="text-[10px] font-mono font-semibold text-sentinel-text-muted uppercase tracking-wider mb-3 flex items-center gap-1.5">
            <Globe className="w-3 h-3" />
            Feed Endpoint
          </h4>
          {feed.url ? (
            <div className="p-2.5 rounded bg-sentinel-bg-primary border border-sentinel-border">
              <p className="text-[10px] font-mono text-sentinel-text-secondary break-all leading-relaxed">{feed.url}</p>
              <a
                href={feed.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 mt-2 text-[10px] font-mono text-sentinel-accent hover:underline"
              >
                <ExternalLink className="w-2.5 h-2.5" />
                Open URL
              </a>
            </div>
          ) : (
            <p className="text-[10px] font-mono text-sentinel-text-muted italic">No URL configured</p>
          )}

          {/* Config JSON */}
          {feed.config && Object.keys(feed.config).length > 0 && (
            <div className="mt-3">
              <h4 className="text-[10px] font-mono font-semibold text-sentinel-text-muted uppercase tracking-wider mb-1.5">Extra Config</h4>
              <pre className="text-[10px] font-mono text-sentinel-text-muted bg-sentinel-bg-primary border border-sentinel-border rounded p-2 overflow-auto max-h-24">
                {JSON.stringify(feed.config, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Sync Logs */}
        <div>
          <h4 className="text-[10px] font-mono font-semibold text-sentinel-text-muted uppercase tracking-wider mb-3 flex items-center gap-1.5">
            <Clock className="w-3 h-3" />
            Sync History
          </h4>
          {loadingLogs ? (
            <div className="space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="h-6 bg-sentinel-bg-tertiary rounded animate-pulse" />
              ))}
            </div>
          ) : logs.length === 0 ? (
            <p className="text-[10px] font-mono text-sentinel-text-muted italic">No sync logs available</p>
          ) : (
            <div className="space-y-1.5">
              {logs.map((log, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded bg-sentinel-bg-primary border border-sentinel-border">
                  <div className="flex items-center gap-2">
                    {log.status === 'success' ? (
                      <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    ) : log.status === 'failed' ? (
                      <XCircle className="w-3 h-3 text-red-400" />
                    ) : (
                      <MinusCircle className="w-3 h-3 text-slate-500" />
                    )}
                    <span className="text-[10px] font-mono text-sentinel-text-secondary">
                      {log.timestamp ? formatDate(log.timestamp) : 'No timestamp'}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-sentinel-text-muted">
                    {formatNumber(log.iocs_ingested)} IOCs
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Danger Zone */}
          <div className="mt-4 pt-3 border-t border-sentinel-border">
            {!confirmDelete ? (
              <button
                onClick={() => setConfirmDelete(true)}
                className="flex items-center gap-1.5 text-[10px] font-mono text-red-400/60 hover:text-red-400 transition-colors"
              >
                <Trash2 className="w-3 h-3" />
                Delete Feed
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-red-400">Confirm?</span>
                <button
                  onClick={onDelete}
                  disabled={deleting}
                  className="px-2 py-1 rounded text-[10px] font-mono bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 disabled:opacity-30 transition-colors"
                >
                  {deleting ? 'DELETING...' : 'YES, DELETE'}
                </button>
                <button
                  onClick={() => setConfirmDelete(false)}
                  className="px-2 py-1 rounded text-[10px] font-mono text-sentinel-text-muted hover:text-sentinel-text-primary border border-sentinel-border transition-colors"
                >
                  CANCEL
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function formatFreqDetail(seconds: number) {
  if (seconds >= 86400) return `${Math.round(seconds / 86400)} day(s)`;
  if (seconds >= 3600) return `${Math.round(seconds / 3600)} hour(s)`;
  return `${Math.round(seconds / 60)} minute(s)`;
}
