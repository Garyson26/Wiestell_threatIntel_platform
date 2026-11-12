'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Clock, Search, Upload, Eye, Filter, Trash2, BarChart3 } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { getUserActivities, clearUserActivities } from '@/lib/userActivity';
import type { UserActivity } from '@/lib/userActivity';
import { formatTimestamp } from '@/lib/utils';
import ScoreBadge from '@/components/ioc/ScoreBadge';
import { cn } from '@/lib/utils';

export default function HistoryPage() {
  const { user } = useAuth();
  const router = useRouter();
  const [activities, setActivities] = useState<UserActivity[]>([]);
  const [filteredActivities, setFilteredActivities] = useState<UserActivity[]>([]);
  const [filterType, setFilterType] = useState<'all' | 'search' | 'submit' | 'view'>('all');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');

  useEffect(() => {
    if (user?.id) {
      const userActivities = getUserActivities(user.id);
      setActivities(userActivities);
      setFilteredActivities(userActivities);
    }
  }, [user]);

  useEffect(() => {
    let filtered = activities;
    
    // Filter by type
    if (filterType !== 'all') {
      filtered = filtered.filter(a => a.type === filterType);
    }
    
    // Sort
    filtered = [...filtered].sort((a, b) => {
      const dateA = new Date(a.timestamp).getTime();
      const dateB = new Date(b.timestamp).getTime();
      return sortOrder === 'desc' ? dateB - dateA : dateA - dateB;
    });
    
    setFilteredActivities(filtered);
  }, [activities, filterType, sortOrder]);

  const handleClearHistory = () => {
    if (user?.id && confirm('Are you sure you want to clear all your activity history? This cannot be undone.')) {
      clearUserActivities(user.id);
      setActivities([]);
      setFilteredActivities([]);
    }
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'search':
        return <Search className="w-4 h-4" />;
      case 'submit':
        return <Upload className="w-4 h-4" />;
      case 'view':
        return <Eye className="w-4 h-4" />;
      default:
        return <Clock className="w-4 h-4" />;
    }
  };

  const getActivityColor = (type: string) => {
    switch (type) {
      case 'search':
        return 'text-gray-700';
      case 'submit':
        return 'text-gray-800';
      case 'view':
        return 'text-wiestell-accent';
      default:
        return 'text-wiestell-text-muted';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold text-wiestell-text-primary mb-2 flex items-center gap-2">
            <Clock className="w-6 h-6" />
            Activity History
          </h1>
          <p className="text-wiestell-text-secondary">
            Complete history of your IOC searches, submissions, and views
          </p>
        </div>
        <button
          onClick={() => router.push('/analytics')}
          className="px-4 py-2 rounded border border-wiestell-border text-wiestell-text-muted hover:text-wiestell-accent hover:border-wiestell-accent/30 transition-colors text-xs font-mono flex items-center gap-2"
        >
          <BarChart3 className="w-4 h-4" />
          Back to Dashboard
        </button>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="wiestell-card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-wiestell-accent/10">
              <Clock className="w-5 h-5 text-wiestell-accent" />
            </div>
            <div>
              <p className="text-xs font-mono text-wiestell-text-muted">Total Activities</p>
              <p className="text-xl font-bold text-wiestell-text-primary">{activities.length}</p>
            </div>
          </div>
        </div>
        <div className="wiestell-card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-gray-200">
              <Search className="w-5 h-5 text-gray-700" />
            </div>
            <div>
              <p className="text-xs font-mono text-wiestell-text-muted">Searches</p>
              <p className="text-xl font-bold text-wiestell-text-primary">
                {activities.filter(a => a.type === 'search').length}
              </p>
            </div>
          </div>
        </div>
        <div className="wiestell-card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-gray-200">
              <Upload className="w-5 h-5 text-gray-800" />
            </div>
            <div>
              <p className="text-xs font-mono text-wiestell-text-muted">Submissions</p>
              <p className="text-xl font-bold text-wiestell-text-primary">
                {activities.filter(a => a.type === 'submit' && a.iocId).length}
              </p>
            </div>
          </div>
        </div>
        <div className="wiestell-card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-wiestell-accent/10">
              <Eye className="w-5 h-5 text-wiestell-accent" />
            </div>
            <div>
              <p className="text-xs font-mono text-wiestell-text-muted">Views</p>
              <p className="text-xl font-bold text-wiestell-text-primary">
                {activities.filter(a => a.type === 'view').length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="wiestell-card p-4">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-wiestell-text-muted" />
            <span className="text-xs font-mono text-wiestell-text-muted uppercase">Filter:</span>
            {['all', 'search', 'submit', 'view'].map((type) => (
              <button
                key={type}
                onClick={() => setFilterType(type as any)}
                className={cn(
                  'px-3 py-1 rounded text-[10px] font-mono uppercase tracking-wider border transition-colors',
                  filterType === type
                    ? 'bg-wiestell-accent/10 border-wiestell-accent/30 text-wiestell-accent'
                    : 'border-wiestell-border text-wiestell-text-muted hover:text-wiestell-text-secondary hover:border-wiestell-border-hover'
                )}
              >
                {type}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')}
              className="px-3 py-1 rounded text-[10px] font-mono uppercase border border-wiestell-border text-wiestell-text-muted hover:text-wiestell-text-secondary transition-colors"
            >
              {sortOrder === 'desc' ? '↓ Newest First' : '↑ Oldest First'}
            </button>
            {activities.length > 0 && (
              <button
                onClick={handleClearHistory}
                className="px-3 py-1 rounded text-[10px] font-mono uppercase border border-wiestell-danger/30 text-wiestell-danger hover:bg-wiestell-danger/10 transition-colors flex items-center gap-1"
              >
                <Trash2 className="w-3 h-3" />
                Clear History
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Activity List */}
      <div className="wiestell-card overflow-hidden">
        <div className="px-5 py-3 border-b border-wiestell-border flex items-center justify-between">
          <span className="text-xs font-mono text-wiestell-text-muted">
            {filteredActivities.length} {filteredActivities.length === 1 ? 'activity' : 'activities'}
          </span>
        </div>
        
        {filteredActivities.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-wiestell-border">
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Type</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Details</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">IOC Type</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Threat Score</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Timestamp</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredActivities.map((activity, idx) => (
                  <tr
                    key={activity.id}
                    onClick={() => activity.iocId && router.push(`/ioc-detail/${activity.iocId}`)}
                    className={`border-b border-wiestell-border/50 hover:bg-wiestell-bg-hover transition-colors animate-fade-in ${activity.iocId ? 'cursor-pointer' : ''}`}
                    style={{ animationDelay: `${Math.min(idx, 10) * 30}ms` }}
                  >
                    <td className="px-4 py-2.5">
                      <div className={cn('flex items-center gap-2', getActivityColor(activity.type))}>
                        {getActivityIcon(activity.type)}
                        <span className="text-xs font-mono uppercase">{activity.type}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      {activity.type === 'search' && activity.metadata ? (
                        <span className="text-xs font-mono text-wiestell-text-primary">
                          Query: {(activity.metadata as any).query || 'N/A'} ({(activity.metadata as any).resultsCount || 0} results)
                        </span>
                      ) : activity.iocValue ? (
                        <span className="text-xs font-mono text-wiestell-text-primary max-w-md truncate block">
                          {activity.iocValue}
                        </span>
                      ) : (
                        <span className="text-xs font-mono text-wiestell-text-muted">-</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      {activity.iocType ? (
                        <span className="text-[10px] font-mono uppercase text-wiestell-text-muted px-2 py-0.5 rounded bg-wiestell-bg-primary border border-wiestell-border">
                          {activity.iocType}
                        </span>
                      ) : (
                        <span className="text-xs text-wiestell-text-muted">-</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      {activity.threatScore !== undefined ? (
                        <ScoreBadge score={activity.threatScore} size="sm" />
                      ) : (
                        <span className="text-xs text-wiestell-text-muted">-</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-wiestell-text-muted">
                      {formatTimestamp(activity.timestamp)}
                    </td>
                    <td className="px-4 py-2.5">
                      {activity.iocId && (
                        <button
                          onClick={() => router.push(`/ioc-detail/${activity.iocId}`)}
                          className="px-2 py-1 rounded text-[10px] font-mono border border-wiestell-border text-wiestell-text-muted hover:text-wiestell-accent hover:border-wiestell-accent/30 transition-colors"
                        >
                          View IOC
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-12 text-center">
            <Clock className="w-16 h-16 text-wiestell-text-muted mx-auto mb-4 opacity-50" />
            <p className="text-sm font-mono text-wiestell-text-muted mb-2">
              {filterType === 'all' ? 'No activity history found' : `No ${filterType} activities found`}
            </p>
            <p className="text-xs font-mono text-wiestell-text-muted">
              {filterType === 'all' 
                ? 'Start by searching or submitting IOCs'
                : 'Try selecting a different filter'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
