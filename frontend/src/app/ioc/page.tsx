'use client';

import { Suspense, useState, useEffect, useCallback } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Search, Filter, Download, ChevronLeft, ChevronRight } from 'lucide-react';
import { useIOCSearch } from '@/hooks/useIOCSearch';
import ScoreBadge from '@/components/ioc/ScoreBadge';
import { cn, formatTimestamp, truncate } from '@/lib/utils';
import type { SearchFilters } from '@/lib/types';

const IOC_TYPES = ['all', 'ip', 'domain', 'hash', 'url', 'email', 'cve'];

export default function IOCSearchPage() {
  return (
    <Suspense fallback={<div className="text-sentinel-text-muted text-sm font-mono p-8">Loading...</div>}>
      <IOCSearchContent />
    </Suspense>
  );
}

function IOCSearchContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { data, loading, error, search, filters, setFilters } = useIOCSearch();
  const [searchInput, setSearchInput] = useState(searchParams.get('q') || '');
  const [selectedType, setSelectedType] = useState('all');
  const [showFilters, setShowFilters] = useState(false);
  const [minScore, setMinScore] = useState<string>('');
  const [maxScore, setMaxScore] = useState<string>('');

  const doSearch = useCallback((overrides?: Partial<SearchFilters>) => {
    const f: SearchFilters = {
      query: searchInput || undefined,
      ioc_type: selectedType !== 'all' ? selectedType : undefined,
      min_score: minScore ? parseInt(minScore) : undefined,
      max_score: maxScore ? parseInt(maxScore) : undefined,
      page: 1,
      page_size: 50,
      sort_by: 'threat_score',
      sort_order: 'desc',
      ...overrides,
    };
    search(f);
  }, [searchInput, selectedType, minScore, maxScore, search]);

  useEffect(() => {
    doSearch();
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    doSearch();
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-display font-bold text-sentinel-text-primary">IOC Search</h1>
        <p className="text-xs font-mono text-sentinel-text-muted mt-0.5">
          Search and analyze Indicators of Compromise across all feeds
        </p>
      </div>

      {/* Search Bar */}
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="flex gap-3">
          <div className="flex items-center gap-2 px-4 py-2.5 rounded bg-sentinel-bg-secondary border border-sentinel-border flex-1 focus-within:border-sentinel-accent/40 transition-colors">
            <Search className="w-4 h-4 text-sentinel-text-muted flex-shrink-0" />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search by IP, domain, hash, URL, email, or CVE..."
              className="bg-transparent text-sm font-mono text-sentinel-text-primary placeholder:text-sentinel-text-muted w-full outline-none"
            />
          </div>
          <button
            type="submit"
            className="px-5 py-2.5 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-xs font-mono font-semibold hover:bg-sentinel-accent/20 transition-colors"
          >
            SEARCH
          </button>
          <button
            type="button"
            onClick={() => setShowFilters(!showFilters)}
            className={cn(
              'px-3 py-2.5 rounded border text-xs font-mono transition-colors',
              showFilters
                ? 'bg-sentinel-accent/10 border-sentinel-accent/30 text-sentinel-accent'
                : 'border-sentinel-border text-sentinel-text-muted hover:text-sentinel-text-secondary'
            )}
          >
            <Filter className="w-4 h-4" />
          </button>
        </div>

        {/* Type Filter Pills */}
        <div className="flex gap-2">
          {IOC_TYPES.map((type) => (
            <button
              key={type}
              type="button"
              onClick={() => { setSelectedType(type); doSearch({ ioc_type: type !== 'all' ? type : undefined }); }}
              className={cn(
                'px-3 py-1 rounded text-[10px] font-mono uppercase tracking-wider border transition-colors',
                selectedType === type
                  ? 'bg-sentinel-accent/10 border-sentinel-accent/30 text-sentinel-accent'
                  : 'border-sentinel-border text-sentinel-text-muted hover:text-sentinel-text-secondary hover:border-sentinel-border-hover'
              )}
            >
              {type}
            </button>
          ))}
        </div>

        {/* Advanced Filters */}
        {showFilters && (
          <div className="sentinel-card p-4 grid grid-cols-2 md:grid-cols-4 gap-3 animate-slide-up">
            <div>
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Min Score</label>
              <input
                type="number"
                min="0"
                max="100"
                value={minScore}
                onChange={(e) => setMinScore(e.target.value)}
                className="w-full px-2 py-1.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-xs font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                placeholder="0"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Max Score</label>
              <input
                type="number"
                min="0"
                max="100"
                value={maxScore}
                onChange={(e) => setMaxScore(e.target.value)}
                className="w-full px-2 py-1.5 rounded bg-sentinel-bg-primary border border-sentinel-border text-xs font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                placeholder="100"
              />
            </div>
          </div>
        )}
      </form>

      {/* Results */}
      {error && (
        <div className="sentinel-card p-4 border-sentinel-danger/30">
          <p className="text-xs font-mono text-sentinel-danger">{error}</p>
        </div>
      )}

      <div className="sentinel-card overflow-hidden">
        <div className="px-5 py-3 border-b border-sentinel-border flex items-center justify-between">
          <span className="text-xs font-mono text-sentinel-text-muted">
            {data ? `${data.total} results` : 'Searching...'}
          </span>
          {data && data.total > 0 && (
            <span className="text-[10px] font-mono text-sentinel-text-muted">
              Page {data.page} of {data.pages}
            </span>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-sentinel-border">
                <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">IOC Value</th>
                <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Type</th>
                <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Score</th>
                <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted hidden md:table-cell">First Seen</th>
                <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted hidden md:table-cell">Last Seen</th>
                <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted hidden lg:table-cell">Tags</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <tr key={i} className="border-b border-sentinel-border/50 animate-pulse">
                    <td className="px-4 py-3"><div className="h-3 w-52 bg-sentinel-bg-tertiary rounded" /></td>
                    <td className="px-4 py-3"><div className="h-3 w-12 bg-sentinel-bg-tertiary rounded" /></td>
                    <td className="px-4 py-3"><div className="h-3 w-10 bg-sentinel-bg-tertiary rounded" /></td>
                    <td className="px-4 py-3 hidden md:table-cell"><div className="h-3 w-16 bg-sentinel-bg-tertiary rounded" /></td>
                    <td className="px-4 py-3 hidden md:table-cell"><div className="h-3 w-16 bg-sentinel-bg-tertiary rounded" /></td>
                    <td className="px-4 py-3 hidden lg:table-cell"><div className="h-3 w-24 bg-sentinel-bg-tertiary rounded" /></td>
                  </tr>
                ))
              ) : !data || data.items.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center">
                    <p className="text-sentinel-text-muted text-sm font-mono">No IOCs found</p>
                    <p className="text-sentinel-text-muted text-xs font-mono mt-1">Enable threat feeds and run a sync to ingest IOCs</p>
                  </td>
                </tr>
              ) : (
                data.items.map((ioc, i) => (
                  <tr
                    key={ioc.id}
                    className="border-b border-sentinel-border/50 cursor-pointer hover:bg-sentinel-bg-hover transition-colors animate-fade-in"
                    style={{ animationDelay: `${i * 20}ms` }}
                    onClick={() => router.push(`/ioc/${ioc.id}`)}
                  >
                    <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">{truncate(ioc.value, 55)}</td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted uppercase">{ioc.type}</td>
                    <td className="px-4 py-2.5"><ScoreBadge score={ioc.threat_score} size="sm" showBar /></td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted hidden md:table-cell">{formatTimestamp(ioc.first_seen)}</td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted hidden md:table-cell">{formatTimestamp(ioc.last_seen)}</td>
                    <td className="px-4 py-2.5 hidden lg:table-cell">
                      <div className="flex gap-1 flex-wrap">
                        {(ioc.tags || []).slice(0, 3).map((tag) => (
                          <span key={tag} className="px-1.5 py-0.5 text-[9px] font-mono rounded bg-sentinel-bg-tertiary text-sentinel-text-muted border border-sentinel-border">{tag}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="px-5 py-3 border-t border-sentinel-border flex items-center justify-between">
            <button
              onClick={() => search({ ...filters, page: Math.max(1, (filters.page || 1) - 1) })}
              disabled={data.page <= 1}
              className="flex items-center gap-1 px-3 py-1 rounded text-xs font-mono border border-sentinel-border text-sentinel-text-muted hover:text-sentinel-text-secondary disabled:opacity-30 transition-colors"
            >
              <ChevronLeft className="w-3 h-3" /> Prev
            </button>
            <span className="text-[10px] font-mono text-sentinel-text-muted">
              {data.page} / {data.pages}
            </span>
            <button
              onClick={() => search({ ...filters, page: Math.min(data.pages, (filters.page || 1) + 1) })}
              disabled={data.page >= data.pages}
              className="flex items-center gap-1 px-3 py-1 rounded text-xs font-mono border border-sentinel-border text-sentinel-text-muted hover:text-sentinel-text-secondary disabled:opacity-30 transition-colors"
            >
              Next <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
