'use client';

import { useState, useCallback } from 'react';
import { searchIOCs, getIOCs } from '@/lib/api';
import type { IOC, PaginatedResponse, SearchFilters } from '@/lib/types';

interface IOCSearchResult {
  data: PaginatedResponse<IOC> | null;
  loading: boolean;
  error: string | null;
  search: (filters: SearchFilters) => Promise<void>;
  loadPage: (page: number) => Promise<void>;
  filters: SearchFilters;
  setFilters: (filters: SearchFilters) => void;
}

export function useIOCSearch(): IOCSearchResult {
  const [data, setData] = useState<PaginatedResponse<IOC> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<SearchFilters>({
    page: 1,
    page_size: 50,
    sort_by: 'last_seen',
    sort_order: 'desc',
  });

  const search = useCallback(async (newFilters: SearchFilters) => {
    setLoading(true);
    setError(null);
    setFilters(newFilters);
    try {
      const result = await searchIOCs(newFilters);
      setData(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Search failed');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadPage = useCallback(async (page: number) => {
    const updatedFilters = { ...filters, page };
    await search(updatedFilters);
  }, [filters, search]);

  return { data, loading, error, search, loadPage, filters, setFilters };
}
