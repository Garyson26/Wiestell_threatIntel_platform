const API_BASE = '';

async function fetchAPI<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!res.ok) {
    let message = `API error: ${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body.detail) message = body.detail;
    } catch {
      // use default message
    }
    throw new Error(message);
  }

  return res.json();
}

// Dashboard
export const getDashboardStats = () => fetchAPI<import('./types').DashboardStats>('/api/v1/dashboard/stats');
export const getDashboardTimeline = (limit = 50) => fetchAPI<import('./types').TimelineEntry[]>(`/api/v1/dashboard/timeline?limit=${limit}`);
export const getDashboardGeo = () => fetchAPI<import('./types').GeoData[]>('/api/v1/dashboard/geo');
export const getTopThreats = (limit = 20) => fetchAPI<import('./types').TopThreat[]>(`/api/v1/dashboard/top-threats?limit=${limit}`);
export const getFeedHealth = () => fetchAPI<import('./types').FeedHealth[]>('/api/v1/dashboard/feed-health');
export const getTrends = (days = 7) => fetchAPI<import('./types').TrendPoint[]>(`/api/v1/dashboard/trends?days=${days}`);

// IOCs
export const getIOCs = (params?: Record<string, string>) => {
  const query = params ? '?' + new URLSearchParams(params).toString() : '';
  return fetchAPI<import('./types').PaginatedResponse<import('./types').IOC>>(`/api/v1/iocs${query}`);
};
export const getIOC = (id: string) => fetchAPI<import('./types').IOCDetail>(`/api/v1/iocs/${id}`);
export const searchIOCs = (filters: import('./types').SearchFilters) =>
  fetchAPI<import('./types').PaginatedResponse<import('./types').IOC>>('/api/v1/iocs/search', {
    method: 'POST',
    body: JSON.stringify(filters),
  });
export const bulkLookup = (values: string[]) =>
  fetchAPI<import('./types').IOC[]>('/api/v1/iocs/bulk', {
    method: 'POST',
    body: JSON.stringify({ values }),
  });
export const updateIOCTags = (id: string, tags: string[]) =>
  fetchAPI<import('./types').IOC>(`/api/v1/iocs/${id}/tags`, {
    method: 'PUT',
    body: JSON.stringify({ tags }),
  });
export const getIOCEnrichment = (id: string) => fetchAPI<unknown[]>(`/api/v1/iocs/${id}/enrichment`);
export const triggerEnrichment = (id: string) =>
  fetchAPI<unknown>(`/api/v1/iocs/${id}/enrich`, { method: 'POST' });
export const getIOCRelationships = (id: string) => fetchAPI<import('./types').IOCRelationship[]>(`/api/v1/iocs/${id}/relationships`);
export const getIOCTimeline = (id: string) => fetchAPI<unknown[]>(`/api/v1/iocs/${id}/timeline`);

// Feeds
export const getFeeds = () => fetchAPI<import('./types').FeedSource[]>('/api/v1/feeds');
export const triggerFeedSync = (id: string) =>
  fetchAPI<unknown>(`/api/v1/feeds/${id}/sync`, { method: 'POST' });
export const updateFeed = (id: string, data: Partial<import('./types').FeedSource>) =>
  fetchAPI<import('./types').FeedSource>(`/api/v1/feeds/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
export const createFeed = (data: { name: string; slug: string; description?: string; feed_type: string; url?: string; api_key_env?: string; sync_frequency?: number }) =>
  fetchAPI<import('./types').FeedSource>('/api/v1/feeds', {
    method: 'POST',
    body: JSON.stringify(data),
  });
export const deleteFeed = (id: string) =>
  fetchAPI<unknown>(`/api/v1/feeds/${id}`, { method: 'DELETE' });
export const getFeedLogs = (id: string) =>
  fetchAPI<{ feed_id: string; feed_name: string; logs: { timestamp: string | null; status: string; iocs_ingested: number }[] }>(`/api/v1/feeds/${id}/logs`);

// ATT&CK
export const getAttackMatrix = () => fetchAPI<import('./types').AttackMatrix>('/api/v1/attack/matrix');
export const getAttackHeatmap = (minScore = 0) => fetchAPI<import('./types').HeatmapEntry[]>(`/api/v1/attack/heatmap?min_score=${minScore}`);
export const getAttackTechnique = (id: string) => fetchAPI<unknown>(`/api/v1/attack/techniques/${id}`);

// Reports
export const getReports = () => fetchAPI<{ items: import('./types').Report[]; total: number }>('/api/v1/reports');
export const generateReport = (data: Record<string, unknown>) =>
  fetchAPI<import('./types').Report>('/api/v1/reports/generate', {
    method: 'POST',
    body: JSON.stringify(data),
  });
export const getDailyBrief = () => fetchAPI<import('./types').Report>('/api/v1/reports/daily-brief');

export async function downloadReport(id: string): Promise<Blob> {
  const url = `${API_BASE}/api/v1/reports/${id}/download`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.blob();
}

// Notifications
export const getNotifications = (limit = 20) => fetchAPI<import('./types').Notification[]>(`/api/v1/dashboard/notifications?limit=${limit}`);

// Users & Auth
export const registerUser = (data: { username: string; email: string; password: string; full_name?: string; role?: string }) =>
  fetchAPI<import('./types').TokenResponse>('/api/v1/users/register', {
    method: 'POST',
    body: JSON.stringify(data),
  });
export const loginUser = (data: { username: string; password: string }) =>
  fetchAPI<import('./types').TokenResponse>('/api/v1/users/login', {
    method: 'POST',
    body: JSON.stringify(data),
  });
export const getMe = (token: string) =>
  fetchAPI<import('./types').UserProfile>('/api/v1/users/me', {
    headers: { Authorization: `Bearer ${token}` },
  });
export const getUsers = () => fetchAPI<{ items: import('./types').UserProfile[]; total: number }>('/api/v1/users');
export const getUser = (id: string) => fetchAPI<import('./types').UserProfile>(`/api/v1/users/${id}`);
export const updateUser = (id: string, data: { full_name?: string; email?: string }) =>
  fetchAPI<import('./types').UserProfile>(`/api/v1/users/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });

// AI
export const analyzeIOCWithAI = (iocId: string) =>
  fetchAPI<import('./types').AIAnalysis>(`/api/v1/ai/analyze/${iocId}`, { method: 'POST' });
export const chatWithAI = (messages: import('./types').AIChatMessage[], context?: string) =>
  fetchAPI<import('./types').AIChatResponse>('/api/v1/ai/chat', {
    method: 'POST',
    body: JSON.stringify({ messages, context }),
  });
export const generateAIReport = () =>
  fetchAPI<import('./types').Report>('/api/v1/ai/report', { method: 'POST' });
export const getAIStatus = () => fetchAPI<import('./types').AIStatus>('/api/v1/ai/status');

// Health
export const getHealth = () => fetchAPI<{ status: string }>('/api/v1/health');
