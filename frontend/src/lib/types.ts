export interface IOC {
  id: string;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'cve';
  value: string;
  threat_score: number;
  confidence: number;
  first_seen: string | null;
  last_seen: string | null;
  sighting_count: number;
  tags: string[];
  metadata?: Record<string, unknown>;
  mitre_techniques: string[];
  created_at: string;
  updated_at: string;
}

export interface IOCDetail extends IOC {
  enrichments: EnrichmentData[];
  sources: IOCSourceInfo[];
  relationships: IOCRelationship[];
}

export interface EnrichmentData {
  source: string;
  data: Record<string, unknown>;
  enriched_at: string;
}

export interface IOCSourceInfo {
  feed_name: string;
  feed_slug: string;
  ingested_at: string | null;
}

export interface IOCRelationship {
  id: string;
  type: string;
  value: string;
  threat_score: number;
  relationship_type: string;
  direction: 'incoming' | 'outgoing';
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface FeedSource {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  feed_type: string;
  url: string | null;
  api_key_env: string | null;
  is_enabled: boolean;
  sync_frequency: number;
  last_sync_at: string | null;
  last_sync_status: string | null;
  ioc_count: number;
  config: Record<string, unknown>;
  created_at: string;
}

export interface FeedHealth {
  id: string;
  name: string;
  slug: string;
  is_enabled: boolean;
  last_sync_at: string | null;
  last_sync_status: string;
  ioc_count: number;
  health: 'healthy' | 'degraded' | 'offline' | 'disabled' | 'never_synced';
}

export interface DashboardStats {
  total_iocs: number;
  new_24h: number;
  delta_pct: number;
  critical_threats: number;
  avg_threat_score: number;
  active_feeds: number;
  total_feeds: number;
  trends: TrendPoint[];
}

export interface TrendPoint {
  date: string;
  count: number;
  total?: number;
  critical?: number;
}

export interface TopThreat {
  id: string;
  type: string;
  value: string;
  threat_score: number;
  tags: string[];
  first_seen: string | null;
  last_seen: string | null;
  sighting_count: number;
}

export interface TimelineEntry {
  id: string;
  type: string;
  value: string;
  threat_score: number;
  tags: string[];
  created_at: string | null;
  first_seen: string | null;
}

export interface GeoData {
  country: string;
  count: number;
  avg_score: number;
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  ioc_count: number;
  url: string | null;
  description?: string;
}

export interface AttackMatrix {
  [tactic: string]: AttackTechnique[];
}

export interface HeatmapEntry {
  technique_id: string;
  technique_name: string;
  tactic: string;
  ioc_count: number;
  intensity: number;
}

export interface Report {
  id: string;
  title: string;
  report_type: string;
  summary: string | null;
  content: Record<string, unknown>;
  parameters: Record<string, unknown>;
  generated_at: string;
  created_by: string | null;
}

export interface SearchFilters {
  query?: string;
  ioc_type?: string;
  min_score?: number;
  max_score?: number;
  tags?: string[];
  date_from?: string;
  date_to?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  page?: number;
  page_size?: number;
}

export type ScoreCategory = 'low' | 'medium' | 'high' | 'critical';

export interface Notification {
  id: string;
  level: 'critical' | 'warning' | 'info';
  message: string;
  ioc_type: string;
  ioc_value: string;
  threat_score: number;
  timestamp: string;
}

export interface UserProfile {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: UserProfile;
}

// AI Types
export interface AIAnalysis {
  analysis: string;
  summary: string;
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  recommendations: string[];
}

export interface AIChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface AIChatResponse {
  response: string;
}

export interface AIStatus {
  available: boolean;
  model: string;
}
