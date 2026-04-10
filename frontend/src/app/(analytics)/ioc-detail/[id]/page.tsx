'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Globe, Link, Hash, ExternalLink, Mail, ShieldAlert, Tag, Clock, Activity, Database, Sparkles } from 'lucide-react';
import { getIOC } from '@/lib/api';
import ScoreBadge from '@/components/ioc/ScoreBadge';
import { cn, formatDate, formatTimestamp, getScoreCategory, getScoreColor } from '@/lib/utils';
import { useAuth } from '@/lib/auth';
import { trackView } from '@/lib/userActivity';
import type { IOCDetail } from '@/lib/types';

function getExternalLinks(type: string, value: string) {
  const encoded = encodeURIComponent(value);
  const vtBase = 'https://www.virustotal.com/gui';
  const vtUrl =
    type === 'ip'     ? `${vtBase}/ip-address/${value}` :
    type === 'domain' ? `${vtBase}/domain/${value}` :
    type === 'hash'   ? `${vtBase}/file/${value}` :
                        `${vtBase}/search/${encoded}`;

  const links = [{ label: 'VirusTotal', url: vtUrl, description: 'Multi-engine threat intelligence scan' }];

  if (type === 'ip') {
    links.push(
      { label: 'Shodan',    url: `https://www.shodan.io/host/${value}`,              description: 'Internet-facing device & service scan' },
      { label: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${value}`,         description: 'Community IP abuse reports' },
    );
  } else if (type === 'domain') {
    links.push(
      { label: 'Shodan',     url: `https://www.shodan.io/search?query=hostname:${encoded}`, description: 'Hostname infrastructure lookup' },
      { label: 'URLScan.io', url: `https://urlscan.io/search/#domain:${value}`,              description: 'Domain scan history' },
    );
  } else if (type === 'hash') {
    links.push({ label: 'MalwareBazaar', url: `https://bazaar.abuse.ch/sample/${value}/`, description: 'Malware sample repository' });
  } else if (type === 'url') {
    links.push(
      { label: 'URLScan.io', url: `https://urlscan.io/search/#page.url:${encoded}`,        description: 'URL scan & screenshot history' },
      { label: 'URLhaus',    url: `https://urlhaus.abuse.ch/browse.php?search=${encoded}`, description: 'Malware distribution URL tracker' },
    );
  } else if (type === 'cve') {
    links.push({ label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${value}`, description: 'NIST National Vulnerability Database' });
  }
  return links;
}

const typeIcons: Record<string, React.ComponentType<{ className?: string; style?: React.CSSProperties }>> = {
  ip: Globe,
  domain: Link,
  hash: Hash,
  url: ExternalLink,
  email: Mail,
  cve: ShieldAlert,
};

export default function IOCDetailPage() {
  const params = useParams();
  const router = useRouter();
  const { user } = useAuth();
  const [ioc, setIOC] = useState<IOCDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const data = await getIOC(params.id as string);
        setIOC(data);
        // Track view activity
        if (user?.id) {
          trackView(user.id, data);
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load IOC');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [params.id, user]);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-6 w-48 bg-sentinel-bg-tertiary rounded animate-pulse" />
        <div className="sentinel-card p-6 space-y-4 animate-pulse">
          <div className="h-8 w-96 bg-sentinel-bg-tertiary rounded" />
          <div className="h-4 w-64 bg-sentinel-bg-tertiary rounded" />
        </div>
      </div>
    );
  }

  if (error || !ioc) {
    return (
      <div className="sentinel-card p-8 text-center">
        <p className="text-sentinel-danger font-mono text-sm">{error || 'IOC not found'}</p>
        <button onClick={() => router.back()} className="mt-4 text-xs font-mono text-sentinel-accent hover:underline">
          Go back
        </button>
      </div>
    );
  }

  const Icon = typeIcons[ioc.type] || Globe;
  const scoreColor = getScoreColor(ioc.threat_score);

  return (
    <div className="space-y-6">
      {/* Back Button */}
      <button
        onClick={() => router.back()}
        className="flex items-center gap-2 text-xs font-mono text-sentinel-text-muted hover:text-sentinel-accent transition-colors"
      >
        <ArrowLeft className="w-3 h-3" /> Back
      </button>

      {/* IOC Header */}
      <div className="sentinel-card p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded bg-sentinel-bg-primary border border-sentinel-border">
              <Icon className="w-6 h-6" style={{ color: scoreColor }} />
            </div>
            <div>
              <p className="font-mono text-lg text-sentinel-text-primary break-all">{ioc.value}</p>
              <div className="flex items-center gap-3 mt-1 flex-wrap">
                <span className="text-[10px] font-mono uppercase tracking-wider text-sentinel-text-muted px-2 py-0.5 rounded bg-sentinel-bg-primary border border-sentinel-border">
                  {ioc.type}
                </span>
                <span className="text-[10px] font-mono text-sentinel-text-muted">
                  {ioc.sighting_count} sightings
                </span>
                <span className="text-[10px] font-mono text-sentinel-text-muted">
                  First: {formatDate(ioc.first_seen)}
                </span>
                <span className="text-[10px] font-mono text-sentinel-text-muted">
                  Last: {formatDate(ioc.last_seen)}
                </span>
              </div>
            </div>
          </div>
          <div className="text-center">
            <p className="text-3xl font-mono font-bold" style={{ color: scoreColor }}>{ioc.threat_score}</p>
            <p className="text-[10px] font-mono uppercase" style={{ color: scoreColor }}>{getScoreCategory(ioc.threat_score)}</p>
            <p className="text-[9px] font-mono text-sentinel-text-muted mt-1">Confidence: {ioc.confidence}%</p>
          </div>
        </div>

        {/* Tags */}
        {ioc.tags && ioc.tags.length > 0 && (
          <div className="flex items-center gap-2 mt-4 flex-wrap">
            <Tag className="w-3 h-3 text-sentinel-text-muted" />
            {ioc.tags.map((tag) => (
              <span key={tag} className="px-2 py-0.5 text-[10px] font-mono rounded bg-sentinel-accent/10 text-sentinel-accent border border-sentinel-accent/20">
                {tag}
              </span>
            ))}
          </div>
        )}

        {/* MITRE Techniques */}
        {ioc.mitre_techniques && ioc.mitre_techniques.length > 0 && (
          <div className="flex items-center gap-2 mt-3 flex-wrap">
            <ShieldAlert className="w-3 h-3 text-sentinel-text-muted" />
            <span className="text-[10px] font-mono text-sentinel-text-muted mr-1">MITRE ATT&CK:</span>
            {ioc.mitre_techniques.map((tech) => (
              <span key={tech} className="px-2 py-0.5 text-[10px] font-mono rounded bg-sentinel-accent-secondary/10 text-purple-400 border border-purple-500/20">
                {tech}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-sentinel-border overflow-x-auto">
        {[
          { id: 'overview',         label: 'Overview',          icon: Activity     },
          { id: 'enrichment',       label: 'Enrichment',        icon: Sparkles     },
          { id: 'history',          label: 'History',           icon: Clock        },
          { id: 'sources',          label: 'Sources',           icon: Database     },
          { id: 'relationships',    label: 'Relationships',     icon: Link         },
          { id: 'external-sources', label: 'External Sources',  icon: ExternalLink },
        ].map(({ id, label, icon: TabIcon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={cn(
              'px-4 py-2 text-xs font-mono uppercase tracking-wider transition-colors border-b-2 -mb-px flex items-center gap-1.5 whitespace-nowrap',
              activeTab === id
                ? 'text-sentinel-accent border-sentinel-accent'
                : 'text-sentinel-text-muted border-transparent hover:text-sentinel-text-secondary'
            )}
          >
            <TabIcon className="w-3 h-3" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="animate-fade-in">
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Stats */}
            <div className="sentinel-card p-5">
              <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-3">Statistics</h3>
              <div className="space-y-2">
                <div className="flex justify-between items-center py-1.5 border-b border-sentinel-border/50">
                  <span className="text-xs font-mono text-sentinel-text-muted">Threat Score</span>
                  <span className="text-xs font-mono font-semibold" style={{ color: scoreColor }}>{ioc.threat_score}/100</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-sentinel-border/50">
                  <span className="text-xs font-mono text-sentinel-text-muted">Confidence</span>
                  <span className="text-xs font-mono text-sentinel-text-secondary">{ioc.confidence}%</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-sentinel-border/50">
                  <span className="text-xs font-mono text-sentinel-text-muted">Sighting Count</span>
                  <span className="text-xs font-mono text-sentinel-text-secondary">{ioc.sighting_count}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-sentinel-border/50">
                  <span className="text-xs font-mono text-sentinel-text-muted">First Seen</span>
                  <span className="text-xs font-mono text-sentinel-text-secondary">{formatTimestamp(ioc.first_seen)}</span>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-xs font-mono text-sentinel-text-muted">Last Seen</span>
                  <span className="text-xs font-mono text-sentinel-text-secondary">{formatTimestamp(ioc.last_seen)}</span>
                </div>
              </div>
            </div>

            {/* Metadata */}
            <div className="sentinel-card p-5">
              <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-3">Metadata</h3>
              <div className="space-y-2">
                <div className="flex justify-between items-center py-1.5 border-b border-sentinel-border/50">
                  <span className="text-xs font-mono text-sentinel-text-muted">Created</span>
                  <span className="text-xs font-mono text-sentinel-text-secondary">{formatTimestamp(ioc.created_at)}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-sentinel-border/50">
                  <span className="text-xs font-mono text-sentinel-text-muted">Updated</span>
                  <span className="text-xs font-mono text-sentinel-text-secondary">{formatTimestamp(ioc.updated_at)}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-sentinel-border/50">
                  <span className="text-xs font-mono text-sentinel-text-muted">Sources</span>
                  <span className="text-xs font-mono text-sentinel-text-secondary">{ioc.sources?.length || 0}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-sentinel-border/50">
                  <span className="text-xs font-mono text-sentinel-text-muted">Relationships</span>
                  <span className="text-xs font-mono text-sentinel-text-secondary">{ioc.relationships?.length || 0}</span>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-xs font-mono text-sentinel-text-muted">Enrichments</span>
                  <span className="text-xs font-mono text-sentinel-text-secondary">{ioc.enrichments?.length || 0}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'enrichment' && (
          <div className="sentinel-card overflow-hidden">
            <div className="px-5 py-3 border-b border-sentinel-border">
              <h3 className="text-sm font-display font-semibold text-sentinel-text-primary">Enrichment Data</h3>
            </div>
            {ioc.enrichments && ioc.enrichments.length > 0 ? (
              <div className="divide-y divide-sentinel-border">
                {ioc.enrichments.map((enrichment, idx) => (
                  <div key={idx} className="p-5">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <Sparkles className="w-4 h-4 text-sentinel-accent" />
                        <span className="text-xs font-mono font-semibold text-sentinel-text-primary uppercase tracking-wider">
                          {enrichment.source}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-sentinel-text-muted">
                        {formatTimestamp(enrichment.enriched_at)}
                      </span>
                    </div>
                    <div className="bg-sentinel-bg-primary rounded p-3 border border-sentinel-border">
                      <pre className="text-[10px] font-mono text-sentinel-text-secondary overflow-x-auto">
{JSON.stringify(enrichment.data, null, 2)}
                      </pre>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center text-xs font-mono text-sentinel-text-muted">No enrichment data available</div>
            )}
          </div>
        )}

        {activeTab === 'history' && (
          <div className="sentinel-card p-5">
            <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-4">IOC Timeline</h3>
            <div className="space-y-3">
              {/* Timeline entries */}
              <div className="relative pl-6 pb-4 border-l-2 border-sentinel-border">
                <div className="absolute left-0 top-0 w-2 h-2 -ml-1 rounded-full bg-sentinel-accent" />
                <div className="text-[10px] font-mono text-sentinel-text-muted mb-1">{formatTimestamp(ioc.updated_at)}</div>
                <div className="text-xs font-mono text-sentinel-text-secondary">Last updated</div>
              </div>
              
              {ioc.enrichments && ioc.enrichments.length > 0 && ioc.enrichments.map((enrichment, idx) => (
                <div key={idx} className="relative pl-6 pb-4 border-l-2 border-sentinel-border">
                  <div className="absolute left-0 top-0 w-2 h-2 -ml-1 rounded-full bg-sentinel-accent-secondary" />
                  <div className="text-[10px] font-mono text-sentinel-text-muted mb-1">{formatTimestamp(enrichment.enriched_at)}</div>
                  <div className="text-xs font-mono text-sentinel-text-secondary">Enrichment from {enrichment.source}</div>
                </div>
              ))}

              <div className="relative pl-6 border-l-2 border-sentinel-border">
                <div className="absolute left-0 top-0 w-2 h-2 -ml-1 rounded-full bg-sentinel-success" />
                <div className="text-[10px] font-mono text-sentinel-text-muted mb-1">{formatTimestamp(ioc.created_at)}</div>
                <div className="text-xs font-mono text-sentinel-text-secondary">IOC added to database</div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'sources' && (
          <div className="sentinel-card overflow-hidden">
            <div className="px-5 py-3 border-b border-sentinel-border">
              <h3 className="text-sm font-display font-semibold text-sentinel-text-primary">Threat Feed Sources</h3>
            </div>
            {ioc.sources && ioc.sources.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-sentinel-border">
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Feed Name</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Slug</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Ingested At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ioc.sources.map((source, idx) => (
                      <tr key={idx} className="border-b border-sentinel-border/50">
                        <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">{source.feed_name}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-secondary">{source.feed_slug}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-muted">{formatTimestamp(source.ingested_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-8 text-center text-xs font-mono text-sentinel-text-muted">No source information available</div>
            )}
          </div>
        )}

        {activeTab === 'relationships' && (
          <div className="sentinel-card overflow-hidden">
            <div className="px-5 py-3 border-b border-sentinel-border">
              <h3 className="text-sm font-display font-semibold text-sentinel-text-primary">Related IOCs</h3>
            </div>
            {ioc.relationships && ioc.relationships.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-sentinel-border">
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Related IOC</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Type</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Relationship</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Threat Score</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Direction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ioc.relationships.map((rel, idx) => (
                      <tr key={idx} className="border-b border-sentinel-border/50 cursor-pointer hover:bg-sentinel-bg-hover" onClick={() => router.push(`/ioc-detail/${rel.id}`)}>
                        <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">{rel.value}</td>
                        <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted uppercase">{rel.type}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-secondary">{rel.relationship_type}</td>
                        <td className="px-4 py-2.5"><ScoreBadge score={rel.threat_score} size="sm" /></td>
                        <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted uppercase">{rel.direction}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-8 text-center text-xs font-mono text-sentinel-text-muted">No related IOCs found</div>
            )}
          </div>
        )}

        {activeTab === 'external-sources' && (
          <div className="space-y-3">
            <p className="text-[10px] font-mono text-sentinel-text-muted uppercase tracking-wider px-1">
              Open {ioc.value} in external intelligence platforms
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {getExternalLinks(ioc.type, ioc.value).map((link) => (
                <a
                  key={link.label}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="sentinel-card p-4 flex items-start justify-between gap-3 hover:border-sentinel-accent/40 transition-colors group"
                >
                  <div className="min-w-0">
                    <p className="text-xs font-mono font-semibold text-sentinel-text-primary group-hover:text-sentinel-accent transition-colors">
                      {link.label}
                    </p>
                    <p className="text-[10px] font-mono text-sentinel-text-muted mt-0.5 leading-relaxed">
                      {link.description}
                    </p>
                  </div>
                  <ExternalLink className="w-3.5 h-3.5 text-sentinel-text-muted group-hover:text-sentinel-accent transition-colors flex-shrink-0 mt-0.5" />
                </a>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
