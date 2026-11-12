'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Globe, Link, Hash, ExternalLink, Mail, ShieldAlert, Tag, Clock, Activity, Database, Sparkles } from 'lucide-react';
import { getIOC } from '@/lib/api';
import ScoreBadge from '@/components/ioc/ScoreBadge';
import { cn, enrichmentEntries, formatDate, formatEnrichmentField, formatTimestamp, getScoreCategory, getScoreColor } from '@/lib/utils';
import { VULN_ENRICHMENT_SOURCES, VulnerabilityEnrichmentPanel } from '@/components/ioc/VulnerabilityEnrichment';
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
        <div className="h-6 w-48 bg-wiestell-bg-tertiary rounded animate-pulse" />
        <div className="wiestell-card p-6 space-y-4 animate-pulse">
          <div className="h-8 w-96 bg-wiestell-bg-tertiary rounded" />
          <div className="h-4 w-64 bg-wiestell-bg-tertiary rounded" />
        </div>
      </div>
    );
  }

  if (error || !ioc) {
    return (
      <div className="wiestell-card p-8 text-center">
        <p className="text-wiestell-danger font-mono text-sm">{error || 'IOC not found'}</p>
        <button onClick={() => router.back()} className="mt-4 text-xs font-mono text-wiestell-accent hover:underline">
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
        className="flex items-center gap-2 text-xs font-mono text-wiestell-text-muted hover:text-wiestell-accent transition-colors"
      >
        <ArrowLeft className="w-3 h-3" /> Back
      </button>

      {/* IOC Header */}
      <div className="wiestell-card p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded bg-wiestell-bg-primary border border-wiestell-border">
              <Icon className="w-6 h-6" style={{ color: scoreColor }} />
            </div>
            <div>
              <p className="font-mono text-lg text-wiestell-text-primary break-all">{ioc.value}</p>
              <div className="flex items-center gap-3 mt-1 flex-wrap">
                <span className="text-[10px] font-mono uppercase tracking-wider text-wiestell-text-muted px-2 py-0.5 rounded bg-wiestell-bg-primary border border-wiestell-border">
                  {ioc.type}
                </span>
                <span className="text-[10px] font-mono text-wiestell-text-muted">
                  {ioc.sighting_count} sightings
                </span>
                <span className="text-[10px] font-mono text-wiestell-text-muted">
                  First: {formatDate(ioc.first_seen)}
                </span>
                <span className="text-[10px] font-mono text-wiestell-text-muted">
                  Last: {formatDate(ioc.last_seen)}
                </span>
              </div>
            </div>
          </div>
          <div className="text-center">
            <p className="text-3xl font-mono font-bold" style={{ color: scoreColor }}>{ioc.threat_score}</p>
            <p className="text-[10px] font-mono uppercase" style={{ color: scoreColor }}>{getScoreCategory(ioc.threat_score)}</p>
            <p className="text-[9px] font-mono text-wiestell-text-muted mt-1">Confidence: {ioc.confidence}%</p>
          </div>
        </div>

        {/* Tags */}
        {ioc.tags && ioc.tags.length > 0 && (
          <div className="flex items-center gap-2 mt-4 flex-wrap">
            <Tag className="w-3 h-3 text-wiestell-text-muted" />
            {ioc.tags.map((tag) => (
              <span key={tag} className="px-2 py-0.5 text-[10px] font-mono rounded bg-wiestell-accent/10 text-wiestell-accent border border-wiestell-accent/20">
                {tag}
              </span>
            ))}
          </div>
        )}

        {/* MITRE Techniques */}
        {ioc.mitre_techniques && ioc.mitre_techniques.length > 0 && (
          <div className="flex items-center gap-2 mt-3 flex-wrap">
            <ShieldAlert className="w-3 h-3 text-wiestell-text-muted" />
            <span className="text-[10px] font-mono text-wiestell-text-muted mr-1">MITRE ATT&CK:</span>
            {ioc.mitre_techniques.map((tech) => (
              <span key={tech} className="px-2 py-0.5 text-[10px] font-mono rounded bg-wiestell-accent-secondary/10 text-purple-400 border border-purple-500/20">
                {tech}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-wiestell-border overflow-x-auto">
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
                ? 'text-wiestell-accent border-wiestell-accent'
                : 'text-wiestell-text-muted border-transparent hover:text-wiestell-text-secondary'
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
            <div className="wiestell-card p-5">
              <h3 className="text-sm font-display font-semibold text-wiestell-text-primary mb-3">Statistics</h3>
              <div className="space-y-2">
                <div className="flex justify-between items-center py-1.5 border-b border-wiestell-border/50">
                  <span className="text-xs font-mono text-wiestell-text-muted">Threat Score</span>
                  <span className="text-xs font-mono font-semibold" style={{ color: scoreColor }}>{ioc.threat_score}/100</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-wiestell-border/50">
                  <span className="text-xs font-mono text-wiestell-text-muted">Confidence</span>
                  <span className="text-xs font-mono text-wiestell-text-secondary">{ioc.confidence}%</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-wiestell-border/50">
                  <span className="text-xs font-mono text-wiestell-text-muted">Sighting Count</span>
                  <span className="text-xs font-mono text-wiestell-text-secondary">{ioc.sighting_count}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-wiestell-border/50">
                  <span className="text-xs font-mono text-wiestell-text-muted">First Seen</span>
                  <span className="text-xs font-mono text-wiestell-text-secondary">{formatTimestamp(ioc.first_seen)}</span>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-xs font-mono text-wiestell-text-muted">Last Seen</span>
                  <span className="text-xs font-mono text-wiestell-text-secondary">{formatTimestamp(ioc.last_seen)}</span>
                </div>
              </div>
            </div>

            {/* Metadata */}
            <div className="wiestell-card p-5">
              <h3 className="text-sm font-display font-semibold text-wiestell-text-primary mb-3">Metadata</h3>
              <div className="space-y-2">
                <div className="flex justify-between items-center py-1.5 border-b border-wiestell-border/50">
                  <span className="text-xs font-mono text-wiestell-text-muted">Created</span>
                  <span className="text-xs font-mono text-wiestell-text-secondary">{formatTimestamp(ioc.created_at)}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-wiestell-border/50">
                  <span className="text-xs font-mono text-wiestell-text-muted">Updated</span>
                  <span className="text-xs font-mono text-wiestell-text-secondary">{formatTimestamp(ioc.updated_at)}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-wiestell-border/50">
                  <span className="text-xs font-mono text-wiestell-text-muted">Sources</span>
                  <span className="text-xs font-mono text-wiestell-text-secondary">{ioc.sources?.length || 0}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-wiestell-border/50">
                  <span className="text-xs font-mono text-wiestell-text-muted">Relationships</span>
                  <span className="text-xs font-mono text-wiestell-text-secondary">{ioc.relationships?.length || 0}</span>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-xs font-mono text-wiestell-text-muted">Enrichments</span>
                  <span className="text-xs font-mono text-wiestell-text-secondary">{ioc.enrichments?.length || 0}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'enrichment' && (
          <div className="space-y-6">
            {ioc.enrichments && ioc.enrichments.length > 0 ? (
              ioc.enrichments.map((e, i) => (
                <div key={i} className="wiestell-card overflow-hidden">
                  <div className="bg-wiestell-bg-secondary/50 px-4 py-2.5 border-b border-wiestell-border flex items-center justify-between">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-wiestell-text-primary">{e.source}</h3>
                    <span className="text-[10px] font-mono text-wiestell-text-muted">{formatTimestamp(e.enriched_at)}</span>
                  </div>
                  
                  {/* GeoIP Table */}
                  {e.source === 'geoip' && e.data && (
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-wiestell-border/50 bg-wiestell-bg-primary/30">
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Field</th>
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(e.data).map(([key, value]) => (
                          <tr key={key} className="border-b border-wiestell-border/30 hover:bg-wiestell-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-muted capitalize">{key.replace(/_/g, ' ')}</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary">{String(value || 'N/A')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

                  {/* WHOIS Table */}
                  {e.source === 'whois' && e.data && (
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-wiestell-border/50 bg-wiestell-bg-primary/30">
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Field</th>
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(e.data).map(([key, value]) => (
                          <tr key={key} className="border-b border-wiestell-border/30 hover:bg-wiestell-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-muted capitalize">{key.replace(/_/g, ' ')}</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary">
                              {Array.isArray(value) ? value.join(', ') : String(value || 'N/A')}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

                  {/* DNS Table */}
                  {e.source === 'dns' && e.data && (
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-wiestell-border/50 bg-wiestell-bg-primary/30">
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Record Type</th>
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Records</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(e.data).map(([recordType, records]) => (
                          Array.isArray(records) && records.length > 0 && (
                            <tr key={recordType} className="border-b border-wiestell-border/30 hover:bg-wiestell-bg-secondary/20">
                              <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-muted uppercase">{recordType}</td>
                              <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary">
                                {records.map((r, idx) => (
                                  <div key={idx}>{String(r)}</div>
                                ))}
                              </td>
                            </tr>
                          )
                        ))}
                      </tbody>
                    </table>
                  )}

                  {/* Reputation Table */}
                  {e.source === 'reputation' && e.data && (
                    <div>
                      <table className="w-full mb-4">
                        <thead>
                          <tr className="border-b border-wiestell-border/50 bg-wiestell-bg-primary/30">
                            <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Metric</th>
                            <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr className="border-b border-wiestell-border/30 hover:bg-wiestell-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-muted">Aggregate Score</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary font-semibold">{(e.data as any).aggregate_score || 0}</td>
                          </tr>
                          <tr className="border-b border-wiestell-border/30 hover:bg-wiestell-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-muted">Sources Checked</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary">{(e.data as any).sources_checked || 0}</td>
                          </tr>
                          <tr className="border-b border-wiestell-border/30 hover:bg-wiestell-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-muted">Sources Flagged</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary">{(e.data as any).sources_flagged || 0}</td>
                          </tr>
                          {(e.data as any).note && (
                            <tr className="hover:bg-wiestell-bg-secondary/20">
                              <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-muted">Note</td>
                              <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-secondary italic">{String((e.data as any).note)}</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                      
                      {/* Reputation Details */}
                      {(e.data as any).details && Object.keys((e.data as any).details).length > 0 && (
                        <div className="px-4 pb-4">
                          <h4 className="text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted mb-2">Source Details</h4>
                          <table className="w-full">
                            <thead>
                              <tr className="border-b border-wiestell-border/50">
                                <th className="px-3 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Source</th>
                                <th className="px-3 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Data</th>
                              </tr>
                            </thead>
                            <tbody>
                              {Object.entries((e.data as any).details).map(([source, data]) => (
                                <tr key={source} className="border-b border-wiestell-border/30 hover:bg-wiestell-bg-secondary/20">
                                  <td className="px-3 py-2 font-mono text-[10px] text-wiestell-text-muted">{source}</td>
                                  <td className="px-3 py-2 font-mono text-[10px] text-wiestell-text-secondary">
                                    {typeof data === 'object' ? JSON.stringify(data) : String(data)}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  )}

                  {/* MalwareBazaar Table */}
                  {e.source === 'malwarebazaar' && e.data && (
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-wiestell-border/50 bg-wiestell-bg-primary/30">
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Field</th>
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(e.data).map(([key, value]) => (
                          <tr key={key} className="border-b border-wiestell-border/30 hover:bg-wiestell-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-muted capitalize">{key.replace(/_/g, ' ')}</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary">
                              {Array.isArray(value) ? value.join(', ') : String(value || 'N/A')}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

                  {/* Vulnerability / malware sources get purpose-built panels */}
                  {VULN_ENRICHMENT_SOURCES.includes(e.source as typeof VULN_ENRICHMENT_SOURCES[number]) && e.data && (
                    <VulnerabilityEnrichmentPanel
                      source={e.source}
                      data={e.data as Record<string, unknown>}
                    />
                  )}

                  {/* Generic fallback for other sources */}
                  {!['geoip', 'whois', 'dns', 'reputation', 'malwarebazaar', ...VULN_ENRICHMENT_SOURCES].includes(e.source) && e.data && (
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-wiestell-border/50 bg-wiestell-bg-primary/30">
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Field</th>
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {enrichmentEntries(e.source, e.data as Record<string, unknown>).map(([key, value]) => (
                          <tr key={key} className="border-b border-wiestell-border/30 hover:bg-wiestell-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-muted capitalize">{formatEnrichmentField(e.source, key)}</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary">
                              {Array.isArray(value) ? (
                                value.length === 0 ? (
                                  <span className="text-wiestell-text-muted italic">Empty</span>
                                ) : (
                                  <div className="flex flex-wrap gap-1">
                                    {value.map((item, idx) => (
                                      <span key={idx} className="px-2 py-0.5 bg-wiestell-bg-secondary/50 border border-wiestell-border/30 rounded text-[10px]">
                                        {typeof item === 'object' && item !== null ? JSON.stringify(item) : String(item)}
                                      </span>
                                    ))}
                                  </div>
                                )
                              ) : typeof value === 'boolean' ? (
                                <span className={value ? 'text-red-400' : 'text-wiestell-text-muted'}>{value ? 'Yes' : 'No'}</span>
                              ) : typeof value === 'object' && value !== null ? (
                                <pre className="text-[10px] overflow-x-auto">{JSON.stringify(value, null, 2)}</pre>
                              ) : (
                                String(value ?? 'N/A')
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              ))
            ) : (
              <div className="wiestell-card p-8 text-center text-xs font-mono text-wiestell-text-muted">No enrichment data available</div>
            )}
          </div>
        )}

        {activeTab === 'history' && (
          <div className="wiestell-card p-5">
            <h3 className="text-sm font-display font-semibold text-wiestell-text-primary mb-4">IOC Timeline</h3>
            <div className="space-y-3">
              {/* Timeline entries */}
              <div className="relative pl-6 pb-4 border-l-2 border-wiestell-border">
                <div className="absolute left-0 top-0 w-2 h-2 -ml-1 rounded-full bg-wiestell-accent" />
                <div className="text-[10px] font-mono text-wiestell-text-muted mb-1">{formatTimestamp(ioc.updated_at)}</div>
                <div className="text-xs font-mono text-wiestell-text-secondary">Last updated</div>
              </div>
              
              {ioc.enrichments && ioc.enrichments.length > 0 && ioc.enrichments.map((enrichment, idx) => (
                <div key={idx} className="relative pl-6 pb-4 border-l-2 border-wiestell-border">
                  <div className="absolute left-0 top-0 w-2 h-2 -ml-1 rounded-full bg-wiestell-accent-secondary" />
                  <div className="text-[10px] font-mono text-wiestell-text-muted mb-1">{formatTimestamp(enrichment.enriched_at)}</div>
                  <div className="text-xs font-mono text-wiestell-text-secondary">Enrichment from {enrichment.source}</div>
                </div>
              ))}

              <div className="relative pl-6 border-l-2 border-wiestell-border">
                <div className="absolute left-0 top-0 w-2 h-2 -ml-1 rounded-full bg-wiestell-success" />
                <div className="text-[10px] font-mono text-wiestell-text-muted mb-1">{formatTimestamp(ioc.created_at)}</div>
                <div className="text-xs font-mono text-wiestell-text-secondary">IOC added to database</div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'sources' && (
          <div className="wiestell-card overflow-hidden">
            <div className="px-5 py-3 border-b border-wiestell-border">
              <h3 className="text-sm font-display font-semibold text-wiestell-text-primary">Threat Feed Sources</h3>
            </div>
            {ioc.sources && ioc.sources.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-wiestell-border">
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Feed Name</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Slug</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Ingested At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ioc.sources.map((source, idx) => (
                      <tr key={idx} className="border-b border-wiestell-border/50">
                        <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary">{source.feed_name}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-secondary">{source.feed_slug}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-muted">{formatTimestamp(source.ingested_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-8 text-center text-xs font-mono text-wiestell-text-muted">No source information available</div>
            )}
          </div>
        )}

        {activeTab === 'relationships' && (
          <div className="wiestell-card overflow-hidden">
            <div className="px-5 py-3 border-b border-wiestell-border">
              <h3 className="text-sm font-display font-semibold text-wiestell-text-primary">Related IOCs</h3>
            </div>
            {ioc.relationships && ioc.relationships.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-wiestell-border">
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Related IOC</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Type</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Relationship</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Threat Score</th>
                      <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-wiestell-text-muted">Direction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ioc.relationships.map((rel, idx) => (
                      <tr key={idx} className="border-b border-wiestell-border/50 cursor-pointer hover:bg-wiestell-bg-hover" onClick={() => router.push(`/ioc-detail/${rel.id}`)}>
                        <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary">{rel.value}</td>
                        <td className="px-4 py-2.5 font-mono text-[10px] text-wiestell-text-muted uppercase">{rel.type}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-secondary">{rel.relationship_type}</td>
                        <td className="px-4 py-2.5"><ScoreBadge score={rel.threat_score} size="sm" /></td>
                        <td className="px-4 py-2.5 font-mono text-[10px] text-wiestell-text-muted uppercase">{rel.direction}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-8 text-center text-xs font-mono text-wiestell-text-muted">No related IOCs found</div>
            )}
          </div>
        )}

        {activeTab === 'external-sources' && (
          <div className="space-y-3">
            <p className="text-[10px] font-mono text-wiestell-text-muted uppercase tracking-wider px-1">
              Open {ioc.value} in external intelligence platforms
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {getExternalLinks(ioc.type, ioc.value).map((link) => (
                <a
                  key={link.label}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="wiestell-card p-4 flex items-start justify-between gap-3 hover:border-wiestell-accent/40 transition-colors group"
                >
                  <div className="min-w-0">
                    <p className="text-xs font-mono font-semibold text-wiestell-text-primary group-hover:text-wiestell-accent transition-colors">
                      {link.label}
                    </p>
                    <p className="text-[10px] font-mono text-wiestell-text-muted mt-0.5 leading-relaxed">
                      {link.description}
                    </p>
                  </div>
                  <ExternalLink className="w-3.5 h-3.5 text-wiestell-text-muted group-hover:text-wiestell-accent transition-colors flex-shrink-0 mt-0.5" />
                </a>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
