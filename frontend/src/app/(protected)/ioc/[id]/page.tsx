'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, RefreshCw, Download, Globe, Link, Hash, ExternalLink, Mail, ShieldAlert, Tag, Sparkles, Loader2, Search } from 'lucide-react';
import { getIOC, triggerEnrichment, analyzeIOCWithAI } from '@/lib/api';
import ScoreBadge from '@/components/ioc/ScoreBadge';
import { cn, enrichmentEntries, formatDate, formatEnrichmentField, formatTimestamp, getScoreCategory, getScoreColor } from '@/lib/utils';
import { VULN_ENRICHMENT_SOURCES, VulnerabilityEnrichmentPanel } from '@/components/ioc/VulnerabilityEnrichment';
import type { IOCDetail, AIAnalysis } from '@/lib/types';

interface ExternalLink {
  label: string;
  url: string;
  description: string;
}

function getExternalLinks(type: string, value: string): ExternalLink[] {
  const encoded = encodeURIComponent(value);
  const vtBase = 'https://www.virustotal.com/gui';

  const vtUrl =
    type === 'ip' ? `${vtBase}/ip-address/${value}` :
    type === 'domain' ? `${vtBase}/domain/${value}` :
    type === 'hash' ? `${vtBase}/file/${value}` :
    `${vtBase}/search/${encoded}`;

  const links: ExternalLink[] = [
    { label: 'VirusTotal', url: vtUrl, description: 'Multi-engine threat intelligence scan' },
  ];

  if (type === 'ip') {
    links.push(
      { label: 'Shodan', url: `https://www.shodan.io/host/${value}`, description: 'Internet-facing device & service scan' },
      { label: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${value}`, description: 'Community IP abuse reports' },
    );
  } else if (type === 'domain') {
    links.push(
      { label: 'Shodan', url: `https://www.shodan.io/search?query=hostname:${encoded}`, description: 'Hostname infrastructure lookup' },
      { label: 'URLScan.io', url: `https://urlscan.io/search/#domain:${value}`, description: 'Domain scan history' },
    );
  } else if (type === 'hash') {
    links.push(
      { label: 'MalwareBazaar', url: `https://bazaar.abuse.ch/sample/${value}/`, description: 'Malware sample repository' },
    );
  } else if (type === 'url') {
    links.push(
      { label: 'URLScan.io', url: `https://urlscan.io/search/#page.url:${encoded}`, description: 'URL scan & screenshot history' },
      { label: 'URLhaus', url: `https://urlhaus.abuse.ch/browse.php?search=${encoded}`, description: 'Malware distribution URL tracker' },
    );
  } else if (type === 'cve') {
    links.push(
      { label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${value}`, description: 'NIST National Vulnerability Database' },
    );
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
  const [ioc, setIOC] = useState<IOCDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [enriching, setEnriching] = useState(false);
  const [activeTab, setActiveTab] = useState('enrichment');
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const data = await getIOC(params.id as string);
        setIOC(data);
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load IOC');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [params.id]);

  const handleEnrich = async () => {
    if (!ioc) return;
    setEnriching(true);
    try {
      await triggerEnrichment(ioc.id);
      const data = await getIOC(ioc.id);
      setIOC(data);
    } catch {
      // ignore
    } finally {
      setEnriching(false);
    }
  };

  const handleAIAnalyze = async () => {
    if (!ioc) return;
    setAiLoading(true);
    setAiError(null);
    try {
      const result = await analyzeIOCWithAI(ioc.id);
      setAiAnalysis(result);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : 'AI analysis failed');
    } finally {
      setAiLoading(false);
    }
  };

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
        <ArrowLeft className="w-3 h-3" /> Back to search
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
              <div className="flex items-center gap-3 mt-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-sentinel-text-muted px-2 py-0.5 rounded bg-sentinel-bg-primary border border-sentinel-border">
                  {ioc.type}
                </span>
                <span className="text-[10px] font-mono text-sentinel-text-muted">
                  {ioc.sighting_count} sightings
                </span>
                <span className="text-[10px] font-mono text-sentinel-text-muted">
                  First: {formatDate(ioc.first_seen)}
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-center">
              <p className="text-3xl font-mono font-bold" style={{ color: scoreColor }}>{ioc.threat_score}</p>
              <p className="text-[10px] font-mono uppercase" style={{ color: scoreColor }}>{getScoreCategory(ioc.threat_score)}</p>
            </div>
            <button
              onClick={handleEnrich}
              disabled={enriching}
              className="px-3 py-2 rounded border border-sentinel-border text-xs font-mono text-sentinel-text-secondary hover:text-sentinel-accent hover:border-sentinel-accent/30 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={cn('w-3 h-3', enriching && 'animate-spin')} />
            </button>
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
            {ioc.mitre_techniques.map((tech) => (
              <span key={tech} className="px-2 py-0.5 text-[10px] font-mono rounded bg-gray-200 text-gray-700 border border-gray-300">
                {tech}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-sentinel-border">
        {['enrichment', 'sources', 'relationships', 'raw', 'ai-analysis', 'external-sources'].map((tab) => (
          <button
            key={tab}
            onClick={() => {
              setActiveTab(tab);
              if (tab === 'ai-analysis' && !aiAnalysis && !aiLoading) handleAIAnalyze();
            }}
            className={cn(
              'px-4 py-2 text-xs font-mono uppercase tracking-wider transition-colors border-b-2 -mb-px flex items-center gap-1.5',
              activeTab === tab
                ? 'text-sentinel-accent border-sentinel-accent'
                : 'text-sentinel-text-muted border-transparent hover:text-sentinel-text-secondary'
            )}
          >
            {tab === 'ai-analysis' && <Sparkles className="w-3 h-3" />}
            {tab === 'external-sources' && <Search className="w-3 h-3" />}
            {tab === 'ai-analysis' ? 'AI Analysis' : tab === 'external-sources' ? 'External Sources' : tab}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="animate-fade-in">
        {activeTab === 'enrichment' && (
          <div className="space-y-6">
            {ioc.enrichments.length === 0 ? (
              <div className="sentinel-card p-8 text-center">
                <p className="text-sentinel-text-muted text-sm font-mono">No enrichment data available</p>
                <button onClick={handleEnrich} className="mt-3 text-xs font-mono text-sentinel-accent hover:underline">
                  Trigger enrichment
                </button>
              </div>
            ) : (
              ioc.enrichments.map((e, i) => (
                <div key={i} className="sentinel-card overflow-hidden">
                  <div className="bg-sentinel-bg-secondary/50 px-4 py-2.5 border-b border-sentinel-border flex items-center justify-between">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-sentinel-text-primary">{e.source}</h3>
                    <span className="text-[10px] font-mono text-sentinel-text-muted">{formatTimestamp(e.enriched_at)}</span>
                  </div>
                  
                  {/* GeoIP Table */}
                  {e.source === 'geoip' && e.data && (
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-sentinel-border/50 bg-sentinel-bg-primary/30">
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Field</th>
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(e.data).map(([key, value]) => (
                          <tr key={key} className="border-b border-sentinel-border/30 hover:bg-sentinel-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-muted capitalize">{key.replace(/_/g, ' ')}</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">
                              {Array.isArray(value) ? (
                                value.length === 0 ? (
                                  <span className="text-sentinel-text-muted italic">Empty</span>
                                ) : (
                                  <div className="flex flex-wrap gap-1">
                                    {value.map((item, idx) => (
                                      <span key={idx} className="px-2 py-0.5 bg-sentinel-bg-secondary/50 border border-sentinel-border/30 rounded text-[10px]">
                                        {String(item)}
                                      </span>
                                    ))}
                                  </div>
                                )
                              ) : (
                                String(value || 'N/A')
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}

                  {/* WHOIS Table */}
                  {e.source === 'whois' && e.data && (
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-sentinel-border/50 bg-sentinel-bg-primary/30">
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Field</th>
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(e.data).map(([key, value]) => (
                          <tr key={key} className="border-b border-sentinel-border/30 hover:bg-sentinel-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-muted capitalize">{key.replace(/_/g, ' ')}</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">
                              {Array.isArray(value) ? (
                                value.length === 0 ? (
                                  <span className="text-sentinel-text-muted italic">Empty</span>
                                ) : (
                                  <div className="flex flex-wrap gap-1">
                                    {value.map((item, idx) => (
                                      <span key={idx} className="px-2 py-0.5 bg-sentinel-bg-secondary/50 border border-sentinel-border/30 rounded text-[10px]">
                                        {String(item)}
                                      </span>
                                    ))}
                                  </div>
                                )
                              ) : (
                                String(value || 'N/A')
                              )}
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
                        <tr className="border-b border-sentinel-border/50 bg-sentinel-bg-primary/30">
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Record Type</th>
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Records</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(e.data).map(([recordType, records]) => 
                          Array.isArray(records) && records.length > 0 ? (
                            <tr key={recordType} className="border-b border-sentinel-border/30 hover:bg-sentinel-bg-secondary/20">
                              <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-muted uppercase">{recordType}</td>
                              <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">
                                {records.map((r, idx) => (
                                  <div key={idx}>{String(r)}</div>
                                ))}
                              </td>
                            </tr>
                          ) : null
                        )}
                      </tbody>
                    </table>
                  )}

                  {/* Reputation Table */}
                  {e.source === 'reputation' && e.data && (
                    <div>
                      <table className="w-full mb-4">
                        <thead>
                          <tr className="border-b border-sentinel-border/50 bg-sentinel-bg-primary/30">
                            <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Metric</th>
                            <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr className="border-b border-sentinel-border/30 hover:bg-sentinel-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-muted">Aggregate Score</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary font-semibold">{String((e.data.aggregate_score as number) ?? 0)}</td>
                          </tr>
                          <tr className="border-b border-sentinel-border/30 hover:bg-sentinel-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-muted">Sources Checked</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">{String((e.data.sources_checked as number) ?? 0)}</td>
                          </tr>
                          <tr className="border-b border-sentinel-border/30 hover:bg-sentinel-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-muted">Sources Flagged</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">{String((e.data.sources_flagged as number) ?? 0)}</td>
                          </tr>
                          {e.data.note ? (
                            <tr className="hover:bg-sentinel-bg-secondary/20">
                              <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-muted">Note</td>
                              <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-secondary italic">{String(e.data.note)}</td>
                            </tr>
                          ) : null}
                        </tbody>
                      </table>
                      
                      {/* Reputation Details */}
                      {e.data.details && typeof e.data.details === 'object' && Object.keys(e.data.details as Record<string, unknown>).length > 0 ? (
                        <div className="px-4 pb-4">
                          <h4 className="text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted mb-2">Source Details</h4>
                          {Object.entries(e.data.details as Record<string, unknown>).map(([source, data]) => (
                            <div key={source} className="mb-4 last:mb-0">
                              <div className="text-[10px] font-mono font-semibold uppercase text-sentinel-accent mb-1">{source}</div>
                              <table className="w-full border border-sentinel-border/30 rounded">
                                <tbody>
                                  {typeof data === 'object' && data !== null ? (
                                    Object.entries(data as Record<string, unknown>).map(([key, value]) => (
                                      <tr key={key} className="border-b border-sentinel-border/20 last:border-0 hover:bg-sentinel-bg-secondary/10">
                                        <td className="px-3 py-2 font-mono text-[10px] text-sentinel-text-muted w-1/3 capitalize">
                                          {key.replace(/_/g, ' ')}
                                        </td>
                                        <td className="px-3 py-2 font-mono text-[10px] text-sentinel-text-primary">
                                          {typeof value === 'object' && value !== null
                                            ? JSON.stringify(value)
                                            : value === null || value === undefined
                                            ? 'N/A'
                                            : String(value)}
                                        </td>
                                      </tr>
                                    ))
                                  ) : (
                                    <tr>
                                      <td className="px-3 py-2 font-mono text-[10px] text-sentinel-text-secondary" colSpan={2}>
                                        {String(data)}
                                      </td>
                                    </tr>
                                  )}
                                </tbody>
                              </table>
                            </div>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  )}

                  {/* MalwareBazaar Table */}
                  {e.source === 'malwarebazaar' && e.data && (
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-sentinel-border/50 bg-sentinel-bg-primary/30">
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Field</th>
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(e.data).map(([key, value]) => (
                          <tr key={key} className="border-b border-sentinel-border/30 hover:bg-sentinel-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-muted capitalize">{key.replace(/_/g, ' ')}</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">
                              {Array.isArray(value) ? (
                                value.length === 0 ? (
                                  <span className="text-sentinel-text-muted italic">Empty</span>
                                ) : (
                                  <div className="flex flex-wrap gap-1">
                                    {value.map((item, idx) => (
                                      <span key={idx} className="px-2 py-0.5 bg-sentinel-bg-secondary/50 border border-sentinel-border/30 rounded text-[10px]">
                                        {String(item)}
                                      </span>
                                    ))}
                                  </div>
                                )
                              ) : (
                                String(value || 'N/A')
                              )}
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
                        <tr className="border-b border-sentinel-border/50 bg-sentinel-bg-primary/30">
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Field</th>
                          <th className="px-4 py-2 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {enrichmentEntries(e.source, e.data as Record<string, unknown>).map(([key, value]) => (
                          <tr key={key} className="border-b border-sentinel-border/30 hover:bg-sentinel-bg-secondary/20">
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-muted capitalize">{formatEnrichmentField(e.source, key)}</td>
                            <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">
                              {Array.isArray(value) ? (
                                value.length === 0 ? (
                                  <span className="text-sentinel-text-muted italic">Empty</span>
                                ) : (
                                  <div className="flex flex-wrap gap-1">
                                    {value.map((item, idx) => (
                                      <span key={idx} className="px-2 py-0.5 bg-sentinel-bg-secondary/50 border border-sentinel-border/30 rounded text-[10px]">
                                        {typeof item === 'object' && item !== null ? JSON.stringify(item) : String(item)}
                                      </span>
                                    ))}
                                  </div>
                                )
                              ) : typeof value === 'object' && value !== null ? (
                                <pre className="text-[10px] overflow-x-auto">{JSON.stringify(value, null, 2)}</pre>
                              ) : typeof value === 'boolean' ? (
                                <span className={value ? 'text-red-400' : 'text-sentinel-text-muted'}>{value ? 'Yes' : 'No'}</span>
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
            )}
          </div>
        )}

        {activeTab === 'sources' && (
          <div className="sentinel-card overflow-hidden">
            {ioc.sources.length === 0 ? (
              <div className="p-8 text-center text-sentinel-text-muted text-sm font-mono">No source information available</div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-sentinel-border">
                    <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Feed</th>
                    <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Ingested</th>
                  </tr>
                </thead>
                <tbody>
                  {ioc.sources.map((s, i) => (
                    <tr key={i} className="border-b border-sentinel-border/50">
                      <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">{s.feed_name}</td>
                      <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted">{formatTimestamp(s.ingested_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeTab === 'relationships' && (
          <div className="sentinel-card overflow-hidden">
            {ioc.relationships.length === 0 ? (
              <div className="p-8 text-center text-sentinel-text-muted text-sm font-mono">No relationships discovered yet</div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-sentinel-border">
                    <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Related IOC</th>
                    <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Type</th>
                    <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Relationship</th>
                    <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase text-sentinel-text-muted">Score</th>
                  </tr>
                </thead>
                <tbody>
                  {ioc.relationships.map((r, i) => (
                    <tr
                      key={i}
                      className="border-b border-sentinel-border/50 cursor-pointer hover:bg-sentinel-bg-hover transition-colors"
                      onClick={() => router.push(`/ioc/${r.id}`)}
                    >
                      <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary">{r.value}</td>
                      <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted uppercase">{r.type}</td>
                      <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-accent">{r.relationship_type}</td>
                      <td className="px-4 py-2.5"><ScoreBadge score={r.threat_score} size="sm" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeTab === 'raw' && (
          <div className="sentinel-card p-5">
            <pre className="text-[11px] font-mono text-sentinel-text-secondary bg-sentinel-bg-primary rounded p-4 overflow-x-auto max-h-[500px]">
              {JSON.stringify(ioc, null, 2)}
            </pre>
          </div>
        )}

        {activeTab === 'ai-analysis' && (
          <div className="space-y-4">
            {aiLoading ? (
              <div className="sentinel-card p-8 text-center">
                <Loader2 className="w-6 h-6 text-sentinel-accent animate-spin mx-auto mb-3" />
                <p className="text-sm font-mono text-sentinel-text-muted">Generating AI analysis...</p>
                <p className="text-[10px] font-mono text-sentinel-text-muted mt-1">This may take a few seconds</p>
              </div>
            ) : aiError ? (
              <div className="sentinel-card p-8 text-center">
                <p className="text-sentinel-danger text-sm font-mono">{aiError}</p>
                <button onClick={handleAIAnalyze} className="mt-3 text-xs font-mono text-sentinel-accent hover:underline">
                  Retry analysis
                </button>
              </div>
            ) : aiAnalysis ? (
              <>
                {/* Summary & Risk */}
                <div className="sentinel-card p-5">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted flex items-center gap-1.5">
                      <Sparkles className="w-3 h-3 text-sentinel-accent" />
                      AI Summary
                    </h3>
                    <div className="flex items-center gap-2">
                      <span className={cn(
                        'px-2 py-0.5 text-[10px] font-mono font-semibold uppercase rounded',
                        aiAnalysis.risk_level === 'critical' && 'bg-gray-300 text-gray-600 border border-gray-400',
                        aiAnalysis.risk_level === 'high' && 'bg-gray-300 text-gray-700 border border-gray-400',
                        aiAnalysis.risk_level === 'medium' && 'bg-gray-200 text-gray-800 border border-gray-300',
                        aiAnalysis.risk_level === 'low' && 'bg-gray-100 text-gray-900 border border-gray-200',
                      )}>
                        {aiAnalysis.risk_level} risk
                      </span>
                      <button
                        onClick={handleAIAnalyze}
                        className="text-[10px] font-mono text-sentinel-accent hover:underline"
                      >
                        Re-analyze
                      </button>
                    </div>
                  </div>
                  <p className="text-xs font-mono text-sentinel-text-primary leading-relaxed">{aiAnalysis.summary}</p>
                </div>

                {/* Detailed Analysis */}
                <div className="sentinel-card p-5">
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted mb-3">
                    Detailed Analysis
                  </h3>
                  <div className="text-xs font-mono text-sentinel-text-secondary leading-relaxed whitespace-pre-wrap">
                    {aiAnalysis.analysis}
                  </div>
                </div>

                {/* Recommendations */}
                {aiAnalysis.recommendations.length > 0 && (
                  <div className="sentinel-card p-5">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted mb-3">
                      Recommendations
                    </h3>
                    <ul className="space-y-2">
                      {aiAnalysis.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start gap-2 text-xs font-mono text-sentinel-text-secondary">
                          <span className="text-sentinel-accent mt-0.5 flex-shrink-0">{'>'}</span>
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            ) : (
              <div className="sentinel-card p-8 text-center">
                <Sparkles className="w-6 h-6 text-sentinel-text-muted mx-auto mb-3" />
                <p className="text-sm font-mono text-sentinel-text-muted">No AI analysis yet</p>
                <button onClick={handleAIAnalyze} className="mt-3 text-xs font-mono text-sentinel-accent hover:underline">
                  Generate AI analysis
                </button>
              </div>
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
