'use client';

import { useState, useEffect, useCallback } from 'react';
import { Grid3X3, RefreshCw, ExternalLink, Target, Shield, Zap, Eye, ChevronRight } from 'lucide-react';
import { getAttackHeatmap, getAttackTechnique } from '@/lib/api';
import { cn } from '@/lib/utils';
import type { HeatmapEntry } from '@/lib/types';

const TACTICS_ORDER = [
  { id: 'Reconnaissance', short: 'RECON', icon: Eye },
  { id: 'Resource Development', short: 'RES DEV', icon: Shield },
  { id: 'Initial Access', short: 'INIT ACC', icon: Zap },
  { id: 'Execution', short: 'EXEC', icon: Zap },
  { id: 'Persistence', short: 'PERSIST', icon: Shield },
  { id: 'Privilege Escalation', short: 'PRIV ESC', icon: ChevronRight },
  { id: 'Defense Evasion', short: 'DEF EVA', icon: Shield },
  { id: 'Credential Access', short: 'CRED ACC', icon: Target },
  { id: 'Discovery', short: 'DISCOV', icon: Eye },
  { id: 'Lateral Movement', short: 'LAT MOV', icon: ChevronRight },
  { id: 'Collection', short: 'COLLECT', icon: Target },
  { id: 'Command and Control', short: 'C2', icon: Zap },
  { id: 'Exfiltration', short: 'EXFIL', icon: ChevronRight },
  { id: 'Impact', short: 'IMPACT', icon: Target },
];

function getHeatColor(intensity: number): string {
  if (intensity <= 0) return 'rgba(30, 41, 59, 0.5)';
  if (intensity < 0.15) return 'rgba(16, 185, 129, 0.25)';
  if (intensity < 0.3) return 'rgba(16, 185, 129, 0.45)';
  if (intensity < 0.5) return 'rgba(245, 158, 11, 0.35)';
  if (intensity < 0.7) return 'rgba(245, 158, 11, 0.55)';
  if (intensity < 0.85) return 'rgba(239, 68, 68, 0.4)';
  return 'rgba(239, 68, 68, 0.6)';
}

function getHeatBorder(intensity: number): string {
  if (intensity <= 0) return 'border-sentinel-border/30';
  if (intensity < 0.3) return 'border-emerald-500/30';
  if (intensity < 0.5) return 'border-yellow-500/30';
  if (intensity < 0.7) return 'border-amber-500/30';
  return 'border-red-500/40';
}

function getTextColor(intensity: number): string {
  if (intensity <= 0) return 'text-sentinel-text-muted/50';
  if (intensity < 0.3) return 'text-emerald-400';
  if (intensity < 0.5) return 'text-yellow-400';
  if (intensity < 0.7) return 'text-amber-400';
  return 'text-red-400';
}

interface TechniqueDetail {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url: string | null;
  data_sources: string[];
  associated_iocs: { id: string; type: string; value: string; threat_score: number; tags: string[] }[];
}

export default function AttackMapPage() {
  const [heatmap, setHeatmap] = useState<HeatmapEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTech, setSelectedTech] = useState<HeatmapEntry | null>(null);
  const [techDetail, setTechDetail] = useState<TechniqueDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [minScore, setMinScore] = useState(0);

  const loadHeatmap = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getAttackHeatmap(minScore);
      setHeatmap(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [minScore]);

  useEffect(() => { loadHeatmap(); }, [loadHeatmap]);

  async function handleSelectTech(tech: HeatmapEntry) {
    setSelectedTech(tech);
    if (tech.ioc_count > 0) {
      setDetailLoading(true);
      try {
        const d = await getAttackTechnique(tech.technique_id) as TechniqueDetail;
        setTechDetail(d);
      } catch {
        setTechDetail(null);
      } finally {
        setDetailLoading(false);
      }
    } else {
      setTechDetail(null);
    }
  }

  const groupedByTactic: Record<string, HeatmapEntry[]> = {};
  TACTICS_ORDER.forEach(t => { groupedByTactic[t.id] = []; });
  heatmap.forEach(entry => {
    if (groupedByTactic[entry.tactic]) {
      groupedByTactic[entry.tactic].push(entry);
    }
  });

  // Stats
  const totalTechniques = heatmap.length;
  const activeTechniques = heatmap.filter(h => h.ioc_count > 0).length;
  const totalMappedIOCs = heatmap.reduce((s, h) => s + h.ioc_count, 0);
  const activeTactics = TACTICS_ORDER.filter(t => (groupedByTactic[t.id] || []).some(e => e.ioc_count > 0)).length;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-display font-bold text-sentinel-text-primary">MITRE ATT&CK Map</h1>
          <p className="text-xs font-mono text-sentinel-text-muted mt-0.5">
            Enterprise technique heatmap &mdash; {activeTechniques} active across {activeTactics} tactics
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="text-[10px] font-mono text-sentinel-text-muted">MIN SCORE</label>
            <input
              type="range"
              min={0}
              max={100}
              value={minScore}
              onChange={(e) => setMinScore(Number(e.target.value))}
              className="w-20 h-1 accent-sentinel-accent"
            />
            <span className="text-[10px] font-mono text-sentinel-accent w-6 text-right">{minScore}</span>
          </div>
          <button
            onClick={loadHeatmap}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-mono rounded border border-sentinel-border text-sentinel-text-secondary hover:text-sentinel-accent hover:border-sentinel-accent/30 transition-colors"
          >
            <RefreshCw className="w-3 h-3" />
            REFRESH
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'TOTAL TECHNIQUES', value: totalTechniques, color: 'text-sentinel-text-primary' },
          { label: 'ACTIVE TECHNIQUES', value: activeTechniques, color: 'text-sentinel-accent' },
          { label: 'MAPPED IOC LINKS', value: totalMappedIOCs, color: 'text-amber-400' },
          { label: 'ACTIVE TACTICS', value: `${activeTactics} / ${TACTICS_ORDER.length}`, color: 'text-emerald-400' },
        ].map((stat) => (
          <div key={stat.label} className="sentinel-card px-4 py-3">
            <p className="text-[10px] font-mono text-sentinel-text-muted uppercase tracking-wider">{stat.label}</p>
            <p className={cn('text-xl font-mono font-bold mt-0.5', stat.color)}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Kill Chain Flow */}
      <div className="sentinel-card p-3 overflow-x-auto">
        <div className="flex items-center gap-0.5 min-w-max">
          {TACTICS_ORDER.map((tactic, i) => {
            const techs = groupedByTactic[tactic.id] || [];
            const activeCount = techs.filter(t => t.ioc_count > 0).length;
            const isActive = activeCount > 0;
            return (
              <div key={tactic.id} className="flex items-center">
                <button
                  onClick={() => {
                    const el = document.getElementById(`tactic-${i}`);
                    el?.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
                  }}
                  className={cn(
                    'px-3 py-2 rounded text-center transition-all min-w-[80px]',
                    isActive
                      ? 'bg-sentinel-accent/10 border border-sentinel-accent/20 hover:bg-sentinel-accent/15'
                      : 'bg-sentinel-bg-tertiary/50 border border-sentinel-border/30 opacity-50 hover:opacity-75'
                  )}
                >
                  <p className={cn(
                    'text-[9px] font-mono font-bold tracking-wider',
                    isActive ? 'text-sentinel-accent' : 'text-sentinel-text-muted'
                  )}>
                    {tactic.short}
                  </p>
                  {isActive && (
                    <p className="text-[10px] font-mono text-sentinel-accent mt-0.5">{activeCount}</p>
                  )}
                </button>
                {i < TACTICS_ORDER.length - 1 && (
                  <div className={cn(
                    'w-4 h-px mx-0.5',
                    isActive ? 'bg-sentinel-accent/30' : 'bg-sentinel-border/30'
                  )} />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Matrix Grid */}
      {loading ? (
        <div className="sentinel-card p-10 text-center animate-pulse">
          <Grid3X3 className="w-10 h-10 text-sentinel-text-muted mx-auto mb-3" />
          <p className="text-sentinel-text-muted text-sm font-mono">Loading ATT&CK matrix...</p>
        </div>
      ) : heatmap.length === 0 ? (
        <div className="sentinel-card p-12 text-center">
          <Grid3X3 className="w-10 h-10 text-sentinel-text-muted mx-auto mb-3" />
          <p className="text-sentinel-text-muted text-sm font-mono">No ATT&CK data loaded</p>
          <p className="text-sentinel-text-muted text-xs font-mono mt-1">
            Run the MITRE seed script: python scripts/seed_mitre.py
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto pb-2">
          <div className="inline-flex gap-2 min-w-full">
            {TACTICS_ORDER.map((tactic, tacticIdx) => {
              const techniques = groupedByTactic[tactic.id] || [];
              const hasActive = techniques.some(t => t.ioc_count > 0);

              return (
                <div key={tactic.id} id={`tactic-${tacticIdx}`} className="flex-shrink-0 w-44">
                  <div className={cn(
                    'rounded-lg overflow-hidden border transition-all',
                    hasActive
                      ? 'border-sentinel-accent/15 bg-sentinel-bg-secondary'
                      : 'border-sentinel-border/30 bg-sentinel-bg-secondary/50 opacity-60'
                  )}>
                    {/* Tactic Header */}
                    <div className={cn(
                      'px-3 py-2.5 border-b',
                      hasActive
                        ? 'bg-sentinel-accent/5 border-sentinel-accent/15'
                        : 'bg-sentinel-bg-tertiary/50 border-sentinel-border/30'
                    )}>
                      <div className="flex items-center justify-between">
                        <h3 className={cn(
                          'text-[9px] font-mono font-bold uppercase tracking-wider',
                          hasActive ? 'text-sentinel-accent' : 'text-sentinel-text-muted'
                        )}>
                          {tactic.short}
                        </h3>
                        <span className="text-[9px] font-mono text-sentinel-text-muted">
                          {techniques.filter(t => t.ioc_count > 0).length}/{techniques.length}
                        </span>
                      </div>
                      <p className="text-[8px] font-mono text-sentinel-text-muted mt-0.5 truncate">{tactic.id}</p>
                    </div>

                    {/* Techniques */}
                    <div className="p-1.5 space-y-1 max-h-[420px] overflow-y-auto">
                      {techniques.length === 0 ? (
                        <p className="text-[8px] font-mono text-sentinel-text-muted text-center py-3">No data</p>
                      ) : (
                        techniques
                          .sort((a, b) => b.ioc_count - a.ioc_count)
                          .map((tech) => {
                            const isSelected = selectedTech?.technique_id === tech.technique_id;
                            return (
                              <button
                                key={tech.technique_id}
                                onClick={() => handleSelectTech(tech)}
                                className={cn(
                                  'w-full text-left px-2.5 py-2 rounded-md border transition-all',
                                  isSelected
                                    ? 'border-sentinel-accent/50 ring-1 ring-sentinel-accent/20 scale-[1.02]'
                                    : getHeatBorder(tech.intensity),
                                  tech.ioc_count === 0 && !isSelected && 'opacity-40 hover:opacity-70'
                                )}
                                style={{
                                  backgroundColor: isSelected
                                    ? 'rgba(0, 229, 255, 0.12)'
                                    : getHeatColor(tech.intensity),
                                }}
                              >
                                <div className="flex justify-between items-center gap-1">
                                  <span className={cn(
                                    'text-[10px] font-mono font-semibold',
                                    isSelected ? 'text-sentinel-accent' : tech.ioc_count > 0 ? 'text-sentinel-text-primary' : 'text-sentinel-text-muted'
                                  )}>
                                    {tech.technique_id}
                                  </span>
                                  {tech.ioc_count > 0 && (
                                    <span className={cn(
                                      'text-[10px] font-mono font-bold px-1.5 py-0.5 rounded',
                                      getTextColor(tech.intensity),
                                    )}
                                    style={{ backgroundColor: getHeatColor(tech.intensity) }}
                                    >
                                      {tech.ioc_count}
                                    </span>
                                  )}
                                </div>
                                <p className={cn(
                                  'text-[8px] font-mono mt-0.5 truncate',
                                  isSelected ? 'text-sentinel-accent/70' : 'text-sentinel-text-muted'
                                )}>
                                  {tech.technique_name}
                                </p>
                              </button>
                            );
                          })
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Intensity Legend */}
      <div className="sentinel-card p-4">
        <div className="flex items-center gap-6">
          <span className="text-[10px] font-mono font-semibold text-sentinel-text-muted uppercase tracking-wider flex-shrink-0">Intensity</span>
          <div className="flex items-center gap-3 flex-1">
            {[
              { label: 'None', color: 'rgba(30, 41, 59, 0.5)', border: 'border-sentinel-border/30', text: 'text-sentinel-text-muted', desc: '0 IOCs' },
              { label: 'Low', color: 'rgba(16, 185, 129, 0.35)', border: 'border-emerald-500/30', text: 'text-emerald-400', desc: '1–3 IOCs' },
              { label: 'Medium', color: 'rgba(245, 158, 11, 0.45)', border: 'border-amber-500/30', text: 'text-amber-400', desc: '4–8 IOCs' },
              { label: 'High', color: 'rgba(239, 68, 68, 0.5)', border: 'border-red-500/40', text: 'text-red-400', desc: '9+ IOCs' },
            ].map((l) => (
              <div key={l.label} className="flex items-center gap-2">
                <div
                  className={cn('w-8 h-6 rounded border', l.border)}
                  style={{ backgroundColor: l.color }}
                />
                <div>
                  <span className={cn('text-[10px] font-mono font-semibold block', l.text)}>{l.label}</span>
                  <span className="text-[8px] font-mono text-sentinel-text-muted">{l.desc}</span>
                </div>
              </div>
            ))}
          </div>
          {/* Gradient bar */}
          <div className="flex-shrink-0 hidden md:flex items-center gap-2">
            <div className="flex h-3 w-40 rounded overflow-hidden">
              <div className="flex-1" style={{ backgroundColor: 'rgba(30, 41, 59, 0.5)' }} />
              <div className="flex-1" style={{ backgroundColor: 'rgba(16, 185, 129, 0.25)' }} />
              <div className="flex-1" style={{ backgroundColor: 'rgba(16, 185, 129, 0.45)' }} />
              <div className="flex-1" style={{ backgroundColor: 'rgba(245, 158, 11, 0.35)' }} />
              <div className="flex-1" style={{ backgroundColor: 'rgba(245, 158, 11, 0.55)' }} />
              <div className="flex-1" style={{ backgroundColor: 'rgba(239, 68, 68, 0.4)' }} />
              <div className="flex-1" style={{ backgroundColor: 'rgba(239, 68, 68, 0.6)' }} />
            </div>
          </div>
        </div>
      </div>

      {/* Selected Technique Detail Panel */}
      {selectedTech && (
        <div className="sentinel-card overflow-hidden animate-slide-up">
          <div className="px-5 py-4 border-b border-sentinel-border bg-sentinel-bg-tertiary/50">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-mono font-bold text-sentinel-text-primary">
                  {selectedTech.technique_id}: {selectedTech.technique_name}
                </h3>
                <p className="text-[10px] font-mono text-sentinel-text-muted mt-0.5">
                  Tactic: {selectedTech.tactic} &mdash; {selectedTech.ioc_count} associated IOCs
                </p>
              </div>
              <div className="flex items-center gap-2">
                {selectedTech.ioc_count > 0 && (
                  <span className={cn(
                    'text-xs font-mono font-bold px-2.5 py-1 rounded',
                    getTextColor(selectedTech.intensity)
                  )}
                  style={{ backgroundColor: getHeatColor(selectedTech.intensity) }}
                  >
                    INTENSITY {Math.round(selectedTech.intensity * 100)}%
                  </span>
                )}
                <button
                  onClick={() => setSelectedTech(null)}
                  className="text-[10px] font-mono text-sentinel-text-muted hover:text-sentinel-text-primary transition-colors"
                >
                  CLOSE
                </button>
              </div>
            </div>
          </div>

          <div className="p-5">
            {detailLoading ? (
              <p className="text-xs font-mono text-sentinel-text-muted animate-pulse">Loading technique details...</p>
            ) : techDetail ? (
              <div className="space-y-4">
                {techDetail.description && (
                  <p className="text-xs font-mono text-sentinel-text-secondary leading-relaxed line-clamp-3">
                    {techDetail.description}
                  </p>
                )}

                {techDetail.url && (
                  <a
                    href={techDetail.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-[10px] font-mono text-sentinel-accent hover:underline"
                  >
                    <ExternalLink className="w-3 h-3" />
                    View on MITRE ATT&CK
                  </a>
                )}

                {techDetail.data_sources.length > 0 && (
                  <div>
                    <p className="text-[10px] font-mono text-sentinel-text-muted uppercase mb-1.5">Data Sources</p>
                    <div className="flex flex-wrap gap-1.5">
                      {techDetail.data_sources.slice(0, 8).map((ds) => (
                        <span key={ds} className="text-[9px] font-mono px-2 py-0.5 rounded bg-sentinel-bg-tertiary border border-sentinel-border text-sentinel-text-secondary">
                          {ds}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {techDetail.associated_iocs.length > 0 && (
                  <div>
                    <p className="text-[10px] font-mono text-sentinel-text-muted uppercase mb-1.5">Associated IOCs</p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                      {techDetail.associated_iocs.map((ioc) => (
                        <a
                          key={ioc.id}
                          href={`/ioc/${ioc.id}`}
                          className="flex items-center justify-between px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border hover:border-sentinel-accent/30 transition-colors"
                        >
                          <div className="min-w-0 flex-1 mr-2">
                            <p className="text-[10px] font-mono text-sentinel-text-primary truncate">{ioc.value}</p>
                            <p className="text-[9px] font-mono text-sentinel-text-muted uppercase">{ioc.type}</p>
                          </div>
                          <span className={cn(
                            'text-[10px] font-mono font-bold px-1.5 py-0.5 rounded flex-shrink-0',
                            ioc.threat_score >= 76 ? 'text-red-400 bg-red-500/10' :
                            ioc.threat_score >= 51 ? 'text-amber-400 bg-amber-500/10' :
                            ioc.threat_score >= 26 ? 'text-yellow-400 bg-yellow-500/10' :
                            'text-emerald-400 bg-emerald-500/10'
                          )}>
                            {ioc.threat_score}
                          </span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs font-mono text-sentinel-text-muted">
                No associated IOCs for this technique at the current score threshold.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
