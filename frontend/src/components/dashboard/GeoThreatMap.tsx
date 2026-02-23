'use client';

import { cn } from '@/lib/utils';
import type { GeoData } from '@/lib/types';

interface GeoThreatMapProps {
  data: GeoData[];
  loading: boolean;
}

const COUNTRY_NAMES: Record<string, string> = {
  AF: 'Afghanistan', AL: 'Albania', DZ: 'Algeria', AE: 'UAE', AR: 'Argentina',
  AM: 'Armenia', AU: 'Australia', AT: 'Austria', AZ: 'Azerbaijan', BD: 'Bangladesh',
  BY: 'Belarus', BE: 'Belgium', BR: 'Brazil', BG: 'Bulgaria', CA: 'Canada',
  CL: 'Chile', CN: 'China', CO: 'Colombia', HR: 'Croatia', CZ: 'Czechia',
  DK: 'Denmark', EG: 'Egypt', EE: 'Estonia', FI: 'Finland', FR: 'France',
  GE: 'Georgia', DE: 'Germany', GR: 'Greece', HK: 'Hong Kong', HU: 'Hungary',
  IN: 'India', ID: 'Indonesia', IR: 'Iran', IQ: 'Iraq', IE: 'Ireland',
  IL: 'Israel', IT: 'Italy', JP: 'Japan', JO: 'Jordan', KZ: 'Kazakhstan',
  KE: 'Kenya', KP: 'North Korea', KR: 'South Korea', KW: 'Kuwait', LV: 'Latvia',
  LB: 'Lebanon', LT: 'Lithuania', MY: 'Malaysia', MX: 'Mexico', MD: 'Moldova',
  MN: 'Mongolia', MA: 'Morocco', NL: 'Netherlands', NZ: 'New Zealand', NG: 'Nigeria',
  NO: 'Norway', PK: 'Pakistan', PA: 'Panama', PE: 'Peru', PH: 'Philippines',
  PL: 'Poland', PT: 'Portugal', QA: 'Qatar', RO: 'Romania', RU: 'Russia',
  SA: 'Saudi Arabia', RS: 'Serbia', SG: 'Singapore', SK: 'Slovakia', SI: 'Slovenia',
  ZA: 'South Africa', ES: 'Spain', SE: 'Sweden', CH: 'Switzerland', TW: 'Taiwan',
  TH: 'Thailand', TR: 'Turkey', UA: 'Ukraine', GB: 'United Kingdom', US: 'United States',
  UZ: 'Uzbekistan', VE: 'Venezuela', VN: 'Vietnam',
};

function countryFlag(code: string): string {
  const upper = code.toUpperCase();
  if (upper.length !== 2) return '';
  return String.fromCodePoint(
    0x1F1E6 + upper.charCodeAt(0) - 65,
    0x1F1E6 + upper.charCodeAt(1) - 65
  );
}

function countryName(code: string): string {
  return COUNTRY_NAMES[code.toUpperCase()] || code;
}

export default function GeoThreatMap({ data, loading }: GeoThreatMapProps) {
  const maxCount = Math.max(...data.map(d => d.count), 1);

  return (
    <div className="sentinel-card">
      <div className="px-5 py-3 border-b border-sentinel-border">
        <h3 className="text-xs font-mono font-semibold uppercase tracking-widest text-sentinel-text-muted">
          GEOGRAPHIC DISTRIBUTION
        </h3>
      </div>
      <div className="p-5">
        {loading ? (
          <div className="space-y-3 animate-pulse">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3">
                <div className="w-16 h-3 bg-sentinel-bg-tertiary rounded" />
                <div className="flex-1 h-3 bg-sentinel-bg-tertiary rounded" />
              </div>
            ))}
          </div>
        ) : data.length === 0 ? (
          <div className="text-center py-8 text-sentinel-text-muted text-xs font-mono">
            Geographic data will appear after IP-based IOCs are enriched
          </div>
        ) : (
          <div className="space-y-2.5">
            {data.slice(0, 10).map((item, i) => (
              <div key={item.country} className="flex items-center gap-2.5 animate-fade-in" style={{ animationDelay: `${i * 30}ms` }}>
                <span className="text-base leading-none flex-shrink-0" title={countryName(item.country)}>
                  {countryFlag(item.country)}
                </span>
                <span className="text-[10px] font-mono text-sentinel-text-secondary w-20 flex-shrink-0 truncate" title={countryName(item.country)}>
                  {countryName(item.country)}
                </span>
                <div className="flex-1 h-3 bg-sentinel-bg-primary rounded overflow-hidden">
                  <div
                    className="h-full rounded transition-all duration-500"
                    style={{
                      width: `${(item.count / maxCount) * 100}%`,
                      backgroundColor: item.avg_score >= 76 ? '#ef4444' : item.avg_score >= 51 ? '#f59e0b' : '#00e5ff',
                    }}
                  />
                </div>
                <span className="text-[10px] font-mono text-sentinel-text-muted w-8 text-right flex-shrink-0">
                  {item.count}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
