import React from 'react';
import Link from 'next/link';

interface ThreatSource {
  name: string;
  url: string;
}

const threatSources: ThreatSource[] = [
  { name: 'URLhaus', url: 'https://urlhaus.abuse.ch' },
  { name: 'ThreatFox', url: 'https://threatfox.abuse.ch' },
  { name: 'AbuseIPDB', url: 'https://www.abuseipdb.com' },
  { name: 'VirusTotal', url: 'https://www.virustotal.com' },
  { name: 'AlienVault OTX', url: 'https://otx.alienvault.com' },
  { name: 'MalwareBazaar', url: 'https://bazaar.abuse.ch' },
  { name: 'Feodo Tracker', url: 'https://feodotracker.abuse.ch' },
  { name: 'PhishTank', url: 'https://www.phishtank.com' },
];

export function PoweredBy() {
  return (
    <section className="py-8 border-t border-sentinel-border">
      <div className="container mx-auto px-6">
        <div className="max-w-5xl mx-auto">
          <p className="text-xs font-mono text-sentinel-text-muted text-center mb-4">
            Powered by open-source threat intelligence
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            {threatSources.map((source) => (
              <a
                key={source.name}
                href={source.url}
                target="_blank"
                rel="noopener noreferrer"
                className="group px-4 py-2 rounded-md bg-sentinel-bg-secondary/50 border border-sentinel-border hover:border-sentinel-accent/40 transition-all duration-200 hover:bg-sentinel-bg-secondary"
              >
                <span className="text-xs font-mono text-sentinel-text-secondary group-hover:text-sentinel-accent transition-colors">
                  {source.name}
                </span>
              </a>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
