import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, ExternalLink, CheckCircle, Database } from 'lucide-react';

export const metadata: Metadata = {
  title: 'Threat Intelligence Feeds',
  description: 'Complete list of open-source threat intelligence feeds and data sources integrated into Wiestell for comprehensive IOC analysis.',
};

export default function FeedsPage() {
  const feeds = [
    {
      name: 'AlienVault OTX',
      description: 'Open Threat Exchange community-driven threat intelligence platform',
      types: ['IP', 'Domain', 'Hash', 'URL'],
      url: 'https://otx.alienvault.com',
    },
    {
      name: 'AbuseIPDB',
      description: 'Database of reported malicious IP addresses',
      types: ['IP'],
      url: 'https://www.abuseipdb.com',
    },
    {
      name: 'URLhaus',
      description: 'Malware URL exchange operated by abuse.ch',
      types: ['URL', 'Domain'],
      url: 'https://urlhaus.abuse.ch',
    },
    {
      name: 'MalwareBazaar',
      description: 'Malware sample database by abuse.ch',
      types: ['Hash'],
      url: 'https://bazaar.abuse.ch',
    },
    {
      name: 'PhishTank',
      description: 'Community-sourced phishing site database',
      types: ['URL', 'Domain'],
      url: 'https://www.phishtank.com',
    },
    {
      name: 'ThreatFox',
      description: 'IOCs associated with malware by abuse.ch',
      types: ['IP', 'Domain', 'Hash'],
      url: 'https://threatfox.abuse.ch',
    },
    {
      name: 'Feodo Tracker',
      description: 'Botnet C&C tracker by abuse.ch',
      types: ['IP', 'Domain'],
      url: 'https://feodotracker.abuse.ch',
    },
    {
      name: 'Blocklist.de',
      description: 'IP addresses conducting attacks, scans, and brute-force attempts',
      types: ['IP'],
      url: 'https://www.blocklist.de',
    },
    {
      name: 'EmergingThreats',
      description: 'Community-driven threat intelligence rules and IOCs',
      types: ['IP', 'Domain'],
      url: 'https://rules.emergingthreats.net',
    },
    {
      name: 'MITRE ATT&CK',
      description: 'Knowledge base of adversary tactics and techniques',
      types: ['Techniques'],
      url: 'https://attack.mitre.org',
    },
  ];

  return (
    <div className="min-h-screen bg-sentinel-bg-primary">
      {/* Header */}
      <header className="border-b border-sentinel-border bg-sentinel-bg-secondary/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <Link
            href="/"
            className="inline-flex items-center gap-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Home
          </Link>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-12">
        <div className="max-w-5xl mx-auto">
          {/* Page Title */}
          <div className="mb-12">
            <h1 className="text-4xl md:text-5xl font-bold font-display text-sentinel-text-primary mb-4">
              Threat Intelligence Feeds
            </h1>
            <p className="text-lg text-sentinel-text-secondary font-mono">
              Open-source threat data sources integrated into Wiestell
            </p>
          </div>

          {/* Stats Section */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
            <div className="sentinel-card p-6 text-center">
              <div className="text-3xl font-bold font-display text-sentinel-accent mb-2">
                {feeds.length}+
              </div>
              <div className="text-sm font-mono text-sentinel-text-muted">
                Active Feeds
              </div>
            </div>
            <div className="sentinel-card p-6 text-center">
              <div className="text-3xl font-bold font-display text-sentinel-accent mb-2">
                24/7
              </div>
              <div className="text-sm font-mono text-sentinel-text-muted">
                Real-time Updates
              </div>
            </div>
            <div className="sentinel-card p-6 text-center">
              <div className="text-3xl font-bold font-display text-sentinel-accent mb-2">
                100%
              </div>
              <div className="text-sm font-mono text-sentinel-text-muted">
                Open Source
              </div>
            </div>
          </div>

          {/* Intro Section */}
          <section className="sentinel-card p-8 mb-8">
            <div className="flex items-start gap-4 mb-4">
              <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                <Database className="w-6 h-6 text-sentinel-accent" />
              </div>
              <div>
                <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary mb-3">
                  Comprehensive Threat Intelligence
                </h2>
                <p className="text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                  Wiestell aggregates data from multiple trusted open-source threat intelligence feeds to provide comprehensive IOC analysis. Each feed is automatically updated to ensure you have access to the latest threat intelligence data.
                </p>
              </div>
            </div>
          </section>

          {/* Feeds List */}
          <div className="space-y-4">
            <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary mb-6">
              Integrated Data Sources
            </h2>
            {feeds.map((feed, index) => (
              <div
                key={index}
                className="sentinel-card p-6 hover:border-sentinel-accent/30 transition-colors"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <CheckCircle className="w-5 h-5 text-sentinel-accent flex-shrink-0" />
                      <h3 className="text-lg font-display font-semibold text-sentinel-text-primary">
                        {feed.name}
                      </h3>
                    </div>
                    <p className="text-sm font-mono text-sentinel-text-secondary mb-3 ml-8">
                      {feed.description}
                    </p>
                    <div className="flex flex-wrap gap-2 ml-8">
                      {feed.types.map((type, typeIndex) => (
                        <span
                          key={typeIndex}
                          className="text-xs font-mono font-semibold text-sentinel-accent px-3 py-1 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/30"
                        >
                          {type}
                        </span>
                      ))}
                    </div>
                  </div>
                  <a
                    href={feed.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors flex-shrink-0"
                  >
                    Visit
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </div>
              </div>
            ))}
          </div>

          {/* Footer Note */}
          <section className="sentinel-card p-8 mt-12 bg-sentinel-accent/5">
            <h2 className="text-xl font-display font-semibold text-sentinel-text-primary mb-3">
              Feed Integration & Updates
            </h2>
            <div className="space-y-2 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
              <p>
                All threat intelligence feeds are automatically synchronized on regular intervals to ensure data freshness. Feed reliability and accuracy are continuously monitored.
              </p>
              <p className="text-sentinel-text-muted text-xs pt-2">
                Want to suggest a new feed? Contact us or submit a pull request on GitHub.
              </p>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
