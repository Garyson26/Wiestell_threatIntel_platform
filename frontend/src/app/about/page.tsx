import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';

export const metadata: Metadata = {
  title: 'About Wiestell - Free Threat Intelligence Platform',
  description: 'Wiestell is a free, open-source platform designed for security analysts and SOC teams to look up IP addresses, domains, and file hashes.',
};

export default function AboutPage() {
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
        <div className="max-w-4xl mx-auto">
          <article className="prose prose-invert max-w-none">
            <div className="sentinel-card p-8 md:p-10">
              <h1 className="text-3xl md:text-4xl font-display font-bold text-sentinel-text-primary mb-8">
                About Wiestell
              </h1>
              
              <div className="space-y-6 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                <p>
                  <strong className="text-sentinel-accent font-semibold">Wiestell</strong> is a free, open-source platform designed for security analysts and SOC teams to look up IP addresses, domains, and file hashes. Our comprehensive Threat Intelligence Platform (TIP) enables rapid analysis of Indicators of Compromise (IOCs), helping organizations identify, investigate, and respond to cyber threats effectively. Whether you're investigating a potential breach, conducting threat hunting activities, or performing routine security assessments, Wiestell provides the intelligence you need to make informed decisions quickly.
                </p>

                <blockquote className="border-l-4 border-sentinel-accent pl-6 py-4 my-8 bg-sentinel-bg-tertiary/30 rounded-r">
                  <p className="text-sentinel-text-primary font-mono text-base italic mb-3 leading-relaxed">
                    "Threat intelligence shouldn't be a privilege. Every defender... deserves access to the same quality of threat data. That's why Wiestell exists."
                  </p>
                  <footer className="text-sentinel-text-muted text-xs font-mono not-italic">
                    — <cite className="font-semibold text-sentinel-accent">Gary(son) Pereira</cite>, Founder, Wiestell
                  </footer>
                </blockquote>

                <p>
                  Built with security operations in mind, Wiestell supports analysis of multiple IOC types including <strong className="text-sentinel-text-primary">IP addresses</strong>, <strong className="text-sentinel-text-primary">domain names</strong>, <strong className="text-sentinel-text-primary">file hashes (MD5, SHA1, SHA256)</strong>, and <strong className="text-sentinel-text-primary">URLs</strong>. The platform is powered by a curated collection of <strong className="text-sentinel-text-primary">open-source threat intelligence feeds</strong> from trusted sources including AlienVault OTX, AbuseIPDB, URLhaus, MalwareBazaar, PhishTank, and ThreatFox.
                </p>

                <p>
                  Our enrichment engine automatically correlates data across multiple feeds, performs geolocation lookups, conducts WHOIS queries, and assesses reputation scores to provide comprehensive context for every IOC analyzed. Security teams can leverage our AI-driven threat scoring system to prioritize investigations, while developers and researchers can integrate threat intelligence into their workflows. The platform features automated feed ingestion, real-time enrichment, correlation analysis, and detailed reporting capabilities—all available at no cost.
                </p>

                <p className="text-sentinel-text-muted text-xs pt-4">
                  Start analyzing threats today with Wiestell's free threat intelligence platform and join a community of security professionals dedicated to making the internet safer for everyone.
                </p>
              </div>
            </div>
          </article>
        </div>
      </main>
    </div>
  );
}
