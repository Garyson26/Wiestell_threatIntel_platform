import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, Search, Database, Zap, TrendingUp, Globe, Shield } from 'lucide-react';

export const metadata: Metadata = {
  title: 'How It Works',
  description: 'Discover how Wiestell analyzes threats, enriches IOCs, and provides actionable intelligence using multiple threat feeds and AI-powered scoring.',
};

export default function HowItWorksPage() {
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
          {/* Page Title */}
          <div className="mb-12">
            <h1 className="text-4xl md:text-5xl font-bold font-display text-sentinel-text-primary mb-4">
              How Wiestell Works
            </h1>
            <p className="text-lg text-sentinel-text-secondary font-mono">
              Understanding our threat intelligence pipeline
            </p>
          </div>

          {/* Process Steps */}
          <div className="space-y-6">
            {/* Step 1 */}
            <section className="sentinel-card p-8">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                  <Search className="w-6 h-6 text-sentinel-accent" />
                </div>
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-xs font-mono font-bold text-sentinel-accent px-3 py-1 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/30">
                      STEP 1
                    </span>
                    <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary">
                      IOC Submission
                    </h2>
                  </div>
                  <div className="space-y-3 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                    <p>
                      Submit an Indicator of Compromise (IOC) for analysis. Wiestell supports IP addresses, domain names, URLs, and file hashes (MD5, SHA1, SHA256).
                    </p>
                    <p>
                      Our validation engine automatically detects the IOC type and formats it correctly for analysis across multiple threat intelligence sources.
                    </p>
                  </div>
                </div>
              </div>
            </section>

            {/* Step 2 */}
            <section className="sentinel-card p-8">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                  <Database className="w-6 h-6 text-sentinel-accent" />
                </div>
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-xs font-mono font-bold text-sentinel-accent px-3 py-1 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/30">
                      STEP 2
                    </span>
                    <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary">
                      Feed Aggregation
                    </h2>
                  </div>
                  <div className="space-y-3 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                    <p>
                      Your IOC is queried against our curated collection of open-source threat intelligence feeds including AlienVault OTX, AbuseIPDB, URLhaus, MalwareBazaar, PhishTank, ThreatFox, and more.
                    </p>
                    <p>
                      We aggregate results from multiple sources to provide comprehensive threat context and reduce false positives.
                    </p>
                  </div>
                </div>
              </div>
            </section>

            {/* Step 3 */}
            <section className="sentinel-card p-8">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                  <Zap className="w-6 h-6 text-sentinel-accent" />
                </div>
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-xs font-mono font-bold text-sentinel-accent px-3 py-1 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/30">
                      STEP 3
                    </span>
                    <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary">
                      Enrichment
                    </h2>
                  </div>
                  <div className="space-y-3 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                    <p>
                      Our enrichment engine enhances each IOC with additional context including geolocation data, WHOIS information, DNS records, reputation scores, and historical threat activity.
                    </p>
                    <p>
                      This enrichment process helps security analysts understand the full scope and potential impact of each indicator.
                    </p>
                  </div>
                </div>
              </div>
            </section>

            {/* Step 4 */}
            <section className="sentinel-card p-8">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                  <TrendingUp className="w-6 h-6 text-sentinel-accent" />
                </div>
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-xs font-mono font-bold text-sentinel-accent px-3 py-1 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/30">
                      STEP 4
                    </span>
                    <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary">
                      AI-Powered Scoring
                    </h2>
                  </div>
                  <div className="space-y-3 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                    <p>
                      Our AI-powered scoring engine analyzes all collected data to generate a comprehensive threat score (0-100). The score considers factors like feed confidence, maliciousness indicators, activity patterns, and correlation with known threats.
                    </p>
                    <p>
                      This helps prioritize which threats require immediate attention versus those that may be false positives or low-risk indicators.
                    </p>
                  </div>
                </div>
              </div>
            </section>

            {/* Step 5 */}
            <section className="sentinel-card p-8">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                  <Globe className="w-6 h-6 text-sentinel-accent" />
                </div>
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-xs font-mono font-bold text-sentinel-accent px-3 py-1 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/30">
                      STEP 5
                    </span>
                    <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary">
                      Results & Correlation
                    </h2>
                  </div>
                  <div className="space-y-3 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                    <p>
                      View comprehensive results including threat classification, associated malware families, MITRE ATT&CK tactics and techniques, related IOCs, and historical activity timelines.
                    </p>
                    <p>
                      Our correlation engine identifies relationships between IOCs, helping you discover campaigns, infrastructure, and threat actor patterns.
                    </p>
                  </div>
                </div>
              </div>
            </section>

            {/* CTA Section */}
            <section className="sentinel-card p-8 bg-sentinel-accent/5">
              <div className="text-center">
                <Shield className="w-12 h-12 text-sentinel-accent mx-auto mb-4" />
                <h2 className="text-xl font-display font-semibold text-sentinel-text-primary mb-3">
                  Ready to Analyze Threats?
                </h2>
                <p className="text-sentinel-text-secondary font-mono text-sm mb-6">
                  Start investigating IOCs with Wiestell's free threat intelligence platform
                </p>
                <Link
                  href="/"
                  className="inline-flex items-center gap-2 px-6 py-3 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-sm font-mono font-semibold hover:bg-sentinel-accent/20 transition-colors"
                >
                  Start Analyzing
                </Link>
              </div>
            </section>
          </div>
        </div>
      </main>
    </div>
  );
}
