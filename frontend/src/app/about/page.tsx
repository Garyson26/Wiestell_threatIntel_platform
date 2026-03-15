import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, Shield, Users, Code } from 'lucide-react';

export const metadata: Metadata = {
  title: 'About',
  description: 'Learn about Wiestell, our mission to provide free threat intelligence for the cybersecurity community, and the team behind the platform.',
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
          {/* Page Title */}
          <div className="mb-12">
            <h1 className="text-4xl md:text-5xl font-bold font-display text-sentinel-text-primary mb-4">
              About Wiestell
            </h1>
            <p className="text-lg text-sentinel-text-secondary font-mono">
              Building the future of free threat intelligence
            </p>
          </div>

          {/* Content Sections */}
          <div className="space-y-8">
            {/* Mission Section */}
            <section className="sentinel-card p-8">
              <div className="flex items-start gap-4 mb-4">
                <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                  <Shield className="w-6 h-6 text-sentinel-accent" />
                </div>
                <div>
                  <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary mb-3">
                    Our Mission
                  </h2>
                  <div className="space-y-3 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                    <p>
                      Wiestell was created to democratize access to threat intelligence. We believe that security tools should be accessible to everyone, from individual researchers to enterprise security teams.
                    </p>
                    <p>
                      Our platform aggregates data from multiple open-source threat intelligence feeds, providing comprehensive IOC analysis, enrichment, and correlation—all at no cost.
                    </p>
                  </div>
                </div>
              </div>
            </section>

            {/* What We Do Section */}
            <section className="sentinel-card p-8">
              <div className="flex items-start gap-4 mb-4">
                <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                  <Code className="w-6 h-6 text-sentinel-accent" />
                </div>
                <div>
                  <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary mb-3">
                    What We Do
                  </h2>
                  <div className="space-y-3 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                    <p>
                      Wiestell provides real-time threat intelligence analysis for IPs, domains, URLs, and file hashes. Our platform enriches IOCs with geolocation data, WHOIS information, reputation scores, and correlates indicators across multiple threat feeds.
                    </p>
                    <p>
                      We believe in transparency and the power of open-source intelligence. All our data sources are publicly documented, and our methodologies are clearly explained.
                    </p>
                  </div>
                </div>
              </div>
            </section>

            {/* Team/Community Section */}
            <section className="sentinel-card p-8">
              <div className="flex items-start gap-4 mb-4">
                <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                  <Users className="w-6 h-6 text-sentinel-accent" />
                </div>
                <div>
                  <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary mb-3">
                    Open Source & Community Driven
                  </h2>
                  <div className="space-y-3 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                    <p>
                      Wiestell is built by security professionals, for security professionals. Our platform is open-source and community-driven, welcoming contributions from researchers and developers worldwide.
                    </p>
                    <p>
                      Join us in making the internet safer for everyone by improving threat intelligence accessibility and quality.
                    </p>
                  </div>
                </div>
              </div>
            </section>

            {/* Contact/Links Section */}
            <section className="sentinel-card p-8 bg-sentinel-accent/5">
              <h2 className="text-xl font-display font-semibold text-sentinel-text-primary mb-4">
                Get Involved
              </h2>
              <div className="space-y-2 text-sentinel-text-secondary font-mono text-sm">
                <p>Want to contribute or learn more?</p>
                <div className="flex flex-wrap gap-4 mt-4">
                  <Link
                    href="https://github.com/wiestell"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-sm font-mono font-semibold hover:bg-sentinel-accent/20 transition-colors"
                  >
                    GitHub
                  </Link>
                  <Link
                    href="/api-docs"
                    className="px-4 py-2 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-sm font-mono font-semibold hover:bg-sentinel-accent/20 transition-colors"
                  >
                    API Documentation
                  </Link>
                </div>
              </div>
            </section>
          </div>
        </div>
      </main>
    </div>
  );
}
