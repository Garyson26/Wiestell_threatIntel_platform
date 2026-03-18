import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, Shield, Search, Activity, Zap, Lock, Cloud, FileCheck, User, Users2, Crosshair, Bug, GraduationCap, ExternalLink, Linkedin } from 'lucide-react';

export const metadata: Metadata = {
  title: 'About Wiestell | Free Open-Source Threat Intelligence Platform',
  description: 'Learn about Wiestell, a free open-source threat intelligence platform built to help security analysts look up IPs, domains, and file hashes against the world\'s best open threat feeds.',
};

export default function AboutPage() {
  const intelligenceSources = [
    { name: 'URLhaus', description: 'Malware distribution URLs' },
    { name: 'ThreatFox', description: 'IOCs shared by the community' },
    { name: 'MalwareBazaar', description: 'Malware sample intelligence' },
    { name: 'Feodo Tracker', description: 'Botnet C2 infrastructure tracking' },
    { name: 'AbuseIPDB', description: 'Crowdsourced IP reputation' },
    { name: 'AlienVault OTX', description: 'Open threat intelligence exchange' },
    { name: 'PhishTank', description: 'Phishing URL verification' },
    { name: 'Emerging Threats', description: 'Proofpoint threat intelligence' },
    { name: 'Blocklist.de', description: 'SSH, mail, and web attacks' },
    { name: 'VirusTotal', description: 'Multi-engine malware scanning' },
  ];

  const userGroups = [
    { icon: Shield, title: 'SOC Analysts', description: 'Monitor and investigate security alerts' },
    { icon: Search, title: 'Incident Responders', description: 'Rapid IOC analysis during breaches' },
    { icon: Crosshair, title: 'Threat Hunters', description: 'Proactive threat discovery' },
    { icon: Lock, title: 'Security Engineers', description: 'Infrastructure protection and monitoring' },
    { icon: GraduationCap, title: 'Students & Researchers', description: 'Learn cybersecurity and threat analysis' },
  ];

  const expertise = [
    'Threat Intelligence & Detection',
    'Incident Response & Automation',
    'Cloud & Infrastructure Security',
    'Governance, Risk & Compliance',
    'Identity & Access Management',
    'AI/ML Security',
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
        <div className="max-w-5xl mx-auto space-y-12">
          {/* Page Header */}
          <div className="text-center mb-16">
            <h1 className="text-4xl md:text-5xl font-display font-bold text-sentinel-text-primary mb-4">
              About Wiestell
            </h1>
            <p className="text-lg text-sentinel-text-secondary font-mono">
              Free, Open-Source Threat Intelligence for Everyone
            </p>
          </div>

          {/* What is Wiestell? */}
          <section className="sentinel-card p-8 md:p-10">
            <h2 className="text-2xl md:text-3xl font-display font-bold text-sentinel-text-primary mb-6">
              What is Wiestell?
            </h2>
            <div className="space-y-4 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
              <p>
                <strong className="text-sentinel-accent">Wiestell</strong> is a free, open-source threat intelligence platform designed for SOC teams, security researchers, and incident responders. It consolidates data from the world's most trusted open-source threat feeds into a single investigation point.
              </p>
              <p>
                Instead of checking multiple sites manually, Wiestell allows you to look up <strong className="text-sentinel-text-primary">IP addresses</strong>, <strong className="text-sentinel-text-primary">domains</strong>, <strong className="text-sentinel-text-primary">URLs</strong>, and <strong className="text-sentinel-text-primary">file hashes</strong> in one place and get enriched, correlated results instantly.
              </p>
              <p className="text-sentinel-accent font-semibold">
                One platform. One search. All feeds.
              </p>
            </div>
          </section>

          {/* Why We Built It */}
          <section className="sentinel-card p-8 md:p-10">
            <h2 className="text-2xl md:text-3xl font-display font-bold text-sentinel-text-primary mb-6">
              Why We Built It
            </h2>
            <div className="space-y-4 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
              <p>
                Threat intelligence is often locked behind expensive subscriptions, making it inaccessible to smaller teams, independent researchers, and students. We believe security should be democratized.
              </p>
              <blockquote className="border-l-4 border-sentinel-accent pl-6 py-4 my-6 bg-sentinel-bg-tertiary/30 rounded-r">
                <p className="text-sentinel-text-primary font-mono text-base italic mb-3 leading-relaxed">
                  "Threat intelligence shouldn't be a privilege. Every defender deserves access to the same quality of threat data. That's why Wiestell exists."
                </p>
                <footer className="text-sentinel-text-muted text-xs font-mono not-italic">
                  — <cite className="font-semibold text-sentinel-accent">Gary(son) Pereira</cite>, Founder, Wiestell
                </footer>
              </blockquote>
              <p>
                Wiestell was built to level the playing field. Whether you're running a global SOC or learning cybersecurity from your dorm room, you deserve the same intelligence-grade tools.
              </p>
            </div>
          </section>

          {/* What Wiestell Checks */}
          <section className="sentinel-card p-8 md:p-10">
            <h2 className="text-2xl md:text-3xl font-display font-bold text-sentinel-text-primary mb-6">
              What Wiestell Checks
            </h2>
            <p className="text-sentinel-text-secondary font-mono text-sm mb-6">
              Every lookup correlates data across these trusted intelligence sources:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {intelligenceSources.map((source, index) => (
                <div
                  key={index}
                  className="flex items-start gap-3 p-4 rounded bg-sentinel-bg-tertiary/30 border border-sentinel-border/50 hover:border-sentinel-accent/40 transition-colors"
                >
                  <Activity className="w-5 h-5 text-sentinel-accent flex-shrink-0 mt-0.5" />
                  <div>
                    <h3 className="text-sm font-mono font-semibold text-sentinel-text-primary">
                      {source.name}
                    </h3>
                    <p className="text-xs font-mono text-sentinel-text-muted mt-1">
                      {source.description}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Who Uses Wiestell */}
          <section className="sentinel-card p-8 md:p-10">
            <h2 className="text-2xl md:text-3xl font-display font-bold text-sentinel-text-primary mb-6">
              Who Uses Wiestell
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {userGroups.map((group, index) => {
                const IconComponent = group.icon;
                return (
                  <div
                    key={index}
                    className="flex flex-col items-center text-center p-6 rounded-lg bg-sentinel-bg-tertiary/20 border border-sentinel-border/50 hover:border-sentinel-accent/40 transition-colors"
                  >
                    <div className="w-12 h-12 rounded-full bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center mb-4">
                      <IconComponent className="w-6 h-6 text-sentinel-accent" />
                    </div>
                    <h3 className="text-sm font-mono font-semibold text-sentinel-text-primary mb-2">
                      {group.title}
                    </h3>
                    <p className="text-xs font-mono text-sentinel-text-muted">
                      {group.description}
                    </p>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Meet the Founder */}
          <section className="sentinel-card p-8 md:p-10 bg-sentinel-accent/5 border-2 border-sentinel-accent/20">
            <div className="flex items-center gap-3 mb-6">
              <h2 className="text-2xl md:text-3xl font-display font-bold text-sentinel-text-primary">
                Meet the Founder
              </h2>
              <a
                href="https://www.linkedin.com/in/garysonpereira"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sentinel-accent hover:text-sentinel-accent/80 transition-colors"
                title="Connect on LinkedIn"
              >
                <Linkedin className="w-6 h-6" />
              </a>
            </div>

            <div className="space-y-6">
              <div>
                <h3 className="text-xl font-mono font-bold text-sentinel-text-primary mb-3">
                  Gary(son) Pereira
                </h3>
                <p className="text-sm font-mono text-sentinel-text-secondary leading-relaxed">
                  With over <strong className="text-sentinel-accent">11 years of experience</strong> in cybersecurity, Gary(son) holds an <strong className="text-sentinel-text-primary">M.Sc. in Computer Forensics</strong> and currently serves as <strong className="text-sentinel-text-primary">Lead Security Engineer at Oakbrook Finance</strong>. His expertise spans threat intelligence, incident response, cloud security, and AI/ML security.
                </p>
              </div>

              {/* Expertise Grid */}
              <div>
                <h4 className="text-sm font-mono font-semibold text-sentinel-text-primary mb-4 uppercase tracking-wider">
                  Core Competencies
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {expertise.map((skill, index) => (
                    <div
                      key={index}
                      className="flex items-center gap-2 p-3 rounded bg-sentinel-bg-secondary border border-sentinel-border hover:border-sentinel-accent/40 transition-colors"
                    >
                      <Zap className="w-4 h-4 text-sentinel-accent flex-shrink-0" />
                      <span className="text-xs font-mono text-sentinel-text-primary">
                        {skill}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>

          {/* Call to Action */}
          <section className="text-center py-8">
            <p className="text-sm font-mono text-sentinel-text-secondary mb-6">
              Ready to start analyzing threats?
            </p>
            <Link
              href="/"
              className="inline-flex items-center gap-2 px-6 py-3 rounded bg-sentinel-accent text-sentinel-bg-primary font-mono font-semibold text-sm hover:bg-sentinel-accent/90 transition-colors"
            >
              <Search className="w-4 h-4" />
              Start Searching IOCs
            </Link>
          </section>
        </div>
      </main>
    </div>
  );
}
