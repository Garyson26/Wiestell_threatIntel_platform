'use client';

import type { Metadata } from 'next';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import Image from 'next/image';
import { ArrowLeft, Shield, Search, Activity, Zap, Lock, Cloud, FileCheck, User, Users2, Crosshair, Bug, GraduationCap, ExternalLink, Linkedin, LogOut } from 'lucide-react';
import { useAuth } from '@/lib/auth';

// export const metadata: Metadata = {
//   title: 'About Wiestell | Free Open-Source Threat Intelligence Platform',
//   description: 'Learn about Wiestell, a free open-source threat intelligence platform built to help security analysts look up IPs, domains, and file hashes against the world\'s best open threat feeds.',
// };

export default function AboutPage() {
  const router = useRouter();
  const { user, logout } = useAuth();
  const intelligenceSources = [
    { name: 'URLhaus', description: 'Malware distribution URLs and download sites' },
    { name: 'ThreatFox', description: 'Indicators of compromise associated with malware families' },
    { name: 'MalwareBazaar', description: 'Malware sample hashes and metadata' },
    { name: 'Feodo Tracker', description: 'Botnet command-and-control server indicators' },
    { name: 'AbuseIPDB', description: 'Crowdsourced IP abuse reports' },
    { name: 'AlienVault OTX', description: 'Open threat exchange indicators and pulses' },
    { name: 'PhishTank', description: 'Verified phishing URLs' },
    { name: 'Emerging Threats', description: 'Community-maintained IP and domain blocklists' },
    { name: 'Blocklist.de', description: 'Attack source IPs from honeypot networks' },
    { name: 'VirusTotal', description: 'Multi-engine file, URL, and domain reputation' },
  ];

  const userGroups = [
    { icon: Shield, title: 'SOC analysts', description: 'Triaging alerts who need a fast IOC reputation check' },
    { icon: Search, title: 'Incident responders', description: 'Investigating suspicious IPs or domains' },
    { icon: Crosshair, title: 'Threat hunters', description: 'Building adversary profiles' },
    { icon: Lock, title: 'Security engineers', description: 'Building automated enrichment pipelines' },
    { icon: GraduationCap, title: 'Students and researchers', description: 'Learning threat intelligence' },
  ];

  const expertise = [
    {
      title: 'Threat Intelligence & Detection',
      description: 'Threat Intelligence, Threat Hunting, MITRE ATT&CK-mapped detections, IOC enrichment and correlation'
    },
    {
      title: 'Incident Response & Automation',
      description: 'Incident Response, SOAR automation, automated alert triage pipelines, SOC workflow design'
    },
    {
      title: 'Cloud & Infrastructure Security',
      description: 'Cloud-native Kubernetes security, Zero Trust design, secure architecture reviews, system design'
    },
    {
      title: 'Governance, Risk & Compliance',
      description: 'NIST CSF, ISO 27001, PCI-DSS, OWASP Top 10, CIS Controls, UK Cyber Essentials, vendor risk assessments'
    },
    {
      title: 'Identity & Access Management',
      description: 'IAM, RBAC, Data Loss Prevention (DLP), Zero Trust access principles'
    },
    {
      title: 'AI / ML Security',
      description: 'AI/ML security research, threat modelling'
    },
  ];

  return (
    <div className="min-h-screen bg-sentinel-bg-primary">
      {/* Header */}
      <header className="border-b border-sentinel-border bg-sentinel-bg-secondary/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center">
            <Image
              src="/images/Wiestell-Logo.png"
              alt="Wiestell Logo"
              width={140}
              height={47}
              className="object-contain"
              priority
            />
          </Link>
          <div className="flex gap-3">
            <Link
              href="/about"
              className="px-4 py-2 text-sm font-mono text-sentinel-accent hover:text-sentinel-accent transition-colors font-semibold"
            >
              About
            </Link>
            <Link
              href="/contact"
              className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
            >
              Contact Us
            </Link>
            {user ? (
              <>
                <button
                  onClick={() => {
                    const dashboardPath = user.role === 'admin' ? '/dashboard' : '/analytics';
                    router.push(dashboardPath);
                  }}
                  className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
                >
                  Dashboard
                </button>
                <button
                  onClick={() => {
                    logout();
                    router.push('/');
                  }}
                  className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors flex items-center gap-1"
                >
                  <LogOut className="w-4 h-4" />
                  Logout
                </button>
              </>
            ) : (
              <>
                <Link
                  href="/login"
                  className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
                >
                  Login
                </Link>
              </>
            )}
          </div>
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
              Free Threat Intelligence for Everyone
            </p>
          </div>

          {/* What is Wiestell? */}
          <section className="sentinel-card p-8 md:p-10">
            <h2 className="text-2xl md:text-3xl font-display font-bold text-sentinel-text-primary mb-6">
              What is Wiestell?
            </h2>
            <div className="space-y-4 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
              <p>
                <strong className="text-sentinel-accent">Wiestell</strong> is a free threat intelligence platform designed for security analysts, SOC teams, incident responders, and cybersecurity researchers. It aggregates and correlates data from the world's most trusted open-source threat intelligence feeds, giving defenders a single place to investigate indicators of compromise (IOCs) quickly and without cost.
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
                Threat intelligence has historically been locked behind expensive enterprise subscriptions. While excellent open-source feeds exist — URLhaus, ThreatFox, AbuseIPDB, AlienVault OTX, and others — accessing them individually is slow and fragmented. Wiestell was built to solve that: <strong className="text-sentinel-accent">one platform, one search, all feeds</strong>.
              </p>
              <p>
                Our goal is to make actionable threat intelligence accessible to every defender, regardless of budget — from a solo analyst at an NGO to a mature SOC team.
              </p>
            </div>
          </section>

          {/* What Wiestell Checks */}
          <section className="sentinel-card p-8 md:p-10">
            <h2 className="text-2xl md:text-3xl font-display font-bold text-sentinel-text-primary mb-6">
              What Wiestell Checks
            </h2>
            <p className="text-sentinel-text-secondary font-mono text-sm mb-6">
              For any IP address, domain, URL, or file hash you submit, Wiestell queries and correlates data from the following open-source intelligence sources:
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
              Who Uses Wiestell?
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
                href="https://www.linkedin.com/in/garyson-pereira-a34019b8"
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
                <div className="space-y-4 text-sm font-mono text-sentinel-text-secondary leading-relaxed">
                  <p>
                    Gary(son) is a cybersecurity leader with <strong className="text-sentinel-accent">11 years of experience</strong> spanning professional practice and advanced academic research. He holds an <strong className="text-sentinel-text-primary">M.Sc. in Computer Forensics and Cyber Security from the University of Greenwich, London</strong>.
                  </p>
                  <p>
                    Garyson built Wiestell out of the conviction that high-quality threat intelligence should be freely available to every defender — not just organisations with enterprise budgets. Drawing on his day-to-day work leading threat intelligence programmes, SOC workflows, and security automation, he designed Wiestell to aggregate the best open-source feeds into a single, fast, and accessible platform.
                  </p>
                </div>
              </div>

              {/* Professional Role */}
              <div>
                <h4 className="text-sm font-mono font-semibold text-sentinel-text-primary mb-3 uppercase tracking-wider">
                  Expertise
                </h4>
                <p className="text-sm font-mono text-sentinel-text-secondary leading-relaxed mb-4">
                  In his professional role, Garyson leads the implementation of a threat intelligence-driven <strong className="text-sentinel-text-primary">Continuous Threat Exposure Management (CTEM)</strong> framework, enhancing organisational resilience against evolving cyber threats. His work spans the full spectrum of modern security engineering:
                </p>
              </div>

              {/* Expertise Grid */}
              <div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {expertise.map((skill, index) => (
                    <div
                      key={index}
                      className="flex flex-col gap-2 p-4 rounded bg-sentinel-bg-secondary border border-sentinel-border hover:border-sentinel-accent/40 transition-colors"
                    >
                      <div className="flex items-center gap-2">
                        <Zap className="w-4 h-4 text-sentinel-accent flex-shrink-0" />
                        <h5 className="text-xs font-mono font-bold text-sentinel-text-primary">
                          {skill.title}
                        </h5>
                      </div>
                      <p className="text-xs font-mono text-sentinel-text-muted leading-relaxed pl-6">
                        {skill.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>

          {/* Open Source */}
          <section className="sentinel-card p-8 md:p-10">
            <h2 className="text-2xl md:text-3xl font-display font-bold text-sentinel-text-primary mb-6">
              Community Driven
            </h2>
            <div className="space-y-4 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
              <p>
                Wiestell is <strong className="text-sentinel-accent">free</strong>. We believe in transparency and community-driven security. Contributions, bug reports, and feature suggestions are welcome.
              </p>
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
