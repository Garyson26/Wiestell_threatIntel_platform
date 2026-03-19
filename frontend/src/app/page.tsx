'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Image from 'next/image';
import { Upload, Link2, Search, FileText, ArrowRight, Zap, Database, TrendingUp } from 'lucide-react';
import { SoftwareApplicationSchema } from '@/components/shared/JsonLd';
import { PoweredBy } from '@/components/shared/PoweredBy';

export default function Home() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<'file' | 'url' | 'search'>('search');
  const [dragActive, setDragActive] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [file, setFile] = useState<File | null>(null);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleFileSubmit = () => {
    if (file) {
      router.push('/upload');
    }
  };

  const handleUrlSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (urlInput.trim()) {
      router.push(`/ioc?search=${encodeURIComponent(urlInput)}`);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchInput.trim()) {
      router.push(`/ioc?search=${encodeURIComponent(searchInput)}`);
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* JSON-LD Structured Data */}
      <SoftwareApplicationSchema />
      
      {/* Header */}
      <header className="border-b border-sentinel-border bg-sentinel-bg-secondary/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center">
            <Image
              src="/images/Wiestell-Logo.png"
              alt="Wiestell Logo"
              width={140}
              height={47}
              className="object-contain"
              priority
            />
          </div>
          <div className="flex gap-3">
            {/* <button
              onClick={() => router.push('/admin')}
              className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
            >
              Admin Login
            </button> */}
            <button
              onClick={() => router.push('/about')}
              className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
            >
              About
            </button>
             <button
              onClick={() => router.push('/contact')}
              className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
            >
              Contact Us
            </button>
            <button
              onClick={() => router.push('/login')}
              className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
            >
              Login
            </button>
            {/* <button
              onClick={() => router.push('/dashboard')}
              className="px-4 py-2 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-sm font-mono font-semibold hover:bg-sentinel-accent/20 transition-colors flex items-center gap-2"
            >
              Dashboard
              <ArrowRight className="w-4 h-4" />
            </button> */}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 container mx-auto px-6 py-12">
        {/* Hero Section */}
        <div className="text-center mb-12 animate-fade-in">
          <h1 className="text-4xl md:text-5xl font-bold font-display text-sentinel-text-primary mb-4 leading-tight">
            Free Threat Intelligence Platform — IP, Domain & Hash IOC Lookup
          </h1>
          <p className="text-sentinel-text-muted font-mono text-sm max-w-3xl mx-auto leading-relaxed">
            Powered by URLhaus, ThreatFox, MalwareBazaar, AbuseIPDB, VirusTotal, AlienVault OTX, Feodo Tracker, PhishTank and more — completely free.
          </p>
        </div>

        {/* Main Card */}
        <div className="max-w-3xl mx-auto sentinel-card p-8 animate-slide-up">
          {/* Tabs */}
          <div className="flex gap-2 mb-6 border-b border-sentinel-border">
            <button
              onClick={() => setActiveTab('search')}
              className={`flex items-center gap-2 px-4 py-3 font-mono text-sm font-medium transition-colors relative ${
                activeTab === 'search'
                  ? 'text-sentinel-accent'
                  : 'text-sentinel-text-muted hover:text-sentinel-text-secondary'
              }`}
            >
              <Search className="w-4 h-4" />
              Search
              {activeTab === 'search' && (
                <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-sentinel-accent"></div>
              )}
            </button>
          </div>

          {/* Tab Content */}
          <div className="min-h-[300px]">
            {/* Search Tab */}
            {activeTab === 'search' && (
              <form onSubmit={handleSearchSubmit} className="space-y-4">
                <div>
                  <label className="text-sm font-mono text-sentinel-text-muted block mb-3">
                    Search for IP, domain, hash, or other Indicators of Compromise
                  </label>
                  <input
                    type="text"
                    value={searchInput}
                    onChange={(e) => setSearchInput(e.target.value)}
                    placeholder="8.8.8.8, example.com, or file hash..."
                    className="w-full px-4 py-3 rounded bg-sentinel-bg-primary border border-sentinel-border text-sentinel-text-primary font-mono text-sm outline-none focus:border-sentinel-accent/40 transition-colors"
                  />
                </div>
                <button
                  type="submit"
                  disabled={!searchInput.trim()}
                  className="w-full px-6 py-3 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-sm font-mono font-semibold hover:bg-sentinel-accent/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
                >
                  <Search className="w-4 h-4" />
                  Search IOCs
                </button>
              </form>
            )}
          </div>
        </div>

        {/* Features Section */}
        <div className="max-w-5xl mx-auto mt-16 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="sentinel-card p-6 text-center animate-fade-in hover:border-sentinel-accent/30 transition-colors">
            <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center mx-auto mb-4">
              <Zap className="w-6 h-6 text-sentinel-accent" />
            </div>
            <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-2">
              Real-time Analysis
            </h3>
            <p className="text-xs font-mono text-sentinel-text-muted">
              Instant IOC detection powered by multiple live intelligence feeds.
            </p>
          </div>

          <div className="sentinel-card p-6 text-center animate-fade-in hover:border-sentinel-accent/30 transition-colors" style={{ animationDelay: '100ms' }}>
            <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center mx-auto mb-4">
              <Database className="w-6 h-6 text-sentinel-accent" />
            </div>
            <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-2">
              Enrichment Engine
            </h3>
            <p className="text-xs font-mono text-sentinel-text-muted">
              Comprehensive enrichment including geolocation, WHOIS records, and ASN data.
            </p>
          </div>

          <div className="sentinel-card p-6 text-center animate-fade-in hover:border-sentinel-accent/30 transition-colors" style={{ animationDelay: '200ms' }}>
            <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center mx-auto mb-4">
              <TrendingUp className="w-6 h-6 text-sentinel-accent" />
            </div>
            <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-2">
              Threat Scoring
            </h3>
            <p className="text-xs font-mono text-sentinel-text-muted">
              AI-powered risk correlation across all data sources for a single actionable verdict.
            </p>
          </div>
        </div>

        {/* About Wiestell Section */}
        <section className="max-w-4xl mx-auto mt-20 mb-16">
          <article className="prose prose-invert max-w-none">
            <div className="sentinel-card p-8 md:p-10">
              <h2 className="text-2xl md:text-3xl font-display font-bold text-sentinel-text-primary mb-6">
                About Wiestell
              </h2>
              
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
        </section>
      </main>

      {/* Powered By Section */}
      <PoweredBy />

      {/* Footer */}
      <footer className="border-t border-sentinel-border bg-sentinel-bg-secondary/50 py-6">
        <div className="container mx-auto px-6 text-center">
          <p className="text-xs font-mono text-sentinel-text-muted">
            © 2026 Wiestell Threat Intelligence Platform. Open Source.
          </p>
        </div>
      </footer>
    </div>
  );
}
