'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Image from 'next/image';
import { Upload, Link2, Search, FileText, ArrowRight, Zap, Database, TrendingUp, LogOut } from 'lucide-react';
import { SoftwareApplicationSchema } from '@/components/shared/JsonLd';
import { PoweredBy } from '@/components/shared/PoweredBy';
import { useAuth } from '@/lib/auth';

export default function Home() {
  const router = useRouter();
  const { user, logout } = useAuth();
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
                <button
                  onClick={() => router.push('/login')}
                  className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
                >
                  Login
                </button>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 container mx-auto px-6 py-12">
        {/* Hero Section */}
        <div className="text-center mb-12 animate-fade-in">
          <h1 className="text-4xl md:text-4xl font-bold font-display text-sentinel-text-primary mb-4 leading-tight">
            Free Threat Intelligence Platform — IP, Domain & Hash IOC Lookup
          </h1>
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
          <div className="">
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

        {/* About Wiestell Section */}
        <section className="max-w-4xl mx-auto mt-20 mb-16">
          <article className="prose prose-invert max-w-none">
            <div className="sentinel-card p-8 md:p-10">
                         
              <div className="space-y-6 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                <p>
                  <strong className="text-sentinel-accent font-semibold">Wiestell</strong> is a free, open-source threat intelligence platform that aggregates data from the most trusted open-source feeds on the internet. Security analysts, SOC teams, and threat researchers can instantly look up any IP address, domain name, URL, or file hash to check its reputation, malware associations, and threat history.
                </p>

                <blockquote className="border-l-4 border-sentinel-accent pl-6 py-4 my-8 bg-sentinel-bg-tertiary/30 rounded-r">
                  <p className="text-sentinel-text-primary font-mono text-base italic mb-3 leading-relaxed">
                    "Threat intelligence shouldn't be a privilege. Every defender — whether in a mature
enterprise SOC or working solo — deserves access to the same quality of threat data.
That's why Wiestell exists."
                  </p>
                  <footer className="text-sentinel-text-muted text-xs font-mono not-italic">
                    — <cite className="font-semibold text-sentinel-accent">Gary(son) Pereira</cite>, Founder, Wiestell
                  </footer>
                </blockquote>

                {/* Feature Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 my-8">
                  <div className="bg-sentinel-bg-tertiary/20 border border-sentinel-border rounded p-5 hover:border-sentinel-accent/30 transition-colors">
                    <div className="w-10 h-10 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center mb-3">
                      <Zap className="w-5 h-5 text-sentinel-accent" />
                    </div>
                    <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-2">
                      Real-time Analysis
                    </h3>
                    <p className="text-xs font-mono text-sentinel-text-secondary leading-relaxed">
                      Instant IOC detection powered by multiple live intelligence feeds updated continuously by the security community.
                    </p>
                  </div>

                  <div className="bg-sentinel-bg-tertiary/20 border border-sentinel-border rounded p-5 hover:border-sentinel-accent/30 transition-colors">
                    <div className="w-10 h-10 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center mb-3">
                      <Database className="w-5 h-5 text-sentinel-accent" />
                    </div>
                    <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-2">
                      Enrichment Engine
                    </h3>
                    <p className="text-xs font-mono text-sentinel-text-secondary leading-relaxed">
                      Comprehensive enrichment including geolocation, WHOIS records, ASN data, and historical reputation scoring.
                    </p>
                  </div>

                  <div className="bg-sentinel-bg-tertiary/20 border border-sentinel-border rounded p-5 hover:border-sentinel-accent/30 transition-colors">
                    <div className="w-10 h-10 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center mb-3">
                      <TrendingUp className="w-5 h-5 text-sentinel-accent" />
                    </div>
                    <h3 className="text-sm font-display font-semibold text-sentinel-text-primary mb-2">
                      Threat Scoring
                    </h3>
                    <p className="text-xs font-mono text-sentinel-text-secondary leading-relaxed">
                      AI-powered risk correlation across all data sources. Get a single actionable verdict on any indicator of compromise.
                    </p>
                  </div>
                </div>

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
            © 2026 Wiestell Open Source Threat Intelligence Platform.
          </p>
        </div>
      </footer>
    </div>
  );
}
