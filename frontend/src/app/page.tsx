'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { Upload, Link2, Search, FileText, Shield, ArrowRight, Zap, Database, TrendingUp } from 'lucide-react';

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
      {/* Header */}
      <header className="border-b border-sentinel-border bg-sentinel-bg-secondary/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-sentinel-accent" />
            <div>
              <h1 className="text-xl font-bold font-display text-sentinel-accent tracking-wider">SENTINEL</h1>
              <p className="text-[10px] font-mono text-sentinel-text-muted tracking-wide">Threat Intelligence Platform</p>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => router.push('/login')}
              className="px-4 py-2 text-sm font-mono text-sentinel-text-secondary hover:text-sentinel-accent transition-colors"
            >
              Sign In
            </button>
            <button
              onClick={() => router.push('/dashboard')}
              className="px-4 py-2 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-sm font-mono font-semibold hover:bg-sentinel-accent/20 transition-colors flex items-center gap-2"
            >
              Dashboard
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 container mx-auto px-6 py-12">
        {/* Hero Section */}
        <div className="text-center mb-12 animate-fade-in">
          <h2 className="text-4xl font-bold font-display text-sentinel-text-primary mb-3">
            Analyze Suspicious Files, URLs, and IOCs
          </h2>
          <p className="text-sentinel-text-secondary font-mono text-sm max-w-2xl mx-auto">
            Powered by advanced threat intelligence feeds, enrichment engines, and AI-driven analysis
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
              Instant threat detection powered by multiple intelligence feeds
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
              Comprehensive IOC enrichment with geolocation, WHOIS, and reputation data
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
              AI-powered risk assessment and correlation analysis
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-sentinel-border bg-sentinel-bg-secondary/50 py-6">
        <div className="container mx-auto px-6 text-center">
          <p className="text-xs font-mono text-sentinel-text-muted">
            © 2026 SENTINEL Threat Intelligence Platform. Open Source.
          </p>
        </div>
      </footer>
    </div>
  );
}
