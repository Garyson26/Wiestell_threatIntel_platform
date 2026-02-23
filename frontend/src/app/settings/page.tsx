'use client';

import { useState } from 'react';
import { Settings, Save, Shield, Database, Rss, Key, Sparkles } from 'lucide-react';
import { cn } from '@/lib/utils';

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState('general');

  const sections = [
    { id: 'general', label: 'General', icon: Settings },
    { id: 'feeds', label: 'Feed Config', icon: Rss },
    { id: 'api-keys', label: 'API Keys', icon: Key },
    { id: 'ai', label: 'AI Config', icon: Sparkles },
    { id: 'database', label: 'Database', icon: Database },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-display font-bold text-sentinel-text-primary">Settings</h1>
        <p className="text-xs font-mono text-sentinel-text-muted mt-0.5">
          Platform configuration and preferences
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Section Nav */}
        <div className="space-y-1">
          {sections.map((section) => {
            const Icon = section.icon;
            return (
              <button
                key={section.id}
                onClick={() => setActiveSection(section.id)}
                className={cn(
                  'w-full flex items-center gap-3 px-3 py-2.5 rounded text-xs font-mono transition-colors text-left',
                  activeSection === section.id
                    ? 'bg-sentinel-accent/10 text-sentinel-accent border border-sentinel-accent/20'
                    : 'text-sentinel-text-secondary hover:text-sentinel-text-primary hover:bg-sentinel-bg-hover border border-transparent'
                )}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                {section.label}
              </button>
            );
          })}
        </div>

        {/* Content */}
        <div className="lg:col-span-3">
          <div className="sentinel-card p-6 space-y-6">
            {activeSection === 'general' && (
              <>
                <h2 className="text-sm font-display font-semibold text-sentinel-text-primary">General Settings</h2>
                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Platform Name</label>
                    <input
                      type="text"
                      defaultValue="SENTINEL"
                      className="w-full max-w-md px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Default Sync Interval (seconds)</label>
                    <input
                      type="number"
                      defaultValue={3600}
                      className="w-full max-w-md px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Log Level</label>
                    <select className="w-full max-w-md px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40">
                      <option>INFO</option>
                      <option>DEBUG</option>
                      <option>WARNING</option>
                      <option>ERROR</option>
                    </select>
                  </div>
                </div>
              </>
            )}

            {activeSection === 'api-keys' && (
              <>
                <h2 className="text-sm font-display font-semibold text-sentinel-text-primary">API Keys</h2>
                <p className="text-xs font-mono text-sentinel-text-muted">
                  API keys are configured via environment variables. Update your .env file or Docker environment.
                </p>
                <div className="space-y-3">
                  {[
                    { name: 'OTX_API_KEY', label: 'AlienVault OTX' },
                    { name: 'ABUSEIPDB_API_KEY', label: 'AbuseIPDB' },
                    { name: 'VT_API_KEY', label: 'VirusTotal' },
                    { name: 'SHODAN_API_KEY', label: 'Shodan' },
                    { name: 'PHISHTANK_API_KEY', label: 'PhishTank' },
                  ].map((key) => (
                    <div key={key.name} className="flex items-center justify-between p-3 rounded bg-sentinel-bg-primary border border-sentinel-border">
                      <div>
                        <p className="text-xs font-mono text-sentinel-text-primary">{key.label}</p>
                        <p className="text-[10px] font-mono text-sentinel-text-muted">{key.name}</p>
                      </div>
                      <span className="text-[10px] font-mono text-sentinel-text-muted px-2 py-0.5 rounded bg-sentinel-bg-tertiary">
                        ENV VAR
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}

            {activeSection === 'feeds' && (
              <>
                <h2 className="text-sm font-display font-semibold text-sentinel-text-primary">Feed Configuration</h2>
                <p className="text-xs font-mono text-sentinel-text-muted">
                  Manage feed sources from the Threat Feeds page. Global feed settings can be adjusted here.
                </p>
                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Max IOCs Per Feed Sync</label>
                    <input
                      type="number"
                      defaultValue={5000}
                      className="w-full max-w-md px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-sentinel-text-muted uppercase block mb-1">Auto-Enrichment on Ingest</label>
                    <select className="w-full max-w-md px-3 py-2 rounded bg-sentinel-bg-primary border border-sentinel-border text-sm font-mono text-sentinel-text-primary outline-none focus:border-sentinel-accent/40">
                      <option>Enabled</option>
                      <option>Disabled</option>
                    </select>
                  </div>
                </div>
              </>
            )}

            {activeSection === 'ai' && (
              <>
                <h2 className="text-sm font-display font-semibold text-sentinel-text-primary">AI Configuration</h2>
                <p className="text-xs font-mono text-sentinel-text-muted">
                  SENTINEL uses Groq (Llama 3.3 70B) for AI-powered threat analysis, chat assistance, and report generation.
                </p>
                <div className="space-y-3">
                  <div className="p-3 rounded bg-sentinel-bg-primary border border-sentinel-border">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-xs font-mono text-sentinel-text-primary">Groq API Key</p>
                        <p className="text-[10px] font-mono text-sentinel-text-muted">GROQ_API_KEY</p>
                      </div>
                      <span className="text-[10px] font-mono text-sentinel-text-muted px-2 py-0.5 rounded bg-sentinel-bg-tertiary">
                        ENV VAR
                      </span>
                    </div>
                  </div>
                  <div className="p-3 rounded bg-sentinel-bg-primary border border-sentinel-border">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-xs font-mono text-sentinel-text-primary">Model</p>
                        <p className="text-[10px] font-mono text-sentinel-text-muted">llama-3.3-70b-versatile</p>
                      </div>
                      <span className="text-[10px] font-mono text-green-400 px-2 py-0.5 rounded bg-green-500/10 border border-green-500/20">
                        FAST
                      </span>
                    </div>
                  </div>
                  <div className="p-3 rounded bg-sentinel-bg-primary border border-sentinel-border">
                    <p className="text-xs font-mono text-sentinel-text-primary mb-2">AI Features</p>
                    <ul className="space-y-1.5">
                      <li className="flex items-center gap-2 text-[10px] font-mono text-sentinel-text-secondary">
                        <Sparkles className="w-3 h-3 text-sentinel-accent" /> IOC Threat Analysis
                      </li>
                      <li className="flex items-center gap-2 text-[10px] font-mono text-sentinel-text-secondary">
                        <Sparkles className="w-3 h-3 text-sentinel-accent" /> Chat Assistant
                      </li>
                      <li className="flex items-center gap-2 text-[10px] font-mono text-sentinel-text-secondary">
                        <Sparkles className="w-3 h-3 text-sentinel-accent" /> AI Report Generation
                      </li>
                    </ul>
                  </div>
                </div>
              </>
            )}

            {activeSection === 'database' && (
              <>
                <h2 className="text-sm font-display font-semibold text-sentinel-text-primary">Database Info</h2>
                <div className="space-y-3">
                  <div className="p-3 rounded bg-sentinel-bg-primary border border-sentinel-border">
                    <p className="text-[10px] font-mono text-sentinel-text-muted">Connection</p>
                    <p className="text-xs font-mono text-sentinel-text-secondary mt-0.5">postgresql://sentinel:***@db:5432/sentinel</p>
                  </div>
                  <div className="p-3 rounded bg-sentinel-bg-primary border border-sentinel-border">
                    <p className="text-[10px] font-mono text-sentinel-text-muted">Redis</p>
                    <p className="text-xs font-mono text-sentinel-text-secondary mt-0.5">redis://redis:6379/0</p>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
