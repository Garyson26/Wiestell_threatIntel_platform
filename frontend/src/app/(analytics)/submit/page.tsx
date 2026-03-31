'use client';

import { useState } from 'react';
import { Upload, Link as LinkIcon, FileText, AlertCircle, CheckCircle2, Loader2 } from 'lucide-react';
import { bulkLookup } from '@/lib/api';
import type { IOC } from '@/lib/types';
import ScoreBadge from '@/components/ioc/ScoreBadge';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { trackSubmission } from '@/lib/userActivity';

export default function SubmitIOCPage() {
  const router = useRouter();
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<'url' | 'file'>('url');
  const [urlInput, setUrlInput] = useState('');
  const [fileContent, setFileContent] = useState<string>('');
  const [fileName, setFileName] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<IOC[]>([]);
  const [error, setError] = useState<string>('');

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    setError('');

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setFileContent(text);
    };
    reader.onerror = () => {
      setError('Failed to read file');
    };
    reader.readAsText(file);
  };

  const extractIOCs = (text: string): string[] => {
    const lines = text.split('\n');
    const iocs: string[] = [];
    
    for (const line of lines) {
      const trimmed = line.trim();
      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
      
      // Extract IOCs (basic extraction)
      const parts = trimmed.split(/[\s,;|]+/);
      for (const part of parts) {
        const cleaned = part.trim();
        if (cleaned && cleaned.length > 3) {
          iocs.push(cleaned);
        }
      }
    }
    
    // Remove duplicates
    const uniqueIOCs: string[] = [];
    const seen = new Set<string>();
    for (const ioc of iocs) {
      if (!seen.has(ioc)) {
        seen.add(ioc);
        uniqueIOCs.push(ioc);
      }
    }
    
    return uniqueIOCs;
  };

  const handleSubmit = async () => {
    setError('');
    setResults([]);
    
    let iocs: string[] = [];
    
    if (activeTab === 'url') {
      if (!urlInput.trim()) {
        setError('Please enter at least one IOC');
        return;
      }
      iocs = extractIOCs(urlInput);
    } else {
      if (!fileContent) {
        setError('Please upload a file');
        return;
      }
      iocs = extractIOCs(fileContent);
    }

    if (iocs.length === 0) {
      setError('No valid IOCs found');
      return;
    }

    if (iocs.length > 1000) {
      setError('Maximum 1000 IOCs allowed per submission');
      return;
    }

    setLoading(true);
    try {
      const data = await bulkLookup(iocs);
      setResults(data);
      if (data.length === 0) {
        setError('No matching IOCs found in database');
      } else if (user?.id) {
        // Track submission activity
        trackSubmission(user.id, data);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to lookup IOCs');
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setUrlInput('');
    setFileContent('');
    setFileName('');
    setResults([]);
    setError('');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-display font-bold text-sentinel-text-primary">Submit & Analyze IOCs</h1>
        <p className="text-xs font-mono text-sentinel-text-muted mt-0.5">
          Submit URLs, IPs, domains, or upload files containing IOCs for analysis
        </p>
      </div>

      {/* Tab Selector */}
      <div className="flex gap-2 border-b border-sentinel-border">
        <button
          onClick={() => setActiveTab('url')}
          className={`px-4 py-2 text-sm font-mono transition-colors relative ${
            activeTab === 'url'
              ? 'text-sentinel-accent'
              : 'text-sentinel-text-muted hover:text-sentinel-text-secondary'
          }`}
        >
          <LinkIcon className="w-4 h-4 inline-block mr-2" />
          Manual Entry
          {activeTab === 'url' && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-sentinel-accent" />
          )}
        </button>
        <button
          onClick={() => setActiveTab('file')}
          className={`px-4 py-2 text-sm font-mono transition-colors relative ${
            activeTab === 'file'
              ? 'text-sentinel-accent'
              : 'text-sentinel-text-muted hover:text-sentinel-text-secondary'
          }`}
        >
          <FileText className="w-4 h-4 inline-block mr-2" />
          File Upload
          {activeTab === 'file' && (
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-sentinel-accent" />
          )}
        </button>
      </div>

      {/* Input Area */}
      <div className="sentinel-card p-6">
        {activeTab === 'url' ? (
          <div className="space-y-3">
            <label className="text-xs font-mono text-sentinel-text-muted uppercase block">
              Enter IOCs (one per line)
            </label>
            <textarea
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter IPs, domains, URLs, hashes, emails, or CVEs&#10;Example:&#10;192.168.1.1&#10;malicious-domain.com&#10;abc123def456..."
              rows={12}
              className="w-full px-4 py-3 rounded bg-sentinel-bg-secondary border border-sentinel-border text-sm font-mono text-sentinel-text-primary placeholder:text-sentinel-text-muted outline-none focus:border-sentinel-accent/40 resize-none"
            />
            <p className="text-xs text-sentinel-text-muted font-mono">
              Supports: IP addresses, domains, URLs, file hashes, email addresses, CVE IDs
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            <label className="text-xs font-mono text-sentinel-text-muted uppercase block">
              Upload File
            </label>
            <div className="border-2 border-dashed border-sentinel-border rounded-lg p-8 text-center hover:border-sentinel-accent/40 transition-colors">
              <input
                type="file"
                accept=".txt,.csv,.log"
                onChange={handleFileUpload}
                className="hidden"
                id="file-upload"
              />
              <label htmlFor="file-upload" className="cursor-pointer">
                <Upload className="w-12 h-12 text-sentinel-text-muted mx-auto mb-3" />
                {fileName ? (
                  <div>
                    <p className="text-sm font-mono text-sentinel-accent mb-1">{fileName}</p>
                    <p className="text-xs text-sentinel-text-muted">Click to change file</p>
                  </div>
                ) : (
                  <div>
                    <p className="text-sm font-mono text-sentinel-text-secondary mb-1">
                      Click to upload or drag and drop
                    </p>
                    <p className="text-xs text-sentinel-text-muted">
                      Supports .txt, .csv, .log files
                    </p>
                  </div>
                )}
              </label>
            </div>
            {fileContent && (
              <div className="bg-sentinel-bg-tertiary rounded p-3 border border-sentinel-border">
                <p className="text-xs font-mono text-sentinel-text-muted mb-2">Preview:</p>
                <pre className="text-xs font-mono text-sentinel-text-secondary overflow-x-auto max-h-24">
                  {fileContent.slice(0, 500)}{fileContent.length > 500 ? '...' : ''}
                </pre>
              </div>
            )}
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-3 mt-6">
          <button
            onClick={handleSubmit}
            disabled={loading || (activeTab === 'url' ? !urlInput.trim() : !fileContent)}
            className="flex items-center gap-2 px-6 py-2.5 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-xs font-mono font-semibold hover:bg-sentinel-accent/20 disabled:opacity-30 transition-colors"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                ANALYZING...
              </>
            ) : (
              <>
                <CheckCircle2 className="w-4 h-4" />
                ANALYZE IOCs
              </>
            )}
          </button>
          <button
            onClick={handleClear}
            disabled={loading}
            className="px-6 py-2.5 rounded border border-sentinel-border text-sentinel-text-muted text-xs font-mono font-semibold hover:text-sentinel-text-secondary hover:border-sentinel-border-hover disabled:opacity-30 transition-colors"
          >
            CLEAR
          </button>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="sentinel-card p-4 border-sentinel-danger/30 bg-sentinel-danger/5">
          <div className="flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-sentinel-danger flex-shrink-0 mt-0.5" />
            <p className="text-xs font-mono text-sentinel-danger">{error}</p>
          </div>
        </div>
      )}

      {/* Results */}
      {results.length > 0 && (
        <div className="sentinel-card overflow-hidden">
          <div className="px-5 py-3 border-b border-sentinel-border flex items-center justify-between">
            <span className="text-xs font-mono text-sentinel-text-muted">
              Found {results.length} matching IOCs in database
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-sentinel-border">
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">IOC Value</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Type</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Threat Score</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Sightings</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase tracking-wider text-sentinel-text-muted">Actions</th>
                </tr>
              </thead>
              <tbody>
                {results.map((ioc, i) => (
                  <tr
                    key={ioc.id}
                    onClick={() => router.push(`/ioc-detail/${ioc.id}`)}
                    className="border-b border-sentinel-border/50 cursor-pointer hover:bg-sentinel-bg-hover transition-colors animate-fade-in"
                    style={{ animationDelay: `${i * 30}ms` }}
                  >
                    <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-primary max-w-md truncate">
                      {ioc.value}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-sentinel-text-muted uppercase">
                      {ioc.type}
                    </td>
                    <td className="px-4 py-2.5">
                      <ScoreBadge score={ioc.threat_score} size="sm" showBar />
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-sentinel-text-secondary">
                      {ioc.sighting_count}
                    </td>
                    <td className="px-4 py-2.5">
                      <button
                        onClick={() => router.push(`/ioc-detail/${ioc.id}`)}
                        className="px-3 py-1 rounded text-[10px] font-mono border border-sentinel-border text-sentinel-text-muted hover:text-sentinel-accent hover:border-sentinel-accent/30 transition-colors"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
