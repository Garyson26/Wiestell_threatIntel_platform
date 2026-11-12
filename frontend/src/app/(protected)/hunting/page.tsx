'use client';

import AdminRoute from '@/components/auth/AdminRoute';
import { useState } from 'react';
import { Crosshair, Search, Plus, X } from 'lucide-react';
import { bulkLookup } from '@/lib/api';
import ScoreBadge from '@/components/ioc/ScoreBadge';
import { cn, truncate } from '@/lib/utils';
import type { IOC } from '@/lib/types';

export default function HuntingPage() {
  const [bulkInput, setBulkInput] = useState('');
  const [results, setResults] = useState<IOC[]>([]);
  const [loading, setLoading] = useState(false);
  const [notes, setNotes] = useState('');

  const handleBulkSearch = async () => {
    const values = bulkInput.split('\n').map(v => v.trim()).filter(Boolean);
    if (values.length === 0) return;

    setLoading(true);
    try {
      const data = await bulkLookup(values);
      setResults(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  return (
    <AdminRoute>
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-display font-bold text-wiestell-text-primary">Threat Hunting</h1>
        <p className="text-xs font-mono text-wiestell-text-muted mt-0.5">
          Investigate and correlate indicators of compromise
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Bulk IOC Lookup */}
        <div className="wiestell-card p-5 space-y-4">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-widest text-wiestell-text-muted">
            BULK IOC LOOKUP
          </h3>
          <textarea
            value={bulkInput}
            onChange={(e) => setBulkInput(e.target.value)}
            placeholder="Paste IOCs here, one per line:&#10;192.168.1.1&#10;evil-domain.com&#10;abc123def456..."
            className="w-full h-48 px-3 py-2 rounded bg-wiestell-bg-primary border border-wiestell-border text-xs font-mono text-wiestell-text-primary placeholder:text-wiestell-text-muted outline-none focus:border-wiestell-accent/40 resize-none"
          />
          <button
            onClick={handleBulkSearch}
            disabled={loading || !bulkInput.trim()}
            className="flex items-center justify-center gap-2 w-full px-4 py-2 rounded bg-wiestell-accent/10 border border-wiestell-accent/30 text-wiestell-accent text-xs font-mono font-semibold hover:bg-wiestell-accent/20 disabled:opacity-30 transition-colors"
          >
            <Search className="w-3 h-3" />
            {loading ? 'SEARCHING...' : 'SEARCH ALL'}
          </button>
        </div>

        {/* Investigation Notes */}
        <div className="wiestell-card p-5 space-y-4">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-widest text-wiestell-text-muted">
            INVESTIGATION NOTES
          </h3>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Document your findings here...&#10;&#10;Supports markdown formatting."
            className="w-full h-48 px-3 py-2 rounded bg-wiestell-bg-primary border border-wiestell-border text-xs font-mono text-wiestell-text-primary placeholder:text-wiestell-text-muted outline-none focus:border-wiestell-accent/40 resize-none"
          />
          <p className="text-[10px] font-mono text-wiestell-text-muted">
            Notes are session-local and will not be persisted
          </p>
        </div>
      </div>

      {/* Bulk Search Results */}
      {results.length > 0 && (
        <div className="wiestell-card overflow-hidden animate-slide-up">
          <div className="px-5 py-3 border-b border-wiestell-border flex items-center justify-between">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-widest text-wiestell-text-muted">
              RESULTS ({results.length} found)
            </h3>
            <button
              onClick={() => setResults([])}
              className="text-wiestell-text-muted hover:text-wiestell-text-secondary transition-colors"
            >
              <X className="w-3 h-3" />
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-wiestell-border">
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">IOC</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Type</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Score</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-mono font-semibold uppercase text-wiestell-text-muted">Tags</th>
                </tr>
              </thead>
              <tbody>
                {results.map((ioc, i) => (
                  <tr key={ioc.id} className="border-b border-wiestell-border/50 animate-fade-in" style={{ animationDelay: `${i * 20}ms` }}>
                    <td className="px-4 py-2.5 font-mono text-xs text-wiestell-text-primary">{truncate(ioc.value, 50)}</td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-wiestell-text-muted uppercase">{ioc.type}</td>
                    <td className="px-4 py-2.5"><ScoreBadge score={ioc.threat_score} size="sm" showBar /></td>
                    <td className="px-4 py-2.5">
                      <div className="flex gap-1 flex-wrap">
                        {(ioc.tags || []).slice(0, 3).map((tag) => (
                          <span key={tag} className="px-1.5 py-0.5 text-[9px] font-mono rounded bg-wiestell-bg-tertiary text-wiestell-text-muted border border-wiestell-border">{tag}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
    </AdminRoute>
  );
}
