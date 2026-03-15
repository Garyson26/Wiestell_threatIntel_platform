import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowLeft, Code, Key, Book, Terminal } from 'lucide-react';

export const metadata: Metadata = {
  title: 'API Documentation',
  description: 'Complete API documentation for integrating Wiestell threat intelligence into your security workflows and applications.',
};

export default function ApiDocsPage() {
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
              API Documentation
            </h1>
            <p className="text-lg text-sentinel-text-secondary font-mono">
              Integrate Wiestell threat intelligence into your workflows
            </p>
          </div>

          {/* Quick Start Section */}
          <section className="sentinel-card p-8 mb-8">
            <div className="flex items-start gap-4 mb-4">
              <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                <Terminal className="w-6 h-6 text-sentinel-accent" />
              </div>
              <div className="flex-1">
                <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary mb-3">
                  Getting Started
                </h2>
                <p className="text-sentinel-text-secondary font-mono text-sm leading-relaxed mb-4">
                  The Wiestell API provides programmatic access to our threat intelligence platform. Query IOCs, retrieve enrichment data, and integrate threat feeds into your security operations.
                </p>
                <div className="bg-sentinel-bg-primary border border-sentinel-border rounded p-4">
                  <code className="text-xs font-mono text-sentinel-accent">
                    Base URL: https://api.wiestell.com/v1
                  </code>
                </div>
              </div>
            </div>
          </section>

          {/* Authentication Section */}
          <section className="sentinel-card p-8 mb-8">
            <div className="flex items-start gap-4 mb-4">
              <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                <Key className="w-6 h-6 text-sentinel-accent" />
              </div>
              <div className="flex-1">
                <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary mb-3">
                  Authentication
                </h2>
                <div className="space-y-3 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                  <p>
                    API requests require authentication using an API key. Include your key in the request headers:
                  </p>
                  <div className="bg-sentinel-bg-primary border border-sentinel-border rounded p-4">
                    <pre className="text-xs font-mono text-sentinel-accent overflow-x-auto">
{`Authorization: Bearer YOUR_API_KEY
Content-Type: application/json`}
                    </pre>
                  </div>
                  <p className="text-sentinel-text-muted text-xs pt-2">
                    API keys can be generated from your dashboard after logging in.
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* Endpoints Section */}
          <section className="sentinel-card p-8 mb-8">
            <div className="flex items-start gap-4 mb-6">
              <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                <Code className="w-6 h-6 text-sentinel-accent" />
              </div>
              <div className="flex-1">
                <h2 className="text-2xl font-display font-semibold text-sentinel-text-primary mb-3">
                  API Endpoints
                </h2>
                <p className="text-sentinel-text-secondary font-mono text-sm leading-relaxed">
                  Available endpoints for IOC analysis and threat intelligence queries
                </p>
              </div>
            </div>

            {/* Endpoint List */}
            <div className="space-y-6">
              {/* Endpoint 1 */}
              <div className="border-l-2 border-sentinel-accent/30 pl-6">
                <div className="flex items-baseline gap-3 mb-2">
                  <span className="text-xs font-mono font-bold text-sentinel-accent px-3 py-1 rounded bg-sentinel-accent/10 border border-sentinel-accent/30">
                    GET
                  </span>
                  <code className="text-sm font-mono text-sentinel-text-primary">
                    /api/ioc/search
                  </code>
                </div>
                <p className="text-sm font-mono text-sentinel-text-secondary mb-3">
                  Search for an IOC across all threat intelligence feeds
                </p>
                <div className="bg-sentinel-bg-primary border border-sentinel-border rounded p-4">
                  <pre className="text-xs font-mono text-sentinel-accent overflow-x-auto">
{`GET /api/ioc/search?query=8.8.8.8&type=ip

Response:
{
  "ioc": "8.8.8.8",
  "type": "ip",
  "score": 15,
  "classification": "benign",
  "enrichments": {...}
}`}
                  </pre>
                </div>
              </div>

              {/* Endpoint 2 */}
              <div className="border-l-2 border-sentinel-accent/30 pl-6">
                <div className="flex items-baseline gap-3 mb-2">
                  <span className="text-xs font-mono font-bold text-sentinel-accent px-3 py-1 rounded bg-sentinel-accent/10 border border-sentinel-accent/30">
                    GET
                  </span>
                  <code className="text-sm font-mono text-sentinel-text-primary">
                    /api/feeds
                  </code>
                </div>
                <p className="text-sm font-mono text-sentinel-text-secondary mb-3">
                  Retrieve list of available threat intelligence feeds
                </p>
                <div className="bg-sentinel-bg-primary border border-sentinel-border rounded p-4">
                  <pre className="text-xs font-mono text-sentinel-accent overflow-x-auto">
{`GET /api/feeds

Response:
{
  "feeds": [
    {
      "name": "AlienVault OTX",
      "status": "active",
      "last_updated": "2026-03-15T12:00:00Z"
    }
  ]
}`}
                  </pre>
                </div>
              </div>

              {/* Endpoint 3 */}
              <div className="border-l-2 border-sentinel-accent/30 pl-6">
                <div className="flex items-baseline gap-3 mb-2">
                  <span className="text-xs font-mono font-bold text-sentinel-accent px-3 py-1 rounded bg-sentinel-accent/10 border border-sentinel-accent/30">
                    POST
                  </span>
                  <code className="text-sm font-mono text-sentinel-text-primary">
                    /api/enrichment
                  </code>
                </div>
                <p className="text-sm font-mono text-sentinel-text-secondary mb-3">
                  Request detailed enrichment data for an IOC
                </p>
                <div className="bg-sentinel-bg-primary border border-sentinel-border rounded p-4">
                  <pre className="text-xs font-mono text-sentinel-accent overflow-x-auto">
{`POST /api/enrichment
{
  "ioc": "example.com",
  "type": "domain"
}

Response:
{
  "whois": {...},
  "dns": {...},
  "geolocation": {...}
}`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          {/* Rate Limits Section */}
          <section className="sentinel-card p-8 mb-8">
            <h2 className="text-xl font-display font-semibold text-sentinel-text-primary mb-3">
              Rate Limits
            </h2>
            <div className="space-y-2 text-sentinel-text-secondary font-mono text-sm leading-relaxed">
              <p>
                Free tier: 1,000 requests per day
              </p>
              <p>
                Registered users: 10,000 requests per day
              </p>
              <p className="text-sentinel-text-muted text-xs pt-2">
                Need higher limits? Contact us for enterprise access.
              </p>
            </div>
          </section>

          {/* Documentation Section */}
          <section className="sentinel-card p-8 bg-sentinel-accent/5">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center flex-shrink-0">
                <Book className="w-6 h-6 text-sentinel-accent" />
              </div>
              <div>
                <h2 className="text-xl font-display font-semibold text-sentinel-text-primary mb-3">
                  Complete Documentation
                </h2>
                <p className="text-sentinel-text-secondary font-mono text-sm mb-4">
                  For complete API documentation, code examples, and SDKs, visit our developer portal or explore our interactive API playground.
                </p>
                <div className="flex flex-wrap gap-4">
                  <Link
                    href="https://docs.wiestell.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-sm font-mono font-semibold hover:bg-sentinel-accent/20 transition-colors"
                  >
                    Full Documentation
                  </Link>
                  <Link
                    href="/login"
                    className="px-4 py-2 rounded bg-sentinel-accent/10 border border-sentinel-accent/30 text-sentinel-accent text-sm font-mono font-semibold hover:bg-sentinel-accent/20 transition-colors"
                  >
                    Get API Key
                  </Link>
                </div>
              </div>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
