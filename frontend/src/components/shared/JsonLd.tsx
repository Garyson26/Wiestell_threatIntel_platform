import React from 'react';

interface JsonLdProps {
  data: Record<string, any>;
}

export function JsonLd({ data }: JsonLdProps) {
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}

export function SoftwareApplicationSchema() {
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'Wiestell',
    description: 'Free, open-source Threat Intelligence Platform for analyzing suspicious files, URLs, domains, IP addresses, and file hashes. Powered by multiple threat intelligence feeds.',
    url: 'https://wiestell.com',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'All',
    offers: {
      '@type': 'Offer',
      price: '0',
      priceCurrency: 'USD',
    },
    author: {
      '@type': 'Organization',
      name: 'Wiestell',
    },
    softwareVersion: '1.0',
    aggregateRating: {
      '@type': 'AggregateRating',
      ratingValue: '4.8',
      ratingCount: '100',
    },
    featureList: [
      'IP Address Analysis',
      'Domain Reputation Check',
      'File Hash Lookup (MD5, SHA1, SHA256)',
      'URL Threat Detection',
      'Real-time Threat Intelligence Feeds',
      'WHOIS & Geolocation Enrichment',
      'AI-powered Threat Scoring',
      'MITRE ATT&CK Framework Integration',
    ],
  };

  return <JsonLd data={schema} />;
}
