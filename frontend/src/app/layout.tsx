import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '@/lib/auth';

export const metadata: Metadata = {
  metadataBase: new URL('https://wiestell.com'),
  verification: {
    google: '6Pe7rE27OmzXczBnDuDLoIXwUGPTcDqTYYzi7zo-Lak',
  },
  title: 'Wiestell | Free Threat Intelligence Platform | IOC Lookup',
  description: 'Free threat intelligence platform aggregating IOC data from URLhaus, ThreatFox, AlienVault OTX, AbuseIPDB, and more. Analyze IPs, domains, file hashes & URLs with comprehensive threat feeds.',
  keywords: [
    'open source threat intelligence',
    'free TIP',
    'IOC lookup',
    'IOC analysis',
    'malware detection',
    'security research',
    'threat feeds',
    'URLhaus',
    'ThreatFox',
    'AlienVault OTX',
    'SOC tools',
    'cybersecurity',
    'IP reputation',
    'domain analysis',
    'hash lookup',
    'community-driven security',
  ],
  authors: [{ name: 'Wiestell' }],
  creator: 'Wiestell',
  publisher: 'Wiestell',
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://wiestell.com',
    siteName: 'Wiestell',
    title: 'Wiestell | Free Threat Intelligence Platform | IOC Lookup',
    description: 'Free threat intelligence platform aggregating IOC data from URLhaus, ThreatFox, AlienVault OTX, AbuseIPDB, and more. Analyze IPs, domains, file hashes & URLs with comprehensive threat feeds.',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 630,
        alt: 'Wiestell Threat Intelligence Platform',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Wiestell | Free Threat Intelligence Platform | IOC Lookup',
    description: 'Free threat intelligence platform aggregating IOC data from URLhaus, ThreatFox, AlienVault OTX, AbuseIPDB, and more.',
    images: ['/og-image.png'],
    creator: '@wiestell',
  },
  icons: {
    icon: '/images/favicon.ico',
    shortcut: '/images/favicon.ico',
  },
  alternates: {
    canonical: 'https://wiestell.com',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'Wiestell',
    url: 'https://wiestell.com',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Web',
    description: 'Free threat intelligence platform for IOC lookup.',
    offers: {
      '@type': 'Offer',
      price: '0',
      priceCurrency: 'USD',
    },
  };

  // Analytics is deliberately NOT here. Google Tag Manager and gtag.js load only
  // from app/(marketing)/layout.tsx, because gtag reports `page_location`
  // including the query string and the signed-in app puts indicator values there:
  // `/ioc-search?q=<indicator>` from the landing page and the global header
  // search, and `/ioc?search=<url>`. Loading analytics on those routes sends an
  // analyst's investigation targets to Google. Referrer-Policy does not help —
  // gtag transmits the URL in its own payload, not as a referer.
  //
  // Scoping by route group rather than by a pathname allowlist is the point: a
  // new route under (protected), (analytics) or (bare) cannot inherit analytics
  // by anyone forgetting to update a list. Adding a tag here re-breaks that, so
  // add it to the marketing layout instead.
  //
  // (bare) is excluded too — it holds the auth pages, where the password-reset
  // flow handles email addresses.
  return (
    <html lang="en">
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
