import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '@/lib/auth';

export const metadata: Metadata = {
  metadataBase: new URL('https://wiestell.com'),
  verification: {
    google: 'your-google-verification-code-here',
  },
  title: 'Wiestell — Free Open Source Threat Intelligence Platform | IOC Lookup',
  description: 'Free open-source threat intelligence platform aggregating IOC data from URLhaus, ThreatFox, AlienVault OTX, AbuseIPDB, and more. Analyze IPs, domains, file hashes & URLs with comprehensive threat feeds.',
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
    title: 'Wiestell — Free Open Source Threat Intelligence Platform | IOC Lookup',
    description: 'Free open-source threat intelligence platform aggregating IOC data from URLhaus, ThreatFox, AlienVault OTX, AbuseIPDB, and more. Analyze IPs, domains, file hashes & URLs with comprehensive threat feeds.',
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
    title: 'Wiestell — Free Open Source Threat Intelligence Platform | IOC Lookup',
    description: 'Free open-source threat intelligence platform aggregating IOC data from URLhaus, ThreatFox, AlienVault OTX, AbuseIPDB, and more.',
    images: ['/og-image.png'],
    creator: '@wiestell',
  },
  icons: {
    icon: [
      { url: '/images/favicon.ico', sizes: 'any' },
      { url: '/images/favicon-32x32.png', sizes: '32x32', type: 'image/png' },
      { url: '/images/favicon-192x192.png', sizes: '192x192', type: 'image/png' },
    ],
    shortcut: '/images/favicon.ico',
    apple: '/images/apple-touch-icon.png',
  },
  manifest: '/site.webmanifest',
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

  return (
    <html lang="en">
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body className="scanline-overlay">
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
