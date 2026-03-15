import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '@/lib/auth';

export const metadata: Metadata = {
  metadataBase: new URL('https://wiestell.com'),
  title: {
    default: 'Wiestell — Free Open Source Threat Intelligence Platform | IOC Lookup',
    template: '%s | Wiestell',
  },
  description: 'Open-source threat intelligence platform for IOC analysis. Community-driven, transparent threat detection with 10+ free feeds. Analyze IPs, domains, file hashes & URLs. No restrictions, fully extensible.',
  keywords: [
    'open source threat intelligence',
    'free TIP',
    'IOC lookup',
    'IOC analysis',
    'malware detection',
    'security research',
    'threat feeds',
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
    title: 'Wiestell — Free Open Source Threat Intelligence Platform | IOC Lookup',
    description: 'Open-source threat intelligence platform for IOC analysis. Community-driven, transparent threat detection with 10+ free feeds. Analyze IPs, domains, file hashes & URLs.',
    siteName: 'Wiestell',
    images: [
      {
        url: '/images/og-image.jpg',
        width: 1200,
        height: 630,
        alt: 'Wiestell Threat Intelligence Platform',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Wiestell — Free Open Source Threat Intelligence Platform | IOC Lookup',
    description: 'Open-source threat intelligence platform for IOC analysis. Community-driven, transparent threat detection with 10+ free feeds.',
    images: ['/images/og-image.jpg'],
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
  return (
    <html lang="en">
      <body className="scanline-overlay">
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
