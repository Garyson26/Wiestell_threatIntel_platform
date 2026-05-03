import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '@/lib/auth';

export const metadata: Metadata = {
  metadataBase: new URL('https://wiestell.com'),
  verification: {
    google: 'your-google-verification-code-here',
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
    title: 'Wiestell | Free Open Source Threat Intelligence Platform | IOC Lookup',
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

  return (
    <html lang="en">
      <head>
        {/* Google Tag Manager */}
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','GTM-TXF68KRQ');`,
          }}
        />
        {/* End Google Tag Manager */}
        
        {/* Google tag (gtag.js) */}
        <script
          async
          src="https://www.googletagmanager.com/gtag/js?id=G-FG3RH76R6J"
        />
        <script
          dangerouslySetInnerHTML={{
            __html: `
              window.dataLayer = window.dataLayer || [];
              function gtag(){dataLayer.push(arguments);}
              gtag('js', new Date());
              gtag('config', 'G-FG3RH76R6J');
            `,
          }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body>
        {/* Google Tag Manager (noscript) */}
        <noscript>
          <iframe
            src="https://www.googletagmanager.com/ns.html?id=GTM-TXF68KRQ"
            height="0"
            width="0"
            style={{ display: 'none', visibility: 'hidden' }}
          />
        </noscript>
        {/* End Google Tag Manager (noscript) */}
        
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
