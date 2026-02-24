import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '@/lib/auth';

export const metadata: Metadata = {
  title: 'SENTINEL — Threat Intelligence Platform',
  description: 'Open-source threat intelligence platform that aggregates, enriches, and scores IOCs from multiple feeds.',
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
