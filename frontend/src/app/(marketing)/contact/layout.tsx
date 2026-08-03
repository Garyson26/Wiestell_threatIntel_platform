import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Contact Wiestell | Threat Intelligence Platform',
  description: 'Get in touch with the Wiestell team for feed issues, API access, feature requests, or abuse reports. We respond within 2 business days.',
  keywords: [
    'contact wiestell',
    'threat intelligence support',
    'report feed issue',
    'API access request',
    'security contact',
    'abuse report',
  ],
};

export default function ContactLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
