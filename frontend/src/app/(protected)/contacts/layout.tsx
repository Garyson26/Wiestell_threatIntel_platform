import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Contact Messages | Wiestell Admin',
  description: 'Manage user contact inquiries and support requests',
};

export default function ContactsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
