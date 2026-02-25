import Sidebar from '@/components/layout/Sidebar';
import Header from '@/components/layout/Header';
import AnalystRoute from '@/components/auth/AnalystRoute';

export default function AnalyticsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AnalystRoute>
      <div className="flex h-screen overflow-hidden">
        <Sidebar />
        <div className="flex flex-col flex-1 overflow-hidden">
          <Header />
          <main className="flex-1 overflow-auto grid-pattern p-6">
            {children}
          </main>
        </div>
      </div>
    </AnalystRoute>
  );
}
