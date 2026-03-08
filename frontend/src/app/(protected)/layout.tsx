import Sidebar from '@/components/layout/Sidebar';
import Header from '@/components/layout/Header';
import RoleBasedRoute from '@/components/auth/RoleBasedRoute';

export default function ProtectedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <RoleBasedRoute allowedRoles={['admin', 'analyst', 'viewer']}>
      <div className="flex h-screen overflow-hidden">
        <Sidebar />
        <div className="flex flex-col flex-1 overflow-hidden">
          <Header />
          <main className="flex-1 overflow-auto grid-pattern p-6">
            {children}
          </main>
        </div>
      </div>
    </RoleBasedRoute>
  );
}
