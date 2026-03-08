'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { Shield, AlertTriangle } from 'lucide-react';

interface RoleBasedRouteProps {
  children: React.ReactNode;
  allowedRoles: string[];
  redirectTo?: string;
}

export default function RoleBasedRoute({ 
  children, 
  allowedRoles,
  redirectTo = '/dashboard'
}: RoleBasedRouteProps) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login');
    }
  }, [user, loading, router]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-sentinel-accent/30 border-t-sentinel-accent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-sentinel-text-muted font-mono text-sm">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return null;
  }

  // Check if user has the required role
  if (!allowedRoles.includes(user.role)) {
    return (
      <div className="flex items-center justify-center min-h-screen p-6">
        <div className="sentinel-card max-w-md w-full p-8 text-center">
          <div className="flex justify-center mb-6">
            <div className="relative">
              <Shield className="w-16 h-16 text-sentinel-danger" />
              <AlertTriangle className="w-8 h-8 text-sentinel-warning absolute -bottom-1 -right-1" />
            </div>
          </div>
          
          <h1 className="text-2xl font-display font-bold text-sentinel-text-primary mb-3">
            Access Denied
          </h1>
          
          <p className="text-sentinel-text-secondary mb-6">
            You don't have permission to access this area. 
            <span className="block mt-2 text-sentinel-text-muted text-sm font-mono">
              Required role: {allowedRoles.join(' or ')}
            </span>
            <span className="block text-sentinel-text-muted text-sm font-mono">
              Your role: {user.role}
            </span>
          </p>
          
          <button
            onClick={() => router.push(redirectTo)}
            className="px-6 py-3 bg-black text-white hover:bg-gray-800 font-semibold rounded transition-colors duration-200"
          >
            Return to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
