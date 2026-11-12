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
  redirectTo
}: RoleBasedRouteProps) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      // Redirect to appropriate login based on required roles
      const loginPath = allowedRoles.includes('admin') && allowedRoles.length === 1 
        ? '/plateform-pilot' 
        : '/login';
      router.push(loginPath);
    }
  }, [user, loading, router, allowedRoles]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-wiestell-accent/30 border-t-wiestell-accent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-wiestell-text-muted font-mono text-sm">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return null;
  }

  // Check if user has the required role
  if (!allowedRoles.includes(user.role)) {
    // Smart redirect based on user role
    const defaultRedirect = redirectTo || (user.role === 'admin' ? '/dashboard' : '/analytics');
    
    return (
      <div className="flex items-center justify-center min-h-screen p-6">
        <div className="wiestell-card max-w-md w-full p-8 text-center">
          <div className="flex justify-center mb-6">
            <div className="relative">
              <Shield className="w-16 h-16 text-wiestell-danger" />
              <AlertTriangle className="w-8 h-8 text-wiestell-warning absolute -bottom-1 -right-1" />
            </div>
          </div>
          
          <h1 className="text-2xl font-display font-bold text-wiestell-text-primary mb-3">
            Access Denied
          </h1>
          
          <p className="text-wiestell-text-secondary mb-6">
            You don't have permission to access this area. 
            <span className="block mt-2 text-wiestell-text-muted text-sm font-mono">
              Required role: {allowedRoles.join(' or ')}
            </span>
            <span className="block text-wiestell-text-muted text-sm font-mono">
              Your role: {user.role}
            </span>
          </p>
          
          <button
            onClick={() => router.push(defaultRedirect)}
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
