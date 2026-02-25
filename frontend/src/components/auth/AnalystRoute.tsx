'use client';

import RoleBasedRoute from './RoleBasedRoute';

interface AnalystRouteProps {
  children: React.ReactNode;
}

export default function AnalystRoute({ children }: AnalystRouteProps) {
  return (
    <RoleBasedRoute allowedRoles={['admin', 'analyst', 'viewer']}>
      {children}
    </RoleBasedRoute>
  );
}
